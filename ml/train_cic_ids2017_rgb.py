"""
SPIN-IDS: Genuine CIC-IDS2017 Wednesday Baseline Experiment
Branch: RGB CNN Branch Only (Spatial Grid Representation)

Architecture:
  Input: 2,187 bytes = 9 sequential packets x 243 bytes = 27 x 27 x 3 RGB image.
  Representation: 3x3 grid of 9x9 patches (81 RGB pixels per packet), matching PacketImageBuilder.
  Network: 2D CNN with Conv2D(32)-MaxPool-Conv2D(64)-MaxPool-Dense(64)-Dropout(0.3)-Dense(2).

Class Imbalance Handling:
  Class counts in training set:
    - NORMAL (BENIGN): 196,640 (80.14%)
    - MALICIOUS (Attacks): 48,734 (19.86%)
    - Imbalance ratio: ~4.03 : 1
  Method:
    Inverse-frequency balanced class weighting:
      w_normal    = N_total / (2 * N_normal)    = 245374 / (2 * 196640) = 0.623927
      w_malicious = N_total / (2 * N_malicious) = 245374 / (2 * 48734)  = 2.517482
    Applied via weighted Cross-Entropy Loss (weight=torch.tensor([w_normal, w_malicious])).
    Penalizes false negatives on attack traffic 4.03x higher, preventing majority-class bias.

Integrity Rules:
  - Strict flow-level train/validation/test isolation (zero flow leakage).
  - Validation set used strictly for epoch monitoring and best-model checkpointing.
  - Held-out test set evaluated ONCE on the selected best checkpoint.
  - Reproducible seed: 42.
"""

import os
import sys
import json
import time
import random
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# ==============================================================================
# 1. PATH CONFIGURATION & SEED SETUP
# ==============================================================================
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "External_CIC_IDS2017", "processed")
CACHE_DIR = os.path.join(PROCESSED_DIR, "cache")
RESULTS_DIR = os.path.join(BASE_DIR, "ml", "results", "cic_ids2017_rgb")
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models", "cic_ids2017_rgb")

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

TRAIN_CSV = os.path.join(PROCESSED_DIR, "train.csv")
VAL_CSV = os.path.join(PROCESSED_DIR, "val.csv")
TEST_CSV = os.path.join(PROCESSED_DIR, "test.csv")

WINDOW_BYTES = 2187
IMAGE_SHAPE = (3, 27, 27)  # PyTorch Channels-First: (C, H, W)
NUM_CLASSES = 2
CLASS_NAMES = ["NORMAL", "MALICIOUS"]

BATCH_SIZE = 256
EPOCHS = 5
LEARNING_RATE = 0.001
WEIGHT_DECAY = 1e-4

print("=" * 70)
print("SPIN-IDS: CIC-IDS2017 WEDNESDAY RGB CNN BASELINE TRAINING")
print("=" * 70)
print(f"Base Directory:     {BASE_DIR}")
print(f"Processed Dataset:  {PROCESSED_DIR}")
print(f"Results Directory:  {RESULTS_DIR}")
print(f"Models Directory:   {MODELS_DIR}")
print(f"Random Seed:        {SEED}")
print(f"Device:             CPU (PyTorch {torch.__version__})")
print("=" * 70)


# ==============================================================================
# 2. FAST MEMORY-MAPPED BINARY CACHING
# Converts large text CSVs into uint8 binary arrays once for instant loading.
# Uses < 400 MB RAM during caching and < 800 MB during training.
# ==============================================================================
def prepare_split_cache(split_name, csv_path):
    bytes_npy = os.path.join(CACHE_DIR, f"{split_name}_bytes.npy")
    labels_npy = os.path.join(CACHE_DIR, f"{split_name}_labels.npy")
    meta_json = os.path.join(CACHE_DIR, f"{split_name}_meta.json")

    if os.path.exists(bytes_npy) and os.path.exists(labels_npy) and os.path.exists(meta_json):
        print(f"Found cached binary for {split_name}: {bytes_npy}")
        raw_bytes = np.load(bytes_npy, mmap_mode="r")
        labels = np.load(labels_npy)
        with open(meta_json, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return raw_bytes, labels, meta

    print(f"Caching {split_name} from {csv_path}...")
    t0 = time.time()
    byte_cols = [f"b{i:04d}" for i in range(WINDOW_BYTES)]

    # Chunked read to keep memory footprint under 400 MB
    chunk_size = 40000
    byte_chunks = []
    labels_list = []
    window_ids = []
    flow_ids = []
    attack_categories = []

    for chunk in pd.read_csv(csv_path, chunksize=chunk_size):
        byte_chunks.append(chunk[byte_cols].to_numpy(dtype=np.uint8))
        labels_list.extend([1 if l == "MALICIOUS" else 0 for l in chunk["label"]])
        window_ids.extend(chunk["window_id"].tolist())
        flow_ids.extend(chunk["flow_id"].tolist())
        attack_categories.extend(chunk["attack_category"].tolist())

    raw_bytes = np.vstack(byte_chunks)
    labels = np.array(labels_list, dtype=np.int64)

    np.save(bytes_npy, raw_bytes)
    np.save(labels_npy, labels)
    meta = {
        "window_ids": window_ids,
        "flow_ids": flow_ids,
        "attack_categories": attack_categories,
        "total_samples": len(labels)
    }
    with open(meta_json, "w", encoding="utf-8") as f:
        json.dump(meta, f)

    print(f"Cached {split_name} ({len(labels):,} samples) in {time.time()-t0:.1f}s!")
    raw_bytes = np.load(bytes_npy, mmap_mode="r")
    return raw_bytes, labels, meta


# ==============================================================================
# 3. DATASET & VECTORIZED PREPROCESSING
# ==============================================================================
def bytes_to_chw_tensor(batch_uint8: np.ndarray) -> torch.Tensor:
    """
    Vectorized transformation of (B, 2187) uint8 bytes into (B, 3, 27, 27) float32
    representing 9 sequential packets in a 3x3 patch grid (PacketImageBuilder).
    Normalized to [0.0, 1.0].
    """
    n = batch_uint8.shape[0]
    # Reshape: (B, 3_row, 3_col, 9_y, 9_x, 3_channel)
    reshaped = batch_uint8.reshape(n, 3, 3, 9, 9, 3)
    # Permute to PyTorch CHW format: (B, channel, 3_row, 9_y, 3_col, 9_x)
    permuted = reshaped.transpose(0, 5, 1, 3, 2, 4)
    # Reshape to (B, 3, 27, 27) float32 normalized to [0, 1]
    tensor_arr = permuted.reshape(n, 3, 27, 27).astype(np.float32) / 255.0
    return torch.from_numpy(tensor_arr)


class CicIdsRgbDataset(Dataset):
    def __init__(self, raw_bytes, labels):
        self.raw_bytes = raw_bytes
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.raw_bytes[idx], self.labels[idx]


def collate_fn(batch):
    bytes_list, labels_list = zip(*batch)
    batch_bytes = np.stack(bytes_list, axis=0)
    batch_tensors = bytes_to_chw_tensor(batch_bytes)
    batch_labels = torch.tensor(labels_list, dtype=torch.long)
    return batch_tensors, batch_labels


# ==============================================================================
# 4. RGB CNN MODEL ARCHITECTURE
# ==============================================================================
class CicIdsRgbCnn(nn.Module):
    """
    2D CNN matching the SPIN-IDS spatial grid architecture:
      - Input: (B, 3, 27, 27)
      - Conv2D(3 -> 32, 3x3, pad=1) + ReLU + MaxPool2d(2x2) -> (B, 32, 13, 13)
      - Conv2D(32 -> 64, 3x3, pad=1) + ReLU + MaxPool2d(2x2) -> (B, 64, 6, 6)
      - Flatten -> 64 * 6 * 6 = 2,304 features
      - Dense(2304 -> 64) + ReLU + Dropout(0.3)
      - Dense(64 -> 2) [Softmax Logits]
    """
    def __init__(self, num_classes=2):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2),

            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2)
        )
        self.classifier = nn.Sequential(
            nn.Linear(64 * 6 * 6, 64),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        feat = self.features(x)
        feat = feat.view(feat.size(0), -1)
        return self.classifier(feat)


# ==============================================================================
# 5. TRAINING & VALIDATION ROUTINE
# ==============================================================================
def train_and_evaluate():
    t_start = time.time()

    # Load / Cache splits
    train_bytes, train_labels, train_meta = prepare_split_cache("train", TRAIN_CSV)
    val_bytes, val_labels, val_meta = prepare_split_cache("val", VAL_CSV)
    test_bytes, test_labels, test_meta = prepare_split_cache("test", TEST_CSV)

    n_train = len(train_labels)
    n_val = len(val_labels)
    n_test = len(test_labels)

    n_train_normal = int(np.sum(train_labels == 0))
    n_train_malicious = int(np.sum(train_labels == 1))

    # Class weights calculation
    w_normal = n_train / (2.0 * n_train_normal)
    w_malicious = n_train / (2.0 * n_train_malicious)
    class_weights = torch.tensor([w_normal, w_malicious], dtype=torch.float32)

    print("\n" + "=" * 60)
    print("DATASET & CLASS IMBALANCE SETUP:")
    print(f"  Train samples:      {n_train:,} (NORMAL: {n_train_normal:,}, MALICIOUS: {n_train_malicious:,})")
    print(f"  Validation samples: {n_val:,} (NORMAL: {np.sum(val_labels == 0):,}, MALICIOUS: {np.sum(val_labels == 1):,})")
    print(f"  Test samples:       {n_test:,} (NORMAL: {np.sum(test_labels == 0):,}, MALICIOUS: {np.sum(test_labels == 1):,})")
    print(f"  Imbalance ratio:    {n_train_normal / n_train_malicious:.2f} : 1")
    print(f"  Inverse-Frequency Weights:")
    print(f"    Class 0 (NORMAL):    {w_normal:.4f}")
    print(f"    Class 1 (MALICIOUS): {w_malicious:.4f}")
    print("=" * 60)

    train_ds = CicIdsRgbDataset(train_bytes, train_labels)
    val_ds = CicIdsRgbDataset(val_bytes, val_labels)
    test_ds = CicIdsRgbDataset(test_bytes, test_labels)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate_fn, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_fn, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_fn, num_workers=0)

    model = CicIdsRgbCnn(num_classes=NUM_CLASSES)
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)

    best_val_f1 = -1.0
    best_epoch = -1
    best_model_path = os.path.join(MODELS_DIR, "best_rgb_cnn.pt")

    history = {
        "epoch": [],
        "train_loss": [],
        "train_acc": [],
        "val_loss": [],
        "val_acc": [],
        "val_precision": [],
        "val_recall": [],
        "val_f1_macro": [],
        "val_f1_malicious": []
    }

    print("\n" + "=" * 60)
    print("STARTING TRAINING (5 EPOCHS):")
    print("=" * 60)

    for epoch in range(1, EPOCHS + 1):
        epoch_t0 = time.time()
        model.train()
        running_loss = 0.0
        correct_train = 0
        total_train = 0

        for b_idx, (images, targets) in enumerate(train_loader, 1):
            optimizer.zero_grad()
            outputs = model(images)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()

            running_loss += loss.item() * targets.size(0)
            preds = torch.argmax(outputs, dim=1)
            correct_train += (preds == targets).sum().item()
            total_train += targets.size(0)

            if b_idx % 200 == 0 or b_idx == len(train_loader):
                cur_loss = running_loss / total_train
                cur_acc = correct_train / total_train
                elapsed = time.time() - epoch_t0
                speed = total_train / elapsed
                print(f"  Epoch {epoch}/{EPOCHS} [{total_train:,}/{n_train:,}] | Loss: {cur_loss:.4f} | Acc: {cur_acc*100:.2f}% | Speed: {speed:.0f} samples/s ({elapsed:.1f}s)", flush=True)

        train_loss = running_loss / total_train
        train_acc = correct_train / total_train

        # Validation on val set
        model.eval()
        val_running_loss = 0.0
        all_val_preds = []
        all_val_targets = []

        with torch.no_grad():
            for images, targets in val_loader:
                outputs = model(images)
                loss = criterion(outputs, targets)
                val_running_loss += loss.item() * targets.size(0)
                preds = torch.argmax(outputs, dim=1)
                all_val_preds.extend(preds.cpu().numpy())
                all_val_targets.extend(targets.cpu().numpy())

        val_loss = val_running_loss / n_val
        val_preds_arr = np.array(all_val_preds)
        val_targets_arr = np.array(all_val_targets)

        val_acc = accuracy_score(val_targets_arr, val_preds_arr)
        prec, rec, f1, _ = precision_recall_fscore_support(val_targets_arr, val_preds_arr, average="macro", zero_division=0)
        prec_mal, rec_mal, f1_mal, _ = precision_recall_fscore_support(val_targets_arr, val_preds_arr, average=None, zero_division=0)

        history["epoch"].append(epoch)
        history["train_loss"].append(train_loss)
        history["train_acc"].append(train_acc)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)
        history["val_precision"].append(prec)
        history["val_recall"].append(rec)
        history["val_f1_macro"].append(f1)
        history["val_f1_malicious"].append(f1_mal[1])

        print(f"\n--- Epoch {epoch}/{EPOCHS} Evaluation Summary ---")
        print(f"  Train Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.2f}%")
        print(f"  Val Loss:   {val_loss:.4f} | Val Acc:   {val_acc*100:.2f}%")
        print(f"  Val Macro Precision: {prec:.4f} | Recall: {rec:.4f} | Macro F1: {f1:.4f}")
        print(f"  Val Malicious F1:    {f1_mal[1]:.4f} (Recall: {rec_mal[1]:.4f})")
        print(f"  Epoch Duration:      {time.time()-epoch_t0:.1f}s")

        # Checkpoint if validation macro F1 improved
        if f1 > best_val_f1:
            best_val_f1 = f1
            best_epoch = epoch
            torch.save(model.state_dict(), best_model_path)
            print(f"  >>> Checkpoint Saved: Best Val Macro F1 = {best_val_f1:.4f} at epoch {epoch} <<<\n", flush=True)

    print("=" * 60)
    print(f"TRAINING COMPLETE! Best checkpoint at Epoch {best_epoch} with Val Macro F1 = {best_val_f1:.4f}")
    print("=" * 60)

    # Save training history
    history_df = pd.DataFrame(history)
    history_csv = os.path.join(RESULTS_DIR, "training_history.csv")
    history_df.to_csv(history_csv, index=False)
    with open(os.path.join(RESULTS_DIR, "history.json"), "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    # Plot Accuracy & Loss curves
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    ax1.plot(history["epoch"], history["train_loss"], "o-", label="Train Loss", color="#1f77b4")
    ax1.plot(history["epoch"], history["val_loss"], "s--", label="Val Loss", color="#ff7f0e")
    ax1.set_title("Training & Validation Loss")
    ax1.set_xlabel("Epoch")
    ax1.set_ylabel("Weighted Cross-Entropy Loss")
    ax1.legend()
    ax1.grid(True, linestyle=":", alpha=0.6)

    ax2.plot(history["epoch"], history["train_acc"], "o-", label="Train Acc", color="#2ca02c")
    ax2.plot(history["epoch"], history["val_acc"], "s--", label="Val Acc", color="#d62728")
    ax2.plot(history["epoch"], history["val_f1_macro"], "^-.", label="Val Macro F1", color="#9467bd")
    ax2.set_title("Accuracy & Macro F1 Score")
    ax2.set_xlabel("Epoch")
    ax2.set_ylabel("Score")
    ax2.legend()
    ax2.grid(True, linestyle=":", alpha=0.6)

    plt.tight_layout()
    curves_path = os.path.join(RESULTS_DIR, "loss_accuracy_curves.png")
    plt.savefig(curves_path, dpi=200)
    plt.close()
    print(f"Saved: {curves_path}")

    # ==============================================================================
    # 6. FINAL HELD-OUT TEST EVALUATION
    # Evaluated strictly once on test.csv using the best checkpoint.
    # ==============================================================================
    print("\n" + "=" * 60)
    print("EVALUATING BEST MODEL ON HELD-OUT TEST SET (52,752 SAMPLES):")
    print("=" * 60)

    model.load_state_dict(torch.load(best_model_path))
    model.eval()

    all_test_preds = []
    all_test_probs = []
    all_test_targets = []

    test_t0 = time.time()
    with torch.no_grad():
        for images, targets in test_loader:
            outputs = model(images)
            probs = torch.softmax(outputs, dim=1)
            preds = torch.argmax(outputs, dim=1)

            all_test_preds.extend(preds.cpu().numpy())
            all_test_probs.extend(probs[:, 1].cpu().numpy())  # Probability of MALICIOUS
            all_test_targets.extend(targets.cpu().numpy())

    test_eval_time = time.time() - test_t0
    print(f"Test inference completed in {test_eval_time:.1f}s ({n_test/test_eval_time:.0f} samples/sec)!")

    y_true = np.array(all_test_targets)
    y_pred = np.array(all_test_preds)
    y_prob = np.array(all_test_probs)

    # Core Metrics
    test_acc = accuracy_score(y_true, y_pred)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    per_p, per_r, per_f1, per_support = precision_recall_fscore_support(y_true, y_pred, average=None, zero_division=0)

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    roc_auc = roc_auc_score(y_true, y_prob)
    fpr, tpr, thresholds = roc_curve(y_true, y_prob)

    # Confusion Matrix Visualization
    plt.figure(figsize=(6, 5))
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title("Confusion Matrix: CIC-IDS2017 RGB CNN (Test Set)")
    plt.colorbar()
    tick_marks = np.arange(len(CLASS_NAMES))
    plt.xticks(tick_marks, CLASS_NAMES)
    plt.yticks(tick_marks, CLASS_NAMES)

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            pct = val / n_test * 100
            plt.text(j, i, f"{val:,}\n({pct:.2f}%)",
                     horizontalalignment="center",
                     verticalalignment="center",
                     color="white" if val > thresh else "black")

    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    cm_plot_path = os.path.join(RESULTS_DIR, "confusion_matrix.png")
    plt.savefig(cm_plot_path, dpi=200)
    plt.close()
    print(f"Saved: {cm_plot_path}")

    # Confusion matrix CSV
    cm_df = pd.DataFrame(cm, index=[f"True_{c}" for c in CLASS_NAMES], columns=[f"Pred_{c}" for c in CLASS_NAMES])
    cm_csv_path = os.path.join(RESULTS_DIR, "confusion_matrix.csv")
    cm_df.to_csv(cm_csv_path)

    # ROC Curve Visualization
    plt.figure(figsize=(7, 6))
    plt.plot(fpr, tpr, color="#d62728", lw=2, label=f"RGB CNN (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color="navy", lw=1.5, linestyle="--")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (FPR)")
    plt.ylabel("True Positive Rate (Recall / TPR)")
    plt.title("ROC Curve: CIC-IDS2017 RGB CNN (Test Set)")
    plt.legend(loc="lower right")
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    roc_plot_path = os.path.join(RESULTS_DIR, "roc_curve.png")
    plt.savefig(roc_plot_path, dpi=200)
    plt.close()
    print(f"Saved: {roc_plot_path}")

    # Test Predictions CSV
    pred_df = pd.DataFrame({
        "window_id": test_meta["window_ids"],
        "flow_id": test_meta["flow_ids"],
        "attack_category": test_meta["attack_categories"],
        "true_label": [CLASS_NAMES[y] for y in y_true],
        "true_label_id": y_true,
        "pred_label": [CLASS_NAMES[y] for y in y_pred],
        "pred_label_id": y_pred,
        "prob_malicious": np.round(y_prob, 5)
    })
    preds_csv_path = os.path.join(RESULTS_DIR, "test_predictions.csv")
    pred_df.to_csv(preds_csv_path, index=False)
    print(f"Saved: {preds_csv_path} ({len(pred_df):,} test predictions)")

    # Attack Category Specific Performance
    category_metrics = {}
    for cat in sorted(set(test_meta["attack_categories"])):
        cat_mask = (pred_df["attack_category"] == cat)
        cat_total = int(np.sum(cat_mask))
        if cat_total == 0:
            continue
        cat_true = y_true[cat_mask]
        cat_pred = y_pred[cat_mask]
        cat_correct = int(np.sum(cat_true == cat_pred))
        cat_acc = cat_correct / cat_total
        category_metrics[cat] = {
            "total_windows": cat_total,
            "correct_windows": cat_correct,
            "accuracy": round(cat_acc, 6),
            "detection_rate": round(cat_acc, 6) if cat != "BENIGN" else None
        }

    # Classification Report JSON
    clf_rep_dict = classification_report(y_true, y_pred, target_names=CLASS_NAMES, output_dict=True, zero_division=0)
    clf_rep_path = os.path.join(RESULTS_DIR, "classification_report.json")
    with open(clf_rep_path, "w", encoding="utf-8") as f:
        json.dump(clf_rep_dict, f, indent=2)

    # ONNX Export
    onnx_path = os.path.join(MODELS_DIR, "best_rgb_cnn.onnx")
    dummy_input = torch.randn(1, 3, 27, 27)
    torch.onnx.export(
        model,
        dummy_input,
        onnx_path,
        export_params=True,
        opset_version=14,
        do_constant_folding=True,
        input_names=["rgb_input"],
        output_names=["output_logits"],
        dynamic_axes={"rgb_input": {0: "batch_size"}, "output_logits": {0: "batch_size"}}
    )
    print(f"Saved ONNX Model: {onnx_path} ({os.path.getsize(onnx_path):,} bytes)")

    # Comprehensive Text Metrics Report
    metrics_txt = f"""================================================================================
SPIN-IDS EVALUATION REPORT: CIC-IDS2017 WEDNESDAY RGB CNN BASELINE
================================================================================
Date:               {time.strftime('%Y-%m-%d %H:%M:%S')}
Model Architecture: 2D Sequential CNN [Conv2D(32)-MaxPool-Conv2D(64)-MaxPool-Dense(64)-Dropout(0.3)-Dense(2)]
Input Representation: 2,187 bytes = 9 pkts x 243 bytes = 27x27x3 RGB image (PacketImageBuilder 3x3 grid)
Class Weighting:    Inverse-Frequency Balanced Loss (w_normal={w_normal:.4f}, w_malicious={w_malicious:.4f})
Best Epoch:         {best_epoch} / {EPOCHS} (Selected via Validation Macro F1)
Total Test Samples: {n_test:,} (NORMAL: {int(per_support[0]):,}, MALICIOUS: {int(per_support[1]):,})

1. OVERALL BINARY CLASSIFICATION METRICS:
  - Accuracy:         {test_acc:.6f} ({test_acc*100:.2f}%)
  - ROC-AUC Score:    {roc_auc:.6f}
  - Macro Precision:  {macro_p:.6f}
  - Macro Recall:     {macro_r:.6f}
  - Macro F1-Score:   {macro_f1:.6f}
  - Weighted F1-Score:{weighted_f1:.6f}

2. PER-CLASS METRICS:
  Class 0 (NORMAL / BENIGN):
    - Precision:      {per_p[0]:.6f}
    - Recall:         {per_r[0]:.6f}
    - F1-Score:       {per_f1[0]:.6f}
    - Support:        {int(per_support[0]):,} windows
  Class 1 (MALICIOUS / ATTACKS):
    - Precision:      {per_p[1]:.6f}
    - Recall:         {per_r[1]:.6f}
    - F1-Score:       {per_f1[1]:.6f}
    - Support:        {int(per_support[1]):,} windows

3. CONFUSION MATRIX:
  - True Negatives  (TN - Normal correctly identified):    {tn:>6,} ({tn/n_test*100:6.2f}%)
  - False Positives (FP - Normal misclassified as Attack): {fp:>6,} ({fp/n_test*100:6.2f}%)
  - False Negatives (FN - Attack missed):                  {fn:>6,} ({fn/n_test*100:6.2f}%)
  - True Positives  (TP - Attack correctly detected):      {tp:>6,} ({tp/n_test*100:6.2f}%)

4. ATTACK-CATEGORY BREAKDOWN IN TEST SET:
{json.dumps(category_metrics, indent=2)}

5. SAVED ARTIFACTS:
  - PyTorch Checkpoint:    {best_model_path}
  - ONNX Model:            {onnx_path}
  - Training History CSV:  {history_csv}
  - Loss/Acc Curves:       {curves_path}
  - Confusion Matrix Plot: {cm_plot_path}
  - Confusion Matrix CSV:  {cm_csv_path}
  - ROC Curve Plot:        {roc_plot_path}
  - Test Predictions CSV:  {preds_csv_path}
  - Classification Report: {clf_rep_path}
================================================================================
"""
    metrics_path = os.path.join(RESULTS_DIR, "metrics.txt")
    with open(metrics_path, "w", encoding="utf-8") as f:
        f.write(metrics_txt)
    print(f"Saved: {metrics_path}")

    print("\n" + "=" * 70)
    print("FINAL SUMMARY REPORT:")
    print("=" * 70)
    print(f"Accuracy:        {test_acc:.4f} ({test_acc*100:.2f}%)")
    print(f"ROC-AUC:         {roc_auc:.4f}")
    print(f"Macro Precision: {macro_p:.4f} | Macro Recall: {macro_r:.4f} | Macro F1: {macro_f1:.4f}")
    print(f"Normal Class:    Precision={per_p[0]:.4f}, Recall={per_r[0]:.4f}, F1={per_f1[0]:.4f}")
    print(f"Malicious Class: Precision={per_p[1]:.4f}, Recall={per_r[1]:.4f}, F1={per_f1[1]:.4f}")
    print(f"Confusion:       TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
    print(f"Attack Category Breakdown:")
    for cat, m in category_metrics.items():
        print(f"  - {cat:<16}: Acc={m['accuracy']*100:.2f}% ({m['correct_windows']:,}/{m['total_windows']:,} windows)")
    print(f"Total Experiment Time: {time.time()-t_start:.1f}s")
    print("=" * 70)

    return True


if __name__ == "__main__":
    train_and_evaluate()
