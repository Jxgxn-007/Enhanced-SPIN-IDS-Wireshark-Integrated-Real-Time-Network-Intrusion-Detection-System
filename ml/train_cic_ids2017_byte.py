"""
SPIN-IDS: Genuine CIC-IDS2017 Wednesday Byte/Hex Baseline Experiment
Branch: 1D Byte Sequence CNN Branch

Architecture:
  Input: 2,187 bytes = 9 sequential packets x 243 preprocessed bytes.
  Representation: 1D sequence normalized to [0.0, 1.0] -> Shape: (B, 1, 2187).
  Network: Hierarchical 1D CNN with multi-scale packet-stride convolutions,
           batch normalization, pooling, and dense classification head.

Class Imbalance Handling:
  Class counts in training set:
    - NORMAL (BENIGN): 196,640 (80.14%)
    - MALICIOUS (Attacks): 48,734 (19.86%)
    - Imbalance ratio: ~4.03 : 1
  Method:
    Inverse-frequency balanced class weighting:
      w_normal    = N_total / (2 * N_normal)    = 245374 / (2 * 196640) = 0.623927
      w_malicious = N_total / (2 * N_malicious) = 245374 / (2 * 48734)  = 2.517483
    Applied via weighted Cross-Entropy Loss (weight=torch.tensor([w_normal, w_malicious])).

Integrity Rules:
  - Exact flow-level train/validation/test isolation (zero flow leakage, Seed 42).
  - Validation set used strictly for epoch monitoring and best-model checkpointing.
  - Held-out test set evaluated ONCE on the selected best checkpoint.
  - Fully self-contained pure-NumPy evaluation metrics (no fragile binary dependencies).
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

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# ==============================================================================
# 1. PATH CONFIGURATION & REPRODUCIBILITY SEED
# ==============================================================================
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "External_CIC_IDS2017", "processed")
CACHE_DIR = os.path.join(PROCESSED_DIR, "cache")

RESULTS_DIR = os.path.join(BASE_DIR, "ml", "results", "cic_ids2017_byte")
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models", "cic_ids2017_byte")

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

WINDOW_BYTES = 2187
NUM_CLASSES = 2
CLASS_NAMES = ["NORMAL", "MALICIOUS"]

BATCH_SIZE = 256
EPOCHS = 5
LEARNING_RATE = 0.001
WEIGHT_DECAY = 1e-4

print("=" * 70)
print("SPIN-IDS: CIC-IDS2017 WEDNESDAY BYTE/HEX 1D CNN BASELINE TRAINING")
print("=" * 70)
print(f"Base Directory:     {BASE_DIR}")
print(f"Processed Dataset:  {PROCESSED_DIR}")
print(f"Results Directory:  {RESULTS_DIR}")
print(f"Models Directory:   {MODELS_DIR}")
print(f"Random Seed:        {SEED}")
print(f"Device:             CPU (PyTorch {torch.__version__})")
print("=" * 70)


# ==============================================================================
# 2. PURE-NUMPY EVALUATION METRICS (STANDALONE & FULLY DETERMINISTIC)
# ==============================================================================
def confusion_matrix(y_true, y_pred):
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred = np.asarray(y_pred, dtype=np.int64)
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    return np.array([[tn, fp], [fn, tp]], dtype=np.int64)


def accuracy_score(y_true, y_pred):
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    return float(np.mean(y_true == y_pred))


def precision_recall_fscore_support(y_true, y_pred, average=None, zero_division=0):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    # Class 0: NORMAL
    p0 = tn / (tn + fn) if (tn + fn) > 0 else float(zero_division)
    r0 = tn / (tn + fp) if (tn + fp) > 0 else float(zero_division)
    f1_0 = (2.0 * p0 * r0) / (p0 + r0) if (p0 + r0) > 0 else float(zero_division)
    s0 = int(tn + fp)

    # Class 1: MALICIOUS
    p1 = tp / (tp + fp) if (tp + fp) > 0 else float(zero_division)
    r1 = tp / (tp + fn) if (tp + fn) > 0 else float(zero_division)
    f1_1 = (2.0 * p1 * r1) / (p1 + r1) if (p1 + r1) > 0 else float(zero_division)
    s1 = int(fn + tp)

    if average == "macro":
        return (p0 + p1) / 2.0, (r0 + r1) / 2.0, (f1_0 + f1_1) / 2.0, None
    elif average == "weighted":
        total = s0 + s1
        if total == 0:
            return 0.0, 0.0, 0.0, None
        return (
            (p0 * s0 + p1 * s1) / total,
            (r0 * s0 + r1 * s1) / total,
            (f1_0 * s0 + f1_1 * s1) / total,
            None
        )
    else:
        return (
            np.array([p0, p1]),
            np.array([r0, r1]),
            np.array([f1_0, f1_1]),
            np.array([s0, s1])
        )


def roc_curve(y_true, y_score):
    y_true = np.asarray(y_true, dtype=np.int64)
    y_score = np.asarray(y_score, dtype=np.float64)

    desc_indices = np.argsort(y_score, kind="mergesort")[::-1]
    y_score_sorted = y_score[desc_indices]
    y_true_sorted = y_true[desc_indices]

    distinct_value_indices = np.where(np.diff(y_score_sorted))[0]
    threshold_idxs = np.r_[distinct_value_indices, y_true_sorted.size - 1]

    tps = np.cumsum(y_true_sorted)[threshold_idxs]
    fps = (1 + threshold_idxs) - tps

    n_pos = tps[-1]
    n_neg = fps[-1]

    if n_pos == 0 or n_neg == 0:
        return np.array([0.0, 1.0]), np.array([0.0, 1.0]), np.array([1.0, 0.0])

    fpr = fps / n_neg
    tpr = tps / n_pos

    fpr = np.r_[0.0, fpr]
    tpr = np.r_[0.0, tpr]
    thresholds = np.r_[y_score_sorted[0] + 1.0, y_score_sorted[threshold_idxs]]
    return fpr, tpr, thresholds


def roc_auc_score(y_true, y_score):
    fpr, tpr, _ = roc_curve(y_true, y_score)
    trap = getattr(np, "trapezoid", getattr(np, "trapz", None))
    return float(trap(tpr, fpr))


def classification_report(y_true, y_pred, target_names=("NORMAL", "MALICIOUS"), output_dict=True, zero_division=0):
    cm = confusion_matrix(y_true, y_pred)
    per_p, per_r, per_f1, per_s = precision_recall_fscore_support(y_true, y_pred, average=None, zero_division=zero_division)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=zero_division)
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=zero_division)
    acc = accuracy_score(y_true, y_pred)
    total_samples = int(np.sum(cm))

    report = {
        target_names[0]: {
            "precision": round(float(per_p[0]), 6),
            "recall": round(float(per_r[0]), 6),
            "f1-score": round(float(per_f1[0]), 6),
            "support": int(per_s[0])
        },
        target_names[1]: {
            "precision": round(float(per_p[1]), 6),
            "recall": round(float(per_r[1]), 6),
            "f1-score": round(float(per_f1[1]), 6),
            "support": int(per_s[1])
        },
        "accuracy": round(acc, 6),
        "macro avg": {
            "precision": round(float(macro_p), 6),
            "recall": round(float(macro_r), 6),
            "f1-score": round(float(macro_f1), 6),
            "support": total_samples
        },
        "weighted avg": {
            "precision": round(float(weighted_p), 6),
            "recall": round(float(weighted_r), 6),
            "f1-score": round(float(weighted_f1), 6),
            "support": total_samples
        }
    }
    return report


# ==============================================================================
# 3. BINARY CACHE LOADING & VALIDATION
# ==============================================================================
def load_split_cache(split_name):
    bytes_npy = os.path.join(CACHE_DIR, f"{split_name}_bytes.npy")
    labels_npy = os.path.join(CACHE_DIR, f"{split_name}_labels.npy")
    meta_json = os.path.join(CACHE_DIR, f"{split_name}_meta.json")

    if not (os.path.exists(bytes_npy) and os.path.exists(labels_npy) and os.path.exists(meta_json)):
        raise FileNotFoundError(f"Cache missing for split '{split_name}'. Expected: {bytes_npy}")

    print(f"Loading cached binary for {split_name}: {bytes_npy}")
    raw_bytes = np.load(bytes_npy, mmap_mode="r")
    labels = np.load(labels_npy)
    with open(meta_json, "r", encoding="utf-8") as f:
        meta = json.load(f)

    # Sanity checks
    assert len(raw_bytes) == len(labels) == len(meta["window_ids"]), f"Mismatched lengths in {split_name}"
    assert raw_bytes.shape[1] == WINDOW_BYTES, f"Expected {WINDOW_BYTES} bytes, got {raw_bytes.shape[1]}"
    print(f"  Loaded {split_name}: {len(labels):,} windows ({raw_bytes.dtype}, {raw_bytes.shape})")
    return raw_bytes, labels, meta


class CicIdsByteDataset(Dataset):
    def __init__(self, raw_bytes, labels):
        self.raw_bytes = raw_bytes
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.raw_bytes[idx], self.labels[idx]


def collate_fn(batch):
    bytes_list, labels_list = zip(*batch)
    batch_bytes = np.stack(bytes_list, axis=0)  # (B, 2187) uint8
    # Normalize to [0.0, 1.0] float32 and reshape to (B, 1, 2187)
    tensor_arr = (batch_bytes.astype(np.float32) / 255.0)[:, np.newaxis, :]
    batch_tensors = torch.from_numpy(tensor_arr)
    batch_labels = torch.tensor(labels_list, dtype=torch.long)
    return batch_tensors, batch_labels


# ==============================================================================
# 4. BYTE 1D CNN MODEL ARCHITECTURE
# ==============================================================================
class CicIdsByte1DCNN(nn.Module):
    """
    1D CNN for sequential network byte stream classification:
      - Input: (B, 1, 2187) normalized [0.0, 1.0]
      - Conv1D (in=1, out=32, k=9, s=3, p=4) + BatchNorm1D + ReLU + MaxPool1D(3, s=3) -> (B, 32, 243)
      - Conv1D (in=32, out=64, k=7, s=1, p=3) + BatchNorm1D + ReLU + MaxPool1D(3, s=3) -> (B, 64, 81)
      - Conv1D (in=64, out=128, k=5, s=1, p=2) + BatchNorm1D + ReLU + AdaptiveAvgPool1D(1) -> (B, 128, 1)
      - Flatten -> (B, 128)
      - Dense (128 -> 64) + ReLU + Dropout(0.3)
      - Dense (64 -> 2) [Softmax Logits]
    """
    def __init__(self, num_classes=2):
        super().__init__()
        self.conv1 = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=9, stride=3, padding=4),
            nn.BatchNorm1d(32),
            nn.ReLU(inplace=True),
            nn.MaxPool1d(kernel_size=3, stride=3)
        )
        self.conv2 = nn.Sequential(
            nn.Conv1d(32, 64, kernel_size=7, stride=1, padding=3),
            nn.BatchNorm1d(64),
            nn.ReLU(inplace=True),
            nn.MaxPool1d(kernel_size=3, stride=3)
        )
        self.conv3 = nn.Sequential(
            nn.Conv1d(64, 128, kernel_size=5, stride=1, padding=2),
            nn.BatchNorm1d(128),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool1d(1)
        )
        self.classifier = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        x = self.conv1(x)
        x = self.conv2(x)
        x = self.conv3(x)
        feat = x.squeeze(-1)
        return self.classifier(feat)


# ==============================================================================
# 5. TRAINING, VALIDATION, AND EVALUATION PIPELINE
# ==============================================================================
def train_and_evaluate():
    t_start = time.time()

    # Load verified binary cache splits
    train_bytes, train_labels, train_meta = load_split_cache("train")
    val_bytes, val_labels, val_meta = load_split_cache("val")
    test_bytes, test_labels, test_meta = load_split_cache("test")

    n_train = len(train_labels)
    n_val = len(val_labels)
    n_test = len(test_labels)

    n_train_normal = int(np.sum(train_labels == 0))
    n_train_malicious = int(np.sum(train_labels == 1))

    # Verify class-weight calculation against actual training labels
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

    train_ds = CicIdsByteDataset(train_bytes, train_labels)
    val_ds = CicIdsByteDataset(val_bytes, val_labels)
    test_ds = CicIdsByteDataset(test_bytes, test_labels)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate_fn, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_fn, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_fn, num_workers=0)

    model = CicIdsByte1DCNN(num_classes=NUM_CLASSES)
    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Model Architecture Initialized: {total_params:,} trainable parameters")

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)

    best_val_f1 = -1.0
    best_epoch = -1
    best_model_path = os.path.join(MODELS_DIR, "best_byte_cnn.pt")

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
    print(f"STARTING TRAINING ({EPOCHS} EPOCHS):")
    print("=" * 60)

    for epoch in range(1, EPOCHS + 1):
        epoch_t0 = time.time()
        model.train()
        running_loss = 0.0
        correct_train = 0
        total_train = 0

        for b_idx, (inputs, targets) in enumerate(train_loader, 1):
            optimizer.zero_grad()
            outputs = model(inputs)
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

        # Validation set evaluation
        model.eval()
        val_running_loss = 0.0
        all_val_preds = []
        all_val_targets = []

        with torch.no_grad():
            for inputs, targets in val_loader:
                outputs = model(inputs)
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
        per_p, per_r, per_f1, _ = precision_recall_fscore_support(val_targets_arr, val_preds_arr, average=None, zero_division=0)

        history["epoch"].append(epoch)
        history["train_loss"].append(train_loss)
        history["train_acc"].append(train_acc)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)
        history["val_precision"].append(prec)
        history["val_recall"].append(rec)
        history["val_f1_macro"].append(f1)
        history["val_f1_malicious"].append(per_f1[1])

        print(f"\n--- Epoch {epoch}/{EPOCHS} Evaluation Summary ---")
        print(f"  Train Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.2f}%")
        print(f"  Val Loss:   {val_loss:.4f} | Val Acc:   {val_acc*100:.2f}%")
        print(f"  Val Macro Precision: {prec:.4f} | Recall: {rec:.4f} | Macro F1: {f1:.4f}")
        print(f"  Val Malicious F1:    {per_f1[1]:.4f} (Recall: {per_r[1]:.4f})")
        print(f"  Epoch Duration:      {time.time()-epoch_t0:.1f}s")

        # Save checkpoint if validation macro F1 improved
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
    ax1.set_title("Training & Validation Loss (Byte 1D CNN)")
    ax1.set_xlabel("Epoch")
    ax1.set_ylabel("Weighted Cross-Entropy Loss")
    ax1.legend()
    ax1.grid(True, linestyle=":", alpha=0.6)

    ax2.plot(history["epoch"], history["train_acc"], "o-", label="Train Acc", color="#2ca02c")
    ax2.plot(history["epoch"], history["val_acc"], "s--", label="Val Acc", color="#d62728")
    ax2.plot(history["epoch"], history["val_f1_macro"], "^-.", label="Val Macro F1", color="#9467bd")
    ax2.set_title("Accuracy & Macro F1 Score (Byte 1D CNN)")
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
    # 6. FINAL HELD-OUT TEST EVALUATION (STRICTLY ONCE ON BEST CHECKPOINT)
    # ==============================================================================
    print("\n" + "=" * 60)
    print(f"EVALUATING BEST MODEL ON HELD-OUT TEST SET ({n_test:,} SAMPLES):")
    print("=" * 60)

    model.load_state_dict(torch.load(best_model_path))
    model.eval()

    all_test_preds = []
    all_test_probs = []
    all_test_targets = []

    test_t0 = time.time()
    with torch.no_grad():
        for inputs, targets in test_loader:
            outputs = model(inputs)
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
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Greens)
    plt.title("Confusion Matrix: CIC-IDS2017 Byte 1D CNN (Test Set)")
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

    # Confusion Matrix CSV
    cm_df = pd.DataFrame(cm, index=[f"True_{c}" for c in CLASS_NAMES], columns=[f"Pred_{c}" for c in CLASS_NAMES])
    cm_csv_path = os.path.join(RESULTS_DIR, "confusion_matrix.csv")
    cm_df.to_csv(cm_csv_path)

    # ROC Curve Visualization
    plt.figure(figsize=(7, 6))
    plt.plot(fpr, tpr, color="#2ca02c", lw=2, label=f"Byte 1D CNN (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color="navy", lw=1.5, linestyle="--")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (FPR)")
    plt.ylabel("True Positive Rate (Recall / TPR)")
    plt.title("ROC Curve: CIC-IDS2017 Byte 1D CNN (Test Set)")
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

    # ONNX Export with sample inference verification
    onnx_path = os.path.join(MODELS_DIR, "best_byte_cnn.onnx")
    try:
        dummy_input = torch.randn(1, 1, WINDOW_BYTES)
        torch.onnx.export(
            model,
            dummy_input,
            onnx_path,
            export_params=True,
            opset_version=18,
            do_constant_folding=True,
            input_names=["byte_input"],
            output_names=["output_logits"],
            dynamic_axes={"byte_input": {0: "batch_size"}, "output_logits": {0: "batch_size"}}
        )
        print(f"Saved ONNX Model: {onnx_path} ({os.path.getsize(onnx_path):,} bytes)")

        # Verify ONNX model with ONNXRuntime
        import onnxruntime as ort
        ort_session = ort.InferenceSession(onnx_path)
        sample_input = np.random.randn(2, 1, WINDOW_BYTES).astype(np.float32)
        ort_out = ort_session.run(["output_logits"], {"byte_input": sample_input})
        print(f"ONNX Model Verification Succeeded: sample output shape = {ort_out[0].shape}")
    except Exception as e:
        print(f"Warning: ONNX export/verification failed: {e}")

    # Comprehensive Text Metrics Report
    metrics_txt = f"""================================================================================
SPIN-IDS EVALUATION REPORT: CIC-IDS2017 WEDNESDAY BYTE/HEX 1D CNN BASELINE
================================================================================
Date:               {time.strftime('%Y-%m-%d %H:%M:%S')}
Model Architecture: 1D Sequential CNN [Conv1D(32,k=9,s=3)-MaxPool-Conv1D(64,k=7)-MaxPool-Conv1D(128,k=5)-AvgPool-Dense(64)-Dropout(0.3)-Dense(2)]
Input Representation: 2,187 bytes = 9 pkts x 243 preprocessed bytes (1D continuous byte stream normalized to [0, 1])
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
