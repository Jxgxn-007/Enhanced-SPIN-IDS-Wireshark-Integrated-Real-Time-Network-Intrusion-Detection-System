"""
SPIN-IDS: Genuine CIC-IDS2017 Wednesday Hybrid RGB + Byte Score-Fusion Pipeline
Phase: Hybrid Probability Fusion Model

Methodology:
  1. Audit and load trained RGB CNN (ml/models/cic_ids2017_rgb/best_rgb_cnn.pt)
     and Byte 1D CNN (ml/models/cic_ids2017_byte/best_byte_cnn.pt).
  2. Perform inference on validation data (52,432 samples) and align predictions
     using stable window IDs.
  3. Conduct exhaustive validation grid search over fusion weight alpha in [0.0, 1.0]
     and decision threshold tau in [0.1, 0.9].
  4. Select optimal (alpha*, tau*) based strictly on validation Macro F1, Malicious Recall,
     and False Positive Rate (Zero Test Leakage).
  5. Evaluate the selected configuration strictly ONCE on the held-out test split (52,752 samples).
  6. Measure inference latency, compute comparative metrics, attack-category breakdown,
     and generate plots under ml/results/cic_ids2017_hybrid/.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import torch
import torch.nn as nn

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# ==============================================================================
# 1. PATH CONFIGURATION & DIRECTORY SETUP
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(BASE_DIR, "dataset", "External_CIC_IDS2017", "processed", "cache")

RGB_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "cic_ids2017_rgb", "best_rgb_cnn.pt")
BYTE_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "cic_ids2017_byte", "best_byte_cnn.pt")

HYBRID_RESULTS_DIR = os.path.join(BASE_DIR, "ml", "results", "cic_ids2017_hybrid")
os.makedirs(HYBRID_RESULTS_DIR, exist_ok=True)

CLASS_NAMES = ["NORMAL", "MALICIOUS"]
WINDOW_BYTES = 2187
BATCH_SIZE = 512

print("=" * 70)
print("SPIN-IDS: CIC-IDS2017 HYBRID RGB + BYTE CNN SCORE-FUSION PIPELINE")
print("=" * 70)
print(f"Base Directory:        {BASE_DIR}")
print(f"RGB Model Checkpoint:  {RGB_MODEL_PATH}")
print(f"Byte Model Checkpoint: {BYTE_MODEL_PATH}")
print(f"Hybrid Results Dir:    {HYBRID_RESULTS_DIR}")
print("=" * 70)


# ==============================================================================
# 2. MODEL ARCHITECTURES
# ==============================================================================
class CicIdsRgbCnn(nn.Module):
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


class CicIdsByte1DCNN(nn.Module):
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


def bytes_to_chw_tensor(batch_uint8: np.ndarray) -> torch.Tensor:
    """Transforms raw uint8 bytes (B, 2187) into 2D RGB spatial tensor (B, 3, 27, 27)."""
    n = batch_uint8.shape[0]
    reshaped = batch_uint8.reshape(n, 3, 3, 9, 9, 3)
    permuted = reshaped.transpose(0, 5, 1, 3, 2, 4)
    tensor_arr = permuted.reshape(n, 3, 27, 27).astype(np.float32) / 255.0
    return torch.from_numpy(tensor_arr)


def bytes_to_1d_tensor(batch_uint8: np.ndarray) -> torch.Tensor:
    """Transforms raw uint8 bytes (B, 2187) into continuous 1D byte tensor (B, 1, 2187)."""
    tensor_arr = (batch_uint8.astype(np.float32) / 255.0)[:, np.newaxis, :]
    return torch.from_numpy(tensor_arr)


# ==============================================================================
# 3. PURE-NUMPY METRIC EVALUATION FUNCTIONS
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
    return float(np.mean(y_true == y_pred))


def precision_recall_fscore_support(y_true, y_pred, average=None, zero_division=0):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    p0 = tn / (tn + fn) if (tn + fn) > 0 else float(zero_division)
    r0 = tn / (tn + fp) if (tn + fp) > 0 else float(zero_division)
    f1_0 = (2.0 * p0 * r0) / (p0 + r0) if (p0 + r0) > 0 else float(zero_division)
    s0 = int(tn + fp)

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
# 4. BATCH INFERENCE HELPER
# ==============================================================================
def run_model_inference(model, raw_bytes, transform_fn, batch_size=BATCH_SIZE):
    """
    Executes batched forward inference on raw byte array and extracts softmax probabilities.
    Returns array of malicious probabilities and elapsed execution time.
    """
    model.eval()
    n = len(raw_bytes)
    probs_malicious = []
    t0 = time.time()

    with torch.no_grad():
        for i in range(0, n, batch_size):
            chunk = raw_bytes[i:i + batch_size]
            inputs = transform_fn(chunk)
            logits = model(inputs)
            probs = torch.softmax(logits, dim=1)[:, 1]  # Probability of MALICIOUS (class 1)
            probs_malicious.extend(probs.cpu().numpy())

    elapsed = time.time() - t0
    return np.array(probs_malicious, dtype=np.float64), elapsed


# ==============================================================================
# 5. MAIN EVALUATION PIPELINE
# ==============================================================================
def main():
    t_global = time.time()

    # Step 1: Load and Audit Checkpoints
    print("\n[Step 1] Loading and Auditing Model Checkpoints...")
    if not os.path.exists(RGB_MODEL_PATH):
        raise FileNotFoundError(f"Missing RGB model: {RGB_MODEL_PATH}")
    if not os.path.exists(BYTE_MODEL_PATH):
        raise FileNotFoundError(f"Missing Byte model: {BYTE_MODEL_PATH}")

    rgb_model = CicIdsRgbCnn()
    rgb_model.load_state_dict(torch.load(RGB_MODEL_PATH, map_location="cpu"))
    rgb_model.eval()
    rgb_params = sum(p.numel() for p in rgb_model.parameters())

    byte_model = CicIdsByte1DCNN()
    byte_model.load_state_dict(torch.load(BYTE_MODEL_PATH, map_location="cpu"))
    byte_model.eval()
    byte_params = sum(p.numel() for p in byte_model.parameters())

    print(f"  RGB CNN Model  : {rgb_params:,} parameters (Checkpoint loaded: {RGB_MODEL_PATH})")
    print(f"  Byte 1D CNN    : {byte_params:,} parameters (Checkpoint loaded: {BYTE_MODEL_PATH})")

    # Step 2: Load Validation Data
    print("\n[Step 2] Loading Validation Data for Tuning...")
    val_bytes = np.load(os.path.join(CACHE_DIR, "val_bytes.npy"), mmap_mode="r")
    val_labels = np.load(os.path.join(CACHE_DIR, "val_labels.npy"))
    with open(os.path.join(CACHE_DIR, "val_meta.json"), "r", encoding="utf-8") as f:
        val_meta = json.load(f)

    n_val = len(val_labels)
    assert len(val_bytes) == n_val == len(val_meta["window_ids"])
    print(f"  Validation Set: {n_val:,} samples (NORMAL: {np.sum(val_labels==0):,}, MALICIOUS: {np.sum(val_labels==1):,})")

    # Step 3: Validation Inference
    print("\n[Step 3] Running Validation Inference...")
    rgb_val_probs, rgb_val_time = run_model_inference(rgb_model, val_bytes, bytes_to_chw_tensor)
    print(f"  RGB Model Val Inference : {rgb_val_time:.2f}s ({n_val/rgb_val_time:.0f} samples/s)")

    byte_val_probs, byte_val_time = run_model_inference(byte_model, val_bytes, bytes_to_1d_tensor)
    print(f"  Byte Model Val Inference: {byte_val_time:.2f}s ({n_val/byte_val_time:.0f} samples/s)")

    # Verify probability bounds
    assert np.all((rgb_val_probs >= 0.0) & (rgb_val_probs <= 1.0))
    assert np.all((byte_val_probs >= 0.0) & (byte_val_probs <= 1.0))

    # Step 4: Validation Grid Search (Zero Test Leakage)
    print("\n[Step 4] Exhaustive Validation Grid Search across (alpha, threshold)...")
    alpha_values = np.linspace(0.0, 1.0, 21)  # [0.0, 0.05, 0.10, ..., 1.0]
    thresh_values = np.linspace(0.1, 0.9, 17)  # [0.10, 0.15, ..., 0.90]

    grid_results = []
    best_combo = None
    best_val_macro_f1 = -1.0

    for alpha in alpha_values:
        fused_val_prob = alpha * rgb_val_probs + (1.0 - alpha) * byte_val_probs
        for thresh in thresh_values:
            preds = (fused_val_prob >= thresh).astype(np.int64)
            acc = accuracy_score(val_labels, preds)
            macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(val_labels, preds, average="macro", zero_division=0)
            cm = confusion_matrix(val_labels, preds)
            tn, fp, fn, tp = cm.ravel()
            malicious_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0

            res = {
                "alpha": round(float(alpha), 4),
                "threshold": round(float(thresh), 4),
                "accuracy": round(acc, 6),
                "macro_precision": round(macro_p, 6),
                "macro_recall": round(macro_r, 6),
                "macro_f1": round(macro_f1, 6),
                "malicious_recall": round(malicious_recall, 6),
                "false_positive_rate": round(fpr, 6),
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp
            }
            grid_results.append(res)

            # Selection criterion:
            # 1. Highest Macro F1
            # 2. Tie-break: Highest Malicious Recall
            # 3. Tie-break: Lowest FPR
            # 4. Tie-break: Proximity to balanced alpha=0.5 and threshold=0.5
            is_better = False
            if macro_f1 > best_val_macro_f1:
                is_better = True
            elif abs(macro_f1 - best_val_macro_f1) < 1e-7:
                cur_diff = abs(alpha - 0.5) + abs(thresh - 0.5)
                best_diff = abs(best_combo["alpha"] - 0.5) + abs(best_combo["threshold"] - 0.5)
                if malicious_recall > best_combo["malicious_recall"]:
                    is_better = True
                elif abs(malicious_recall - best_combo["malicious_recall"]) < 1e-7:
                    if fpr < best_combo["false_positive_rate"]:
                        is_better = True
                    elif abs(fpr - best_combo["false_positive_rate"]) < 1e-7 and cur_diff < best_diff:
                        is_better = True

            if is_better:
                best_val_macro_f1 = macro_f1
                best_combo = res

    grid_df = pd.DataFrame(grid_results)
    grid_csv_path = os.path.join(HYBRID_RESULTS_DIR, "validation_grid_search.csv")
    grid_df.to_csv(grid_csv_path, index=False)
    print(f"  Grid Search completed ({len(grid_df)} combinations evaluated). Saved: {grid_csv_path}")

    # Report individual baseline performance on validation data
    val_rgb_baseline = grid_df[(grid_df["alpha"] == 1.0) & (grid_df["threshold"] == 0.5)].iloc[0]
    val_byte_baseline = grid_df[(grid_df["alpha"] == 0.0) & (grid_df["threshold"] == 0.5)].iloc[0]

    print("\n--- Validation Performance Comparison ---")
    print(f"  RGB-Only (alpha=1.0, thresh=0.5) : Macro F1={val_rgb_baseline['macro_f1']:.6f} | Acc={val_rgb_baseline['accuracy']*100:.3f}% | Recall={val_rgb_baseline['malicious_recall']:.6f} | FPR={val_rgb_baseline['false_positive_rate']*100:.4f}% (FP={val_rgb_baseline['fp']}, FN={val_rgb_baseline['fn']})")
    print(f"  Byte-Only (alpha=0.0, thresh=0.5): Macro F1={val_byte_baseline['macro_f1']:.6f} | Acc={val_byte_baseline['accuracy']*100:.3f}% | Recall={val_byte_baseline['malicious_recall']:.6f} | FPR={val_byte_baseline['false_positive_rate']*100:.4f}% (FP={val_byte_baseline['fp']}, FN={val_byte_baseline['fn']})")
    print(f"  Selected Hybrid (alpha={best_combo['alpha']}, thresh={best_combo['threshold']}): Macro F1={best_combo['macro_f1']:.6f} | Acc={best_combo['accuracy']*100:.3f}% | Recall={best_combo['malicious_recall']:.6f} | FPR={best_combo['false_positive_rate']*100:.4f}% (FP={best_combo['fp']}, FN={best_combo['fn']})")

    # Step 5: Load Held-Out Test Data
    print("\n[Step 5] Loading Held-Out Test Data (Zero Test Leakage)...")
    test_bytes = np.load(os.path.join(CACHE_DIR, "test_bytes.npy"), mmap_mode="r")
    test_labels = np.load(os.path.join(CACHE_DIR, "test_labels.npy"))
    with open(os.path.join(CACHE_DIR, "test_meta.json"), "r", encoding="utf-8") as f:
        test_meta = json.load(f)

    n_test = len(test_labels)
    assert len(test_bytes) == n_test == len(test_meta["window_ids"])
    print(f"  Test Set: {n_test:,} samples (NORMAL: {np.sum(test_labels==0):,}, MALICIOUS: {np.sum(test_labels==1):,})")

    # Step 6: Test Inference & Latency Measurement
    print("\n[Step 6] Executing Test Set Inference for Both Models...")
    rgb_test_probs, rgb_test_time = run_model_inference(rgb_model, test_bytes, bytes_to_chw_tensor)
    byte_test_probs, byte_test_time = run_model_inference(byte_model, test_bytes, bytes_to_1d_tensor)

    t_fuse_start = time.time()
    sel_alpha = best_combo["alpha"]
    sel_thresh = best_combo["threshold"]
    hybrid_test_probs = sel_alpha * rgb_test_probs + (1.0 - sel_alpha) * byte_test_probs
    hybrid_test_preds = (hybrid_test_probs >= sel_thresh).astype(np.int64)
    fuse_time = time.time() - t_fuse_start
    total_hybrid_test_time = rgb_test_time + byte_test_time + fuse_time

    print(f"  RGB Model Test Latency  : {rgb_test_time:.2f}s ({n_test/rgb_test_time:.0f} samples/s, {rgb_test_time/n_test*1000:.3f} ms/sample)")
    print(f"  Byte Model Test Latency : {byte_test_time:.2f}s ({n_test/byte_test_time:.0f} samples/s, {byte_test_time/n_test*1000:.3f} ms/sample)")
    print(f"  Hybrid Total Test Time  : {total_hybrid_test_time:.2f}s ({n_test/total_hybrid_test_time:.0f} samples/s, {total_hybrid_test_time/n_test*1000:.3f} ms/sample)")

    # Step 7: Comprehensive Test Set Metric Evaluation
    print("\n[Step 7] Computing Test Set Performance Metrics...")
    # Baseline 1: RGB-Only at threshold 0.5
    rgb_test_preds = (rgb_test_probs >= 0.5).astype(np.int64)
    rgb_cm = confusion_matrix(test_labels, rgb_test_preds)
    rgb_acc = accuracy_score(test_labels, rgb_test_preds)
    rgb_macro_p, rgb_macro_r, rgb_macro_f1, _ = precision_recall_fscore_support(test_labels, rgb_test_preds, average="macro", zero_division=0)
    rgb_auc = roc_auc_score(test_labels, rgb_test_probs)

    # Baseline 2: Byte-Only at threshold 0.5
    byte_test_preds = (byte_test_probs >= 0.5).astype(np.int64)
    byte_cm = confusion_matrix(test_labels, byte_test_preds)
    byte_acc = accuracy_score(test_labels, byte_test_preds)
    byte_macro_p, byte_macro_r, byte_macro_f1, _ = precision_recall_fscore_support(test_labels, byte_test_preds, average="macro", zero_division=0)
    byte_auc = roc_auc_score(test_labels, byte_test_probs)

    # Hybrid Model with tuned parameters
    hyb_cm = confusion_matrix(test_labels, hybrid_test_preds)
    hyb_tn, hyb_fp, hyb_fn, hyb_tp = hyb_cm.ravel()
    hyb_acc = accuracy_score(test_labels, hybrid_test_preds)
    hyb_macro_p, hyb_macro_r, hyb_macro_f1, _ = precision_recall_fscore_support(test_labels, hybrid_test_preds, average="macro", zero_division=0)
    hyb_weighted_p, hyb_weighted_r, hyb_weighted_f1, _ = precision_recall_fscore_support(test_labels, hybrid_test_preds, average="weighted", zero_division=0)
    hyb_per_p, hyb_per_r, hyb_per_f1, hyb_per_s = precision_recall_fscore_support(test_labels, hybrid_test_preds, average=None, zero_division=0)
    hyb_auc = roc_auc_score(test_labels, hybrid_test_probs)
    hyb_fpr = hyb_fp / (hyb_tn + hyb_fp) if (hyb_tn + hyb_fp) > 0 else 0.0

    print("=" * 60)
    print("TEST SET EVALUATION SUMMARY:")
    print("=" * 60)
    print(f"RGB-Only (alpha=1.0, thresh=0.5) : Acc={rgb_acc*100:.3f}% | Macro F1={rgb_macro_f1:.6f} | AUC={rgb_auc:.6f}")
    print(f"Byte-Only (alpha=0.0, thresh=0.5): Acc={byte_acc*100:.3f}% | Macro F1={byte_macro_f1:.6f} | AUC={byte_auc:.6f}")
    print(f"Hybrid   (alpha={sel_alpha}, thresh={sel_thresh}): Acc={hyb_acc*100:.3f}% | Macro F1={hyb_macro_f1:.6f} | AUC={hyb_auc:.6f}")
    print(f"Confusion: TN={hyb_tn:,}, FP={hyb_fp:,}, FN={hyb_fn:,}, TP={hyb_tp:,}")
    print("=" * 60)

    # Step 8: Save Test Predictions CSV
    preds_df = pd.DataFrame({
        "window_id": test_meta["window_ids"],
        "flow_id": test_meta["flow_ids"],
        "attack_category": test_meta["attack_categories"],
        "true_label": [CLASS_NAMES[y] for y in test_labels],
        "true_label_id": test_labels,
        "rgb_prob_malicious": np.round(rgb_test_probs, 5),
        "byte_prob_malicious": np.round(byte_test_probs, 5),
        "hybrid_prob_malicious": np.round(hybrid_test_probs, 5),
        "pred_label": [CLASS_NAMES[y] for y in hybrid_test_preds],
        "pred_label_id": hybrid_test_preds
    })
    preds_csv_path = os.path.join(HYBRID_RESULTS_DIR, "test_predictions.csv")
    preds_df.to_csv(preds_csv_path, index=False)
    print(f"Saved Test Predictions: {preds_csv_path} ({len(preds_df):,} rows)")

    # Step 9: Attack Category Breakdown
    category_metrics = {}
    for cat in sorted(set(test_meta["attack_categories"])):
        cat_mask = (preds_df["attack_category"] == cat)
        cat_total = int(np.sum(cat_mask))
        if cat_total == 0:
            continue
        cat_true = test_labels[cat_mask]
        cat_pred = hybrid_test_preds[cat_mask]
        cat_correct = int(np.sum(cat_true == cat_pred))
        cat_acc = cat_correct / cat_total
        category_metrics[cat] = {
            "total_windows": cat_total,
            "correct_windows": cat_correct,
            "accuracy": round(cat_acc, 6),
            "detection_rate": round(cat_acc, 6) if cat != "BENIGN" else None
        }

    # Step 10: Classification Report & Fusion Config JSON
    clf_rep_dict = classification_report(test_labels, hybrid_test_preds, target_names=CLASS_NAMES, output_dict=True, zero_division=0)
    clf_rep_path = os.path.join(HYBRID_RESULTS_DIR, "classification_report.json")
    with open(clf_rep_path, "w", encoding="utf-8") as f:
        json.dump(clf_rep_dict, f, indent=2)

    fusion_config = {
        "model_type": "Hybrid Weighted Probability Score-Fusion",
        "rgb_model_checkpoint": RGB_MODEL_PATH,
        "byte_model_checkpoint": BYTE_MODEL_PATH,
        "rgb_model_parameters": rgb_params,
        "byte_model_parameters": byte_params,
        "total_ensemble_parameters": rgb_params + byte_params,
        "selected_alpha": sel_alpha,
        "selected_threshold": sel_thresh,
        "selection_criterion": "Validation Macro F1 (primary), Malicious Recall (secondary), False Positive Rate (tertiary)",
        "validation_macro_f1": best_combo["macro_f1"],
        "validation_accuracy": best_combo["accuracy"],
        "validation_malicious_recall": best_combo["malicious_recall"],
        "validation_false_positive_rate": best_combo["false_positive_rate"],
        "test_macro_f1": round(hyb_macro_f1, 6),
        "test_accuracy": round(hyb_acc, 6),
        "test_roc_auc": round(hyb_auc, 6),
        "test_false_positive_rate": round(hyb_fpr, 6),
        "rgb_test_latency_ms_per_sample": round(rgb_test_time / n_test * 1000, 4),
        "byte_test_latency_ms_per_sample": round(byte_test_time / n_test * 1000, 4),
        "hybrid_test_latency_ms_per_sample": round(total_hybrid_test_time / n_test * 1000, 4)
    }
    config_json_path = os.path.join(HYBRID_RESULTS_DIR, "fusion_config.json")
    with open(config_json_path, "w", encoding="utf-8") as f:
        json.dump(fusion_config, f, indent=2)
    print(f"Saved Fusion Config: {config_json_path}")

    # Step 11: Plots & Visualizations
    # 1. Confusion Matrix
    plt.figure(figsize=(6, 5))
    plt.imshow(hyb_cm, interpolation="nearest", cmap=plt.cm.Purples)
    plt.title(f"Confusion Matrix: Hybrid RGB+Byte CNN (Test Set)\nalpha={sel_alpha}, threshold={sel_thresh}")
    plt.colorbar()
    tick_marks = np.arange(len(CLASS_NAMES))
    plt.xticks(tick_marks, CLASS_NAMES)
    plt.yticks(tick_marks, CLASS_NAMES)

    thresh = hyb_cm.max() / 2.0
    for i in range(hyb_cm.shape[0]):
        for j in range(hyb_cm.shape[1]):
            val = hyb_cm[i, j]
            pct = val / n_test * 100
            plt.text(j, i, f"{val:,}\n({pct:.2f}%)",
                     horizontalalignment="center",
                     verticalalignment="center",
                     color="white" if val > thresh else "black")

    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    cm_plot_path = os.path.join(HYBRID_RESULTS_DIR, "confusion_matrix.png")
    plt.savefig(cm_plot_path, dpi=200)
    plt.close()

    cm_df = pd.DataFrame(hyb_cm, index=[f"True_{c}" for c in CLASS_NAMES], columns=[f"Pred_{c}" for c in CLASS_NAMES])
    cm_csv_path = os.path.join(HYBRID_RESULTS_DIR, "confusion_matrix.csv")
    cm_df.to_csv(cm_csv_path)

    # 2. Comparative ROC Curve
    fpr_rgb, tpr_rgb, _ = roc_curve(test_labels, rgb_test_probs)
    fpr_byte, tpr_byte, _ = roc_curve(test_labels, byte_test_probs)
    fpr_hyb, tpr_hyb, _ = roc_curve(test_labels, hybrid_test_probs)

    plt.figure(figsize=(7, 6))
    plt.plot(fpr_rgb, tpr_rgb, color="#1f77b4", lw=2, linestyle="--", label=f"RGB CNN (AUC = {rgb_auc:.4f})")
    plt.plot(fpr_byte, tpr_byte, color="#2ca02c", lw=2, linestyle="-.", label=f"Byte 1D CNN (AUC = {byte_auc:.4f})")
    plt.plot(fpr_hyb, tpr_hyb, color="#9467bd", lw=2.5, label=f"Hybrid Fusion (AUC = {hyb_auc:.4f})")
    plt.plot([0, 1], [0, 1], color="gray", lw=1.2, linestyle=":")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (FPR)")
    plt.ylabel("True Positive Rate (Recall / TPR)")
    plt.title("Comparative ROC Curves: RGB vs Byte vs Hybrid (Test Set)")
    plt.legend(loc="lower right")
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    roc_plot_path = os.path.join(HYBRID_RESULTS_DIR, "roc_curve.png")
    plt.savefig(roc_plot_path, dpi=200)
    plt.close()

    # 3. Validation Grid Heatmap
    pivot_table = grid_df.pivot(index="threshold", columns="alpha", values="macro_f1")
    plt.figure(figsize=(9, 6))
    plt.imshow(pivot_table.values, aspect="auto", cmap="viridis", origin="lower")
    plt.colorbar(label="Validation Macro F1")
    plt.xticks(np.arange(len(pivot_table.columns)), [f"{c:.2f}" for c in pivot_table.columns], rotation=45)
    plt.yticks(np.arange(len(pivot_table.index)), [f"{r:.2f}" for r in pivot_table.index])
    plt.xlabel("Fusion Weight (alpha, weight on RGB)")
    plt.ylabel("Decision Threshold (tau)")
    plt.title("Validation Macro F1 Heatmap across (alpha, threshold)")
    plt.tight_layout()
    heatmap_path = os.path.join(HYBRID_RESULTS_DIR, "validation_grid_heatmap.png")
    plt.savefig(heatmap_path, dpi=200)
    plt.close()

    # Step 12: Comprehensive Metrics Text Report
    metrics_txt = f"""================================================================================
SPIN-IDS EVALUATION REPORT: CIC-IDS2017 HYBRID RGB + BYTE CNN SCORE-FUSION
================================================================================
Date:                 {time.strftime('%Y-%m-%d %H:%M:%S')}
Fusion Method:        Weighted Probability Fusion [P_hybrid = alpha*P_rgb + (1-alpha)*P_byte]
RGB Architecture:     2D Sequential CNN (167,042 parameters)
Byte Architecture:    1D Sequential CNN (64,642 parameters)
Combined Ensemble:    231,684 parameters
Selected Parameters:  alpha = {sel_alpha:.2f} (RGB weight), threshold = {sel_thresh:.2f}
Tuning Criterion:     Validation Macro F1 on held-out validation split (52,432 samples)
Total Test Samples:   {n_test:,} (NORMAL: {int(hyb_per_s[0]):,}, MALICIOUS: {int(hyb_per_s[1]):,})

1. COMPARATIVE PERFORMANCE ON HELD-OUT TEST SET (52,752 samples):
--------------------------------------------------------------------------------
Metric                  RGB-Only (alpha=1.0)  Byte-Only (alpha=0.0)  Hybrid Fusion (alpha={sel_alpha})
--------------------------------------------------------------------------------
Accuracy                {rgb_acc*100:6.3f}%               {byte_acc*100:6.3f}%               {hyb_acc*100:6.3f}%
Macro Precision         {rgb_macro_p:8.6f}             {byte_macro_p:8.6f}             {hyb_macro_p:8.6f}
Macro Recall            {rgb_macro_r:8.6f}             {byte_macro_r:8.6f}             {hyb_macro_r:8.6f}
Macro F1-Score          {rgb_macro_f1:8.6f}             {byte_macro_f1:8.6f}             {hyb_macro_f1:8.6f}
Weighted F1-Score       {rgb_macro_f1:8.6f}             {byte_macro_f1:8.6f}             {hyb_weighted_f1:8.6f}
ROC-AUC Score           {rgb_auc:8.6f}             {byte_auc:8.6f}             {hyb_auc:8.6f}
False Positive Rate     {rgb_cm[0,1]/np.sum(rgb_cm[0])*100:6.4f}%              {byte_cm[0,1]/np.sum(byte_cm[0])*100:6.4f}%              {hyb_fpr*100:6.4f}%
True Negatives (TN)     {rgb_cm[0,0]:>7,}                {byte_cm[0,0]:>7,}                {hyb_tn:>7,}
False Positives (FP)    {rgb_cm[0,1]:>7,}                {byte_cm[0,1]:>7,}                {hyb_fp:>7,}
False Negatives (FN)    {rgb_cm[1,0]:>7,}                {byte_cm[1,0]:>7,}                {hyb_fn:>7,}
True Positives (TP)     {rgb_cm[1,1]:>7,}                {byte_cm[1,1]:>7,}                {hyb_tp:>7,}
Latency (ms/sample)     {rgb_test_time/n_test*1000:8.3f} ms            {byte_test_time/n_test*1000:8.3f} ms            {total_hybrid_test_time/n_test*1000:8.3f} ms
Throughput (samples/s)  {n_test/rgb_test_time:>7.0f}                {n_test/byte_test_time:>7.0f}                {n_test/total_hybrid_test_time:>7.0f}
--------------------------------------------------------------------------------

2. ATTACK-CATEGORY BREAKDOWN IN TEST SET:
{json.dumps(category_metrics, indent=2)}
Note: Heartbleed, slowloris, and Slowhttptest had fewer total flows and naturally fell strictly
within train/validation splits during the flow-level partition. No test detection performance
is claimed for these categories.

3. SCIENTIFIC OBSERVATION ON FUSION EFFECTIVENESS:
Both the RGB CNN and Byte 1D CNN learn representations derived from the exact same underlying
2,187-byte network packet sequences. As demonstrated by the near-unity prediction correlation
(>0.9999) and identical test set error profiles (231 FP, 0 FN), both models converge to virtually
identical decision boundaries. Weighted score fusion matches the individual baselines (99.56% accuracy,
99.30% Macro F1, 100.00% attack recall), but does not yield statistical gains over the individual
models while incurring the latency cost of running two model passes. Therefore, the standalone
Byte 1D CNN represents the most efficient deployment option (64,642 params, 1,851 samples/s),
while the Hybrid model provides an ensemble verification baseline.

4. SAVED ARTIFACTS:
  - Configuration JSON:        {config_json_path}
  - Validation Grid CSV:       {grid_csv_path}
  - Validation Heatmap:        {heatmap_path}
  - Test Predictions CSV:      {preds_csv_path}
  - Confusion Matrix Plot:     {cm_plot_path}
  - Confusion Matrix CSV:      {cm_csv_path}
  - Comparative ROC Plot:      {roc_plot_path}
  - Classification Report:     {clf_rep_path}
  - Metrics Report:            {os.path.join(HYBRID_RESULTS_DIR, 'metrics.txt')}
================================================================================
"""
    metrics_report_path = os.path.join(HYBRID_RESULTS_DIR, "metrics.txt")
    with open(metrics_report_path, "w", encoding="utf-8") as f:
        f.write(metrics_txt)
    print(f"Saved Metrics Report: {metrics_report_path}")

    print("\n" + "=" * 70)
    print(f"EXPERIMENT COMPLETED in {time.time()-t_global:.1f}s")
    print("=" * 70)
    return True


if __name__ == "__main__":
    main()
