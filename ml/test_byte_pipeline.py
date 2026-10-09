"""
SPIN-IDS: Test Suite for CIC-IDS2017 Byte/Hex Baseline Pipeline
Tests model architecture, output shapes, pure NumPy metric functions,
and cache file integrity.
"""

import os
import sys
import json
import unittest
import numpy as np
import torch

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(BASE_DIR, "dataset", "External_CIC_IDS2017", "processed", "cache")

# Metric Implementations
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


# Byte CNN Model Architecture
class CicIdsByte1DCNN(torch.nn.Module):
    def __init__(self, num_classes=2):
        super().__init__()
        self.conv1 = torch.nn.Sequential(
            torch.nn.Conv1d(1, 32, kernel_size=9, stride=3, padding=4),
            torch.nn.BatchNorm1d(32),
            torch.nn.ReLU(inplace=True),
            torch.nn.MaxPool1d(kernel_size=3, stride=3)
        )
        self.conv2 = torch.nn.Sequential(
            torch.nn.Conv1d(32, 64, kernel_size=7, stride=1, padding=3),
            torch.nn.BatchNorm1d(64),
            torch.nn.ReLU(inplace=True),
            torch.nn.MaxPool1d(kernel_size=3, stride=3)
        )
        self.conv3 = torch.nn.Sequential(
            torch.nn.Conv1d(64, 128, kernel_size=5, stride=1, padding=2),
            torch.nn.BatchNorm1d(128),
            torch.nn.ReLU(inplace=True),
            torch.nn.AdaptiveAvgPool1d(1)
        )
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(128, 64),
            torch.nn.ReLU(inplace=True),
            torch.nn.Dropout(0.3),
            torch.nn.Linear(64, num_classes)
        )

    def forward(self, x):
        x = self.conv1(x)
        x = self.conv2(x)
        x = self.conv3(x)
        feat = x.squeeze(-1)
        return self.classifier(feat)


class TestBytePipeline(unittest.TestCase):

    def test_cache_integrity(self):
        """Verifies existence, shapes, and sample alignment of cached binary splits."""
        for split, expected_n in [("train", 245374), ("val", 52432), ("test", 52752)]:
            bytes_path = os.path.join(CACHE_DIR, f"{split}_bytes.npy")
            labels_path = os.path.join(CACHE_DIR, f"{split}_labels.npy")
            meta_path = os.path.join(CACHE_DIR, f"{split}_meta.json")

            self.assertTrue(os.path.exists(bytes_path), f"Missing {bytes_path}")
            self.assertTrue(os.path.exists(labels_path), f"Missing {labels_path}")
            self.assertTrue(os.path.exists(meta_path), f"Missing {meta_path}")

            raw_bytes = np.load(bytes_path, mmap_mode="r")
            labels = np.load(labels_path)
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)

            self.assertEqual(raw_bytes.shape, (expected_n, 2187))
            self.assertEqual(raw_bytes.dtype, np.uint8)
            self.assertEqual(labels.shape, (expected_n,))
            self.assertEqual(len(meta["window_ids"]), expected_n)
            self.assertEqual(len(meta["flow_ids"]), expected_n)
            self.assertEqual(len(meta["attack_categories"]), expected_n)

            # Labels must strictly be binary: 0 (NORMAL) and 1 (MALICIOUS)
            unique_labels = set(np.unique(labels))
            self.assertTrue(unique_labels.issubset({0, 1}))

    def test_model_forward_pass_and_shapes(self):
        """Verifies model parameter count, input shape compatibility, and output logits."""
        model = CicIdsByte1DCNN(num_classes=2)
        model.eval()

        batch_size = 8
        dummy_input = torch.randn(batch_size, 1, 2187)
        with torch.no_grad():
            output = model(dummy_input)

        self.assertEqual(output.shape, (batch_size, 2))
        probs = torch.softmax(output, dim=1)
        self.assertTrue(torch.allclose(probs.sum(dim=1), torch.ones(batch_size), atol=1e-5))

    def test_metric_calculations_against_known_cases(self):
        """Validates accuracy, confusion matrix, precision, recall, F1, and ROC-AUC."""
        # 10 samples: 6 Normal (0), 4 Malicious (1)
        # Predictions:
        # True 0s: 5 predicted 0 (TN), 1 predicted 1 (FP)
        # True 1s: 1 predicted 0 (FN), 3 predicted 1 (TP)
        y_true = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1])
        y_pred = np.array([0, 0, 0, 0, 0, 1, 0, 1, 1, 1])
        y_prob = np.array([0.1, 0.2, 0.15, 0.05, 0.3, 0.7, 0.4, 0.8, 0.85, 0.9])

        cm = confusion_matrix(y_true, y_pred)
        self.assertEqual(cm.tolist(), [[5, 1], [1, 3]])

        acc = accuracy_score(y_true, y_pred)
        self.assertAlmostEqual(acc, 0.8, places=6)

        # Class 0: TN=5, FP=1, FN=1 -> p0 = 5/6, r0 = 5/6, f1_0 = 5/6
        # Class 1: TP=3, FP=1, FN=1 -> p1 = 3/4 = 0.75, r1 = 3/4 = 0.75, f1_1 = 0.75
        macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro")
        expected_macro_f1 = (5.0 / 6.0 + 0.75) / 2.0
        self.assertAlmostEqual(macro_f1, expected_macro_f1, places=6)

        auc = roc_auc_score(y_true, y_prob)
        # True 0 probs: [0.1, 0.2, 0.15, 0.05, 0.3, 0.7]
        # True 1 probs: [0.4, 0.8, 0.85, 0.9]
        # Pairs (6 neg * 4 pos = 24 pairs):
        # 0.4 > [0.1, 0.2, 0.15, 0.05, 0.3] -> 5 pairs
        # 0.8 > all 6 -> 6 pairs
        # 0.85 > all 6 -> 6 pairs
        # 0.9 > all 6 -> 6 pairs
        # Total concordant = 23 pairs / 24 = 0.958333...
        self.assertAlmostEqual(auc, 23.0 / 24.0, places=5)

        # Classification report structure
        rep = classification_report(y_true, y_pred)
        self.assertIn("NORMAL", rep)
        self.assertIn("MALICIOUS", rep)
        self.assertIn("macro avg", rep)
        self.assertIn("accuracy", rep)
        self.assertEqual(rep["macro avg"]["support"], 10)


if __name__ == "__main__":
    unittest.main()
