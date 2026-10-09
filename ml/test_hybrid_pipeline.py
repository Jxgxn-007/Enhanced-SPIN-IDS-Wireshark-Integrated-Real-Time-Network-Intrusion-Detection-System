"""
SPIN-IDS: Test Suite for Hybrid RGB + Byte Score-Fusion Pipeline
Tests probability alignment by stable window IDs, weighted fusion calculations,
class mappings, decision thresholding, and model checkpoint loading.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RGB_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "cic_ids2017_rgb", "best_rgb_cnn.pt")
BYTE_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "cic_ids2017_byte", "best_byte_cnn.pt")

CLASS_NAMES = ["NORMAL", "MALICIOUS"]


# Model Definitions
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


def fuse_probabilities(rgb_prob, byte_prob, alpha=0.5):
    """Computes weighted probability score fusion."""
    rgb_p = np.asarray(rgb_prob, dtype=np.float64)
    byte_p = np.asarray(byte_prob, dtype=np.float64)
    if not (0.0 <= alpha <= 1.0):
        raise ValueError(f"Alpha must be in [0.0, 1.0], got {alpha}")
    return alpha * rgb_p + (1.0 - alpha) * byte_p


def apply_decision_threshold(probs, threshold=0.5):
    """Applies decision threshold to probability scores."""
    p = np.asarray(probs, dtype=np.float64)
    return (p >= threshold).astype(np.int64)


def map_pred_to_class(pred_ids):
    """Maps binary numeric predictions (0, 1) to string class labels."""
    return [CLASS_NAMES[i] for i in pred_ids]


def align_predictions_by_window_id(df1, df2, id_col="window_id"):
    """
    Safely joins and aligns predictions by stable window_id.
    Guarantees 1-to-1 row alignment even if CSV rows were originally reordered.
    """
    merged = pd.merge(df1, df2, on=id_col, suffixes=("_rgb", "_byte"), how="inner")
    if len(merged) != len(df1) or len(merged) != len(df2):
        raise ValueError(f"Window ID alignment mismatch: df1={len(df1)}, df2={len(df2)}, merged={len(merged)}")
    return merged


class TestHybridPipeline(unittest.TestCase):

    def test_fusion_calculation(self):
        """Verifies weighted probability fusion across extreme and intermediate alphas."""
        p_rgb = np.array([0.9, 0.1, 0.5])
        p_byte = np.array([0.7, 0.3, 0.5])

        # Alpha = 0.5 (equal weight)
        f_mid = fuse_probabilities(p_rgb, p_byte, alpha=0.5)
        np.testing.assert_allclose(f_mid, [0.8, 0.2, 0.5], atol=1e-6)

        # Alpha = 1.0 (RGB only)
        f_rgb = fuse_probabilities(p_rgb, p_byte, alpha=1.0)
        np.testing.assert_allclose(f_rgb, p_rgb, atol=1e-6)

        # Alpha = 0.0 (Byte only)
        f_byte = fuse_probabilities(p_rgb, p_byte, alpha=0.0)
        np.testing.assert_allclose(f_byte, p_byte, atol=1e-6)

        # Alpha = 0.25 (75% Byte, 25% RGB)
        f_quarter = fuse_probabilities(p_rgb, p_byte, alpha=0.25)
        expected = 0.25 * p_rgb + 0.75 * p_byte
        np.testing.assert_allclose(f_quarter, expected, atol=1e-6)

        # Invalid alpha
        with self.assertRaises(ValueError):
            fuse_probabilities(p_rgb, p_byte, alpha=-0.1)
        with self.assertRaises(ValueError):
            fuse_probabilities(p_rgb, p_byte, alpha=1.5)

    def test_threshold_handling(self):
        """Verifies binary decision thresholding and edge boundaries."""
        probs = np.array([0.0, 0.499, 0.5, 0.501, 1.0])
        preds_default = apply_decision_threshold(probs, threshold=0.5)
        np.testing.assert_array_equal(preds_default, [0, 0, 1, 1, 1])

        preds_high = apply_decision_threshold(probs, threshold=0.6)
        np.testing.assert_array_equal(preds_high, [0, 0, 0, 0, 1])

        preds_low = apply_decision_threshold(probs, threshold=0.4)
        np.testing.assert_array_equal(preds_low, [0, 1, 1, 1, 1])

    def test_class_mapping(self):
        """Verifies mapping between binary integers and class labels."""
        self.assertEqual(map_pred_to_class([0, 1, 0]), ["NORMAL", "MALICIOUS", "NORMAL"])
        self.assertEqual(CLASS_NAMES[0], "NORMAL")
        self.assertEqual(CLASS_NAMES[1], "MALICIOUS")

    def test_probability_alignment_by_window_id(self):
        """Verifies that alignment by window_id preserves integrity even when shuffled."""
        df_rgb = pd.DataFrame({
            "window_id": ["win_001", "win_002", "win_003"],
            "prob_malicious": [0.1, 0.8, 0.4],
            "true_label": ["NORMAL", "MALICIOUS", "NORMAL"]
        })
        # Shuffled order in df_byte
        df_byte = pd.DataFrame({
            "window_id": ["win_003", "win_001", "win_002"],
            "prob_malicious": [0.45, 0.12, 0.85],
            "true_label": ["NORMAL", "NORMAL", "MALICIOUS"]
        })

        aligned = align_predictions_by_window_id(df_rgb, df_byte)
        self.assertEqual(len(aligned), 3)
        self.assertEqual(aligned["window_id"].tolist(), ["win_001", "win_002", "win_003"])
        self.assertEqual(aligned["prob_malicious_rgb"].tolist(), [0.1, 0.8, 0.4])
        self.assertEqual(aligned["prob_malicious_byte"].tolist(), [0.12, 0.85, 0.45])

    def test_model_checkpoints_exist_and_load(self):
        """Verifies that both trained baseline checkpoints exist and load properly."""
        self.assertTrue(os.path.exists(RGB_MODEL_PATH), f"Missing {RGB_MODEL_PATH}")
        self.assertTrue(os.path.exists(BYTE_MODEL_PATH), f"Missing {BYTE_MODEL_PATH}")

        rgb_model = CicIdsRgbCnn()
        rgb_model.load_state_dict(torch.load(RGB_MODEL_PATH))
        rgb_model.eval()

        byte_model = CicIdsByte1DCNN()
        byte_model.load_state_dict(torch.load(BYTE_MODEL_PATH))
        byte_model.eval()

        # Test forward pass through both models with sample input
        dummy_rgb = torch.randn(2, 3, 27, 27)
        dummy_byte = torch.randn(2, 1, 2187)

        with torch.no_grad():
            out_rgb = rgb_model(dummy_rgb)
            out_byte = byte_model(dummy_byte)

        self.assertEqual(out_rgb.shape, (2, 2))
        self.assertEqual(out_byte.shape, (2, 2))


if __name__ == "__main__":
    unittest.main()
