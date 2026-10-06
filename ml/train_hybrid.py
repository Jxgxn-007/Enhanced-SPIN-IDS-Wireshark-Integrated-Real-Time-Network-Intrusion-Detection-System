"""
================================================================================
SPIN-IDS HYBRID RGB + BYTE/HEX ANALYSIS TRAINING PIPELINE
================================================================================

Architecture Overview:
                    9-PACKET WINDOW
                           |
              +------------+------------+
              |                         |
              v                         v
       RGB representation          Raw byte values
              |                         |
              v                         v
          RGB CNN                 Byte/Hex model
              |                         |
              v                         v
       RGB malicious score       Byte malicious score
              |                         |
              +------------+------------+
                           |
                           v
                     Score Fusion
                           |
                           v
                  Final malicious score
                           |
                    +------+------+
                    |             |
                  NORMAL       MALICIOUS

IMPORTANT RESEARCH & DATASET NOTES:
- MALICIOUS_SYNTHETIC represents controlled, synthetic anomalous byte patterns
  generated specifically for validating multi-modal fusion pipelines in SPIN-IDS.
- It is NOT real-world exploit traffic or benchmark attack suites (e.g. CIC-IDS2017).
- This experiment evaluates whether combining 2D spatial packet layout (RGB CNN)
  with 1D global byte statistics (MLP) improves anomaly classification robustness.
================================================================================
"""

import os
import sys
import time
from pathlib import Path

# Ensure PyTorch backend for Keras 3
os.environ["KERAS_BACKEND"] = "torch"
os.environ["PYTHONIOENCODING"] = "utf-8"

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import torch
import keras
from keras import layers

# ==============================================================================
# 1. CONFIGURABLE CONSTANTS & SEED SETUP
# ==============================================================================
SEED = 42
np.random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)
keras.utils.set_random_seed(SEED)

# Score fusion weights (can be adjusted for experimental tuning)
WEIGHT_RGB = 0.70
WEIGHT_BYTE = 0.30
DECISION_THRESHOLD = 0.50

# Class naming convention
CLASS_NAMES = ["NORMAL", "MALICIOUS"]

# Label mapping for dataset
# MALICIOUS_SYNTHETIC represents controlled synthetic anomalous patterns.
LABEL_MAP = {
    "NORMAL": 0,
    "MALICIOUS_SYNTHETIC": 1,
    "MALICIOUS": 1
}


# ==============================================================================
# 2. PATH RESOLUTION HELPERS
# ==============================================================================
def get_project_root() -> Path:
    """Resolves the root directory of the SPIN-IDS project."""
    current = Path(__file__).resolve().parent
    if current.name == "ml":
        return current.parent
    return current


# ==============================================================================
# 3. FEATURE EXTRACTION & DATA LOADING
# ==============================================================================
def extract_byte_statistical_features(byte_matrix: np.ndarray):
    """
    Derives 9 byte-level statistical features from raw byte values (N, 2187):
      1. mean_byte          : Mean byte value
      2. std_byte           : Standard deviation of byte values
      3. min_byte           : Minimum byte value observed
      4. max_byte           : Maximum byte value observed
      5. unique_byte_count  : Number of distinct byte symbols present
      6. byte_entropy       : Shannon entropy in bits (base 2)
      7. zero_ratio         : Fraction of null bytes (0x00)
      8. ff_ratio           : Fraction of 0xFF bytes
      9. high_byte_ratio    : Fraction of high-order bytes (>= 128)
    """
    byte_matrix = np.asarray(byte_matrix, dtype=np.uint8)
    n_samples, n_bytes = byte_matrix.shape

    means = np.mean(byte_matrix, axis=1)
    stds = np.std(byte_matrix, axis=1)
    mins = np.min(byte_matrix, axis=1)
    maxs = np.max(byte_matrix, axis=1)
    zero_ratios = np.mean(byte_matrix == 0, axis=1)
    ff_ratios = np.mean(byte_matrix == 255, axis=1)
    high_byte_ratios = np.mean(byte_matrix >= 128, axis=1)

    unique_counts = np.empty(n_samples, dtype=np.float32)
    entropies = np.empty(n_samples, dtype=np.float32)

    for i in range(n_samples):
        row = byte_matrix[i]
        counts = np.bincount(row, minlength=256)
        unique_counts[i] = np.count_nonzero(counts)
        probs = counts[counts > 0] / float(n_bytes)
        entropies[i] = -np.sum(probs * np.log2(probs))

    features = np.column_stack([
        means,
        stds,
        mins,
        maxs,
        unique_counts,
        entropies,
        zero_ratios,
        ff_ratios,
        high_byte_ratios
    ]).astype(np.float32)

    feature_names = [
        "mean_byte",
        "std_byte",
        "min_byte",
        "max_byte",
        "unique_byte_count",
        "byte_entropy",
        "zero_ratio",
        "ff_ratio",
        "high_byte_ratio"
    ]
    return features, feature_names


class FeatureStandardScaler:
    """Standardizes feature columns to zero mean and unit variance."""
    def __init__(self):
        self.mean_ = None
        self.scale_ = None

    def fit(self, X: np.ndarray):
        X = np.asarray(X, dtype=np.float32)
        self.mean_ = np.mean(X, axis=0)
        self.scale_ = np.std(X, axis=0)
        # Avoid division by zero for constant features
        self.scale_[self.scale_ == 0.0] = 1.0
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float32)
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)


def load_dataset_split(csv_path: Path):
    """
    Loads dataset split from CSV and extracts:
      - Window identifiers
      - Labels (mapped to 0=NORMAL, 1=MALICIOUS)
      - RGB image representation (N, 27, 27, 3) normalized to [0, 1]
      - Byte statistical features (N, 9)
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset split file not found: {csv_path}")

    print(f"Loading {csv_path.name} from {csv_path.parent}...")
    df = pd.read_csv(csv_path)

    # 1. Extract window IDs and labels
    window_ids = df["window_id"].tolist()
    raw_labels = df["label"].tolist()
    labels = np.array([LABEL_MAP.get(l, 1) for l in raw_labels], dtype=np.int64)

    # 2. Identify the 2187 byte columns (b0000 ... b2186)
    byte_cols = [f"b{i:04d}" for i in range(2187)]
    missing_cols = [col for col in byte_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"CSV {csv_path.name} is missing {len(missing_cols)} byte columns!")

    raw_bytes = df[byte_cols].to_numpy(dtype=np.uint8)

    # 3. Convert every 2187-byte sample into shape (27, 27, 3) normalized to [0, 1]
    # 2187 bytes = 27 x 27 x 3 channels
    rgb_images = (raw_bytes.reshape(-1, 27, 27, 3).astype(np.float32)) / 255.0

    # 4. Extract byte-level statistical features
    byte_features, feature_names = extract_byte_statistical_features(raw_bytes)

    return {
        "window_ids": window_ids,
        "labels": labels,
        "rgb_images": rgb_images,
        "byte_features": byte_features,
        "feature_names": feature_names,
        "raw_labels": raw_labels
    }


# ==============================================================================
# 4. MODEL BUILDERS
# ==============================================================================
def build_rgb_cnn_model(input_shape=(27, 27, 3), num_classes=2):
    """
    Lightweight 2D CNN matching existing ml/train.py architecture:
      - Conv2D 32, 3x3, ReLU, same
      - MaxPooling2D 2x2
      - Conv2D 64, 3x3, ReLU, same
      - MaxPooling2D 2x2
      - Flatten
      - Dense 64 ReLU
      - Dropout 0.3
      - Dense 2 softmax
      - Adam lr=0.001, sparse categorical crossentropy
    """
    model = keras.Sequential([
        layers.Input(shape=input_shape, name="rgb_input"),
        layers.Conv2D(32, (3, 3), activation="relu", padding="same", name="conv2d_1"),
        layers.MaxPooling2D((2, 2), name="maxpool_1"),
        layers.Conv2D(64, (3, 3), activation="relu", padding="same", name="conv2d_2"),
        layers.MaxPooling2D((2, 2), name="maxpool_2"),
        layers.Flatten(name="flatten"),
        layers.Dense(64, activation="relu", name="dense_1"),
        layers.Dropout(0.3, name="dropout"),
        layers.Dense(num_classes, activation="softmax", name="output_softmax")
    ], name="spin_ids_rgb_cnn")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model


def build_byte_mlp_model(input_dim=9, num_classes=2):
    """
    Small MLP architecture for byte-level statistical features:
      - Dense 64 ReLU
      - Dropout 0.2
      - Dense 32 ReLU
      - Dense 2 softmax
      - Adam lr=0.001, sparse categorical crossentropy
    """
    model = keras.Sequential([
        layers.Input(shape=(input_dim,), name="byte_features_input"),
        layers.Dense(64, activation="relu", name="mlp_dense_1"),
        layers.Dropout(0.2, name="mlp_dropout_1"),
        layers.Dense(32, activation="relu", name="mlp_dense_2"),
        layers.Dense(num_classes, activation="softmax", name="mlp_output_softmax")
    ], name="spin_ids_byte_mlp")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model


# ==============================================================================
# 5. METRICS COMPUTATION & PLOTTING HELPERS
# ==============================================================================
def evaluate_predictions(y_true: np.ndarray, y_pred: np.ndarray):
    """
    Computes accuracy, precision, recall, f1, and confusion matrix.
    Pure NumPy implementation for robust execution and exact parity with sklearn.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    total = len(y_true)

    # Confusion matrix:
    # row 0 = Actual Normal, row 1 = Actual Malicious
    # col 0 = Pred Normal,   col 1 = Pred Malicious
    cm = np.zeros((2, 2), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1

    tn, fp = cm[0, 0], cm[0, 1]
    fn, tp = cm[1, 0], cm[1, 1]

    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "confusion_matrix": cm,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "total": int(total)
    }


def format_classification_report(y_true: np.ndarray, y_pred: np.ndarray, class_names=CLASS_NAMES) -> str:
    """Formats a detailed classification report string."""
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)

    lines = [f"{'':>20}  precision    recall  f1-score   support\n"]
    prec_list, rec_list, f1_list, sup_list = [], [], [], []

    for cls_idx, name in enumerate(class_names):
        tp = np.sum((y_true == cls_idx) & (y_pred == cls_idx))
        fp = np.sum((y_true != cls_idx) & (y_pred == cls_idx))
        fn = np.sum((y_true == cls_idx) & (y_pred != cls_idx))
        support = np.sum(y_true == cls_idx)

        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0

        prec_list.append(p)
        rec_list.append(r)
        f1_list.append(f)
        sup_list.append(support)

        lines.append(f"{name:>20}     {p:.4f}    {r:.4f}    {f:.4f}       {support:>4}\n")

    total_sup = np.sum(sup_list)
    macro_p = np.mean(prec_list)
    macro_r = np.mean(rec_list)
    macro_f = np.mean(f1_list)

    weight_p = np.sum(np.array(prec_list) * np.array(sup_list)) / total_sup if total_sup > 0 else 0.0
    weight_r = np.sum(np.array(rec_list) * np.array(sup_list)) / total_sup if total_sup > 0 else 0.0
    weight_f = np.sum(np.array(f1_list) * np.array(sup_list)) / total_sup if total_sup > 0 else 0.0

    acc = np.mean(y_true == y_pred)
    lines.append("\n")
    lines.append(f"{'accuracy':>20}                         {acc:.4f}       {total_sup:>4}\n")
    lines.append(f"{'macro avg':>20}     {macro_p:.4f}    {macro_r:.4f}    {macro_f:.4f}       {total_sup:>4}\n")
    lines.append(f"{'weighted avg':>20}     {weight_p:.4f}    {weight_r:.4f}    {weight_f:.4f}       {total_sup:>4}\n")
    return "".join(lines)


def plot_and_save_confusion_matrix(cm: np.ndarray, title: str, save_path: Path):
    """Renders and saves a confusion matrix heatmap image."""
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(
        xticks=np.arange(cm.shape[1]),
        yticks=np.arange(cm.shape[0]),
        xticklabels=CLASS_NAMES,
        yticklabels=CLASS_NAMES,
        title=title,
        ylabel="True Label",
        xlabel="Predicted Label"
    )

    thresh = cm.max() / 2.0 if cm.max() > 0 else 1.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontweight="bold", fontsize=12
            )

    plt.tight_layout()
    plt.savefig(save_path, dpi=200)
    plt.close()


def save_metrics_text_file(save_path: Path, title: str, model_desc: str, metrics: dict, y_true: np.ndarray, y_pred: np.ndarray):
    """Writes detailed evaluation metrics report to text file."""
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(f"SPIN-IDS EVALUATION REPORT: {title}\n")
        f.write("=" * 60 + "\n")
        f.write(f"Model Type               : {model_desc}\n")
        f.write(f"Total Test Samples       : {metrics['total']}\n")
        f.write(f"Accuracy                 : {metrics['accuracy']:.6f} ({metrics['accuracy'] * 100:.2f}%)\n")
        f.write(f"Precision                : {metrics['precision']:.6f}\n")
        f.write(f"Recall                   : {metrics['recall']:.6f}\n")
        f.write(f"F1-Score                 : {metrics['f1']:.6f}\n\n")
        f.write("Confusion Matrix:\n")
        f.write(f"  TN = {metrics['tn']} (Normal correctly classified)\n")
        f.write(f"  FP = {metrics['fp']} (Normal misclassified as Malicious)\n")
        f.write(f"  FN = {metrics['fn']} (Malicious misclassified as Normal)\n")
        f.write(f"  TP = {metrics['tp']} (Malicious correctly classified)\n\n")
        f.write("Classification Report:\n")
        f.write(format_classification_report(y_true, y_pred))


# ==============================================================================
# 6. MAIN HYBRID TRAINING & EVALUATION PIPELINE
# ==============================================================================
def main():
    start_time = time.time()
    project_root = get_project_root()
    dataset_dir = project_root / "dataset" / "Synthetic"

    results_dir = project_root / "ml" / "results" / "hybrid"
    models_dir = project_root / "ml" / "models" / "hybrid"
    results_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("SPIN-IDS HYBRID RGB + BYTE/HEX ANALYSIS EXPERIMENT")
    print("=" * 70)
    print("Keras Version        :", keras.__version__)
    print("Keras Backend        :", keras.backend.backend())
    print("PyTorch Version      :", torch.__version__)
    print("Random Seed          :", SEED)
    print(f"Fusion Weights       : RGB = {WEIGHT_RGB:.2f}, BYTE = {WEIGHT_BYTE:.2f}")
    print(f"Decision Threshold   : {DECISION_THRESHOLD:.2f}")
    print("Target Models Dir    :", models_dir)
    print("Target Results Dir   :", results_dir)
    print("=" * 70)
    print()

    # --------------------------------------------------------------------------
    # Step 1: Load Datasets
    # --------------------------------------------------------------------------
    train_data = load_dataset_split(dataset_dir / "train.csv")
    val_data = load_dataset_split(dataset_dir / "val.csv")
    test_data = load_dataset_split(dataset_dir / "test.csv")

    y_train = train_data["labels"]
    y_val = val_data["labels"]
    y_test = test_data["labels"]

    print("\n--------------------------------------------------")
    print("Dataset Distribution Summary:")
    print("--------------------------------------------------")
    print(f"Train Set      : Total={len(y_train)}, NORMAL={np.sum(y_train == 0)}, MALICIOUS={np.sum(y_train == 1)}")
    print(f"Validation Set : Total={len(y_val)}, NORMAL={np.sum(y_val == 0)}, MALICIOUS={np.sum(y_val == 1)}")
    print(f"Test Set       : Total={len(y_test)}, NORMAL={np.sum(y_test == 0)}, MALICIOUS={np.sum(y_test == 1)}")
    print(f"RGB Tensor Shape: {train_data['rgb_images'].shape[1:]} (H, W, C)")
    print(f"Byte Features Dim: {train_data['byte_features'].shape[1]} features: {train_data['feature_names']}")
    print("--------------------------------------------------\n")

    # --------------------------------------------------------------------------
    # Step 2: Prepare Feature Scaler for Byte Statistical Features
    # --------------------------------------------------------------------------
    # IMPORTANT: Fit scaler ONLY on training data, then transform val & test
    scaler = FeatureStandardScaler()
    x_byte_train = scaler.fit_transform(train_data["byte_features"])
    x_byte_val = scaler.transform(val_data["byte_features"])
    x_byte_test = scaler.transform(test_data["byte_features"])

    x_rgb_train = train_data["rgb_images"]
    x_rgb_val = val_data["rgb_images"]
    x_rgb_test = test_data["rgb_images"]

    # --------------------------------------------------------------------------
    # Step 3: Train Model A - RGB CNN
    # --------------------------------------------------------------------------
    print("\n" + "#" * 60)
    print("TRAINING MODEL 1: RGB CNN (27x27x3 Spatial Packet Image)")
    print("#" * 60)

    rgb_model = build_rgb_cnn_model(input_shape=(27, 27, 3), num_classes=2)
    rgb_model.summary()

    rgb_model_path = models_dir / "spin_ids_rgb_hybrid.keras"
    rgb_callbacks = [
        keras.callbacks.ModelCheckpoint(
            filepath=str(rgb_model_path),
            monitor="val_loss",
            save_best_only=True,
            verbose=1
        ),
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=8,
            restore_best_weights=True,
            verbose=1
        )
    ]

    rgb_batch_size = 32
    rgb_max_epochs = 25
    print(f"\nStarting RGB CNN training (max_epochs={rgb_max_epochs}, batch_size={rgb_batch_size})...")
    rgb_history = rgb_model.fit(
        x_rgb_train, y_train,
        validation_data=(x_rgb_val, y_val),
        epochs=rgb_max_epochs,
        batch_size=rgb_batch_size,
        callbacks=rgb_callbacks,
        verbose=1
    )
    print(f"RGB CNN training complete. Best model saved to: {rgb_model_path}")

    # --------------------------------------------------------------------------
    # Step 4: Train Model B - Byte/Hex Statistical MLP
    # --------------------------------------------------------------------------
    print("\n" + "#" * 60)
    print("TRAINING MODEL 2: BYTE/HEX MLP (9 Statistical Byte Features)")
    print("#" * 60)

    byte_model = build_byte_mlp_model(input_dim=9, num_classes=2)
    byte_model.summary()

    byte_model_path = models_dir / "spin_ids_byte_model.keras"
    byte_callbacks = [
        keras.callbacks.ModelCheckpoint(
            filepath=str(byte_model_path),
            monitor="val_loss",
            save_best_only=True,
            verbose=1
        ),
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=8,
            restore_best_weights=True,
            verbose=1
        )
    ]

    byte_batch_size = 32
    byte_max_epochs = 25
    print(f"\nStarting Byte MLP training (max_epochs={byte_max_epochs}, batch_size={byte_batch_size})...")
    byte_history = byte_model.fit(
        x_byte_train, y_train,
        validation_data=(x_byte_val, y_val),
        epochs=byte_max_epochs,
        batch_size=byte_batch_size,
        callbacks=byte_callbacks,
        verbose=1
    )
    print(f"Byte MLP training complete. Best model saved to: {byte_model_path}")

    # --------------------------------------------------------------------------
    # Step 5: Test Set Evaluation - Separate Models
    # --------------------------------------------------------------------------
    print("\n" + "#" * 60)
    print("EVALUATING MODELS ON TEST SET (300 SAMPLES)")
    print("#" * 60)

    # 5.1 RGB Predictions
    rgb_probs = rgb_model.predict(x_rgb_test, batch_size=rgb_batch_size, verbose=0)
    rgb_preds = np.argmax(rgb_probs, axis=1)
    rgb_metrics = evaluate_predictions(y_test, rgb_preds)

    # 5.2 Byte Predictions
    byte_probs = byte_model.predict(x_byte_test, batch_size=byte_batch_size, verbose=0)
    byte_preds = np.argmax(byte_probs, axis=1)
    byte_metrics = evaluate_predictions(y_test, byte_preds)

    # --------------------------------------------------------------------------
    # Step 6: Score Fusion (Hybrid Model)
    # --------------------------------------------------------------------------
    # Malicious probability is class index 1 (softmax output)
    rgb_malicious_prob = rgb_probs[:, 1]
    byte_malicious_prob = byte_probs[:, 1]

    # Weighted Score Fusion
    final_malicious_score = (WEIGHT_RGB * rgb_malicious_prob) + (WEIGHT_BYTE * byte_malicious_prob)

    # Final Decision Rule
    hybrid_preds = np.where(final_malicious_score >= DECISION_THRESHOLD, 1, 0)
    hybrid_metrics = evaluate_predictions(y_test, hybrid_preds)

    # --------------------------------------------------------------------------
    # Step 7: Save All Evaluation Artifacts
    # --------------------------------------------------------------------------
    print("\nSaving evaluation artifacts to:", results_dir)

    # 7.1 Metrics Text Reports
    save_metrics_text_file(
        results_dir / "rgb_metrics.txt",
        "RGB CNN Model (27x27x3)",
        "2D Sequential CNN with Conv2D(32)-MaxPool-Conv2D(64)-MaxPool-Dense(64)-Dropout(0.3)-Softmax(2)",
        rgb_metrics, y_test, rgb_preds
    )

    save_metrics_text_file(
        results_dir / "byte_metrics.txt",
        "Byte/Hex MLP Model (9 Statistical Features)",
        "Sequential MLP with Dense(64, ReLU)-Dropout(0.2)-Dense(32, ReLU)-Softmax(2)",
        byte_metrics, y_test, byte_preds
    )

    save_metrics_text_file(
        results_dir / "hybrid_metrics.txt",
        f"Hybrid Score Fusion Model ({WEIGHT_RGB:.2f} RGB + {WEIGHT_BYTE:.2f} BYTE)",
        f"Weighted ensemble: {WEIGHT_RGB:.2f}*P(malicious|RGB) + {WEIGHT_BYTE:.2f}*P(malicious|BYTE) >= {DECISION_THRESHOLD:.2f}",
        hybrid_metrics, y_test, hybrid_preds
    )

    # 7.2 Confusion Matrix CSVs
    cm_index = ["Actual_NORMAL", "Actual_MALICIOUS"]
    cm_columns = ["Predicted_NORMAL", "Predicted_MALICIOUS"]

    pd.DataFrame(rgb_metrics["confusion_matrix"], index=cm_index, columns=cm_columns).to_csv(
        results_dir / "rgb_confusion_matrix.csv"
    )
    pd.DataFrame(byte_metrics["confusion_matrix"], index=cm_index, columns=cm_columns).to_csv(
        results_dir / "byte_confusion_matrix.csv"
    )
    pd.DataFrame(hybrid_metrics["confusion_matrix"], index=cm_index, columns=cm_columns).to_csv(
        results_dir / "hybrid_confusion_matrix.csv"
    )

    # 7.3 Confusion Matrix PNG Heatmaps
    plot_and_save_confusion_matrix(
        rgb_metrics["confusion_matrix"],
        "SPIN-IDS: RGB CNN Confusion Matrix",
        results_dir / "rgb_confusion_matrix.png"
    )
    plot_and_save_confusion_matrix(
        byte_metrics["confusion_matrix"],
        "SPIN-IDS: Byte/Hex MLP Confusion Matrix",
        results_dir / "byte_confusion_matrix.png"
    )
    plot_and_save_confusion_matrix(
        hybrid_metrics["confusion_matrix"],
        f"SPIN-IDS: Hybrid (RGB {int(WEIGHT_RGB*100)}% + Byte {int(WEIGHT_BYTE*100)}%) Confusion Matrix",
        results_dir / "hybrid_confusion_matrix.png"
    )

    # 7.4 Prediction CSVs
    test_wids = test_data["window_ids"]

    # rgb_predictions.csv
    rgb_df = pd.DataFrame({
        "window_id": test_wids,
        "true_label": [CLASS_NAMES[y] for y in y_test],
        "predicted_label": [CLASS_NAMES[p] for p in rgb_preds],
        "prob_normal": rgb_probs[:, 0],
        "prob_malicious": rgb_probs[:, 1],
        "correct": (y_test == rgb_preds)
    })
    rgb_df.to_csv(results_dir / "rgb_predictions.csv", index=False)

    # byte_predictions.csv
    byte_df = pd.DataFrame({
        "window_id": test_wids,
        "true_label": [CLASS_NAMES[y] for y in y_test],
        "predicted_label": [CLASS_NAMES[p] for p in byte_preds],
        "prob_normal": byte_probs[:, 0],
        "prob_malicious": byte_probs[:, 1],
        "correct": (y_test == byte_preds)
    })
    byte_df.to_csv(results_dir / "byte_predictions.csv", index=False)

    # hybrid_predictions.csv
    hybrid_df = pd.DataFrame({
        "window_id": test_wids,
        "true_label": [CLASS_NAMES[y] for y in y_test],
        "predicted_label": [CLASS_NAMES[p] for p in hybrid_preds],
        "rgb_prob_malicious": rgb_malicious_prob,
        "byte_prob_malicious": byte_malicious_prob,
        "final_malicious_score": final_malicious_score,
        "correct": (y_test == hybrid_preds)
    })
    hybrid_df.to_csv(results_dir / "hybrid_predictions.csv", index=False)

    # 7.5 Comparison CSV
    comparison_df = pd.DataFrame([
        {
            "model": "RGB",
            "accuracy": rgb_metrics["accuracy"],
            "precision": rgb_metrics["precision"],
            "recall": rgb_metrics["recall"],
            "f1": rgb_metrics["f1"]
        },
        {
            "model": "BYTE_HEX",
            "accuracy": byte_metrics["accuracy"],
            "precision": byte_metrics["precision"],
            "recall": byte_metrics["recall"],
            "f1": byte_metrics["f1"]
        },
        {
            "model": "HYBRID",
            "accuracy": hybrid_metrics["accuracy"],
            "precision": hybrid_metrics["precision"],
            "recall": hybrid_metrics["recall"],
            "f1": hybrid_metrics["f1"]
        }
    ])
    comparison_df.to_csv(results_dir / "comparison.csv", index=False)
    print("Saved comparison.csv successfully.")

    # --------------------------------------------------------------------------
    # Step 8: Final Summary Output
    # --------------------------------------------------------------------------
    total_elapsed = time.time() - start_time
    print()
    print("==================================================")
    print("SPIN-IDS HYBRID MODEL RESULTS")
    print("==================================================")
    print()
    print("RGB CNN")
    print(f"Accuracy:  {rgb_metrics['accuracy']:.4f} ({rgb_metrics['accuracy'] * 100:.2f}%)")
    print(f"Precision: {rgb_metrics['precision']:.4f}")
    print(f"Recall:    {rgb_metrics['recall']:.4f}")
    print(f"F1:        {rgb_metrics['f1']:.4f}")
    print()
    print("BYTE/HEX MODEL")
    print(f"Accuracy:  {byte_metrics['accuracy']:.4f} ({byte_metrics['accuracy'] * 100:.2f}%)")
    print(f"Precision: {byte_metrics['precision']:.4f}")
    print(f"Recall:    {byte_metrics['recall']:.4f}")
    print(f"F1:        {byte_metrics['f1']:.4f}")
    print()
    print("HYBRID RGB + BYTE")
    print(f"Accuracy:  {hybrid_metrics['accuracy']:.4f} ({hybrid_metrics['accuracy'] * 100:.2f}%)")
    print(f"Precision: {hybrid_metrics['precision']:.4f}")
    print(f"Recall:    {hybrid_metrics['recall']:.4f}")
    print(f"F1:        {hybrid_metrics['f1']:.4f}")
    print()
    print("Fusion weights:")
    print(f"RGB  = {WEIGHT_RGB:.2f}")
    print(f"BYTE = {WEIGHT_BYTE:.2f}")
    print()
    print(f"Total Experiment Time: {total_elapsed:.2f} seconds")
    print("==================================================")

    # --------------------------------------------------------------------------
    # Step 9: 10 Sample Predictions Display
    # --------------------------------------------------------------------------
    print("\n" + "=" * 95)
    print("SAMPLE PREDICTIONS (10 WINDOWS FROM TEST SET)")
    print("=" * 95)
    print(f"{'Index':<6} {'Window ID':<18} {'True Label':<12} {'RGB Prob':<10} {'Byte Prob':<10} {'Final Score':<12} {'Final Pred':<11} {'Status'}")
    print("-" * 95)

    # Sample 5 normal and 5 malicious windows from test set for balanced inspection
    normal_idxs = np.where(y_test == 0)[0][:5]
    malicious_idxs = np.where(y_test == 1)[0][:5]
    sample_idxs = np.concatenate([normal_idxs, malicious_idxs])

    for rank, idx in enumerate(sample_idxs, 1):
        wid = test_wids[idx]
        t_label = CLASS_NAMES[y_test[idx]]
        rgb_p = rgb_malicious_prob[idx]
        byte_p = byte_malicious_prob[idx]
        f_score = final_malicious_score[idx]
        pred_label = CLASS_NAMES[hybrid_preds[idx]]
        status = "[CORRECT]" if pred_label == t_label else "[MISMATCH]"

        print(f"{rank:<6} {wid:<18} {t_label:<12} {rgb_p:<10.4f} {byte_p:<10.4f} {f_score:<12.4f} {pred_label:<11} {status}")
    print("=" * 95)
    print()


if __name__ == "__main__":
    main()
