"""
================================================================================
SPIN-IDS EXPERIMENT 2: HYBRID RGB + BYTE/HEX HARD DATASET TRAINING PIPELINE
================================================================================

Experiment Description:
This experiment trains and evaluates the SPIN-IDS multi-modal pipeline on the
hard synthetic dataset (dataset/Synthetic_Hard/), where NORMAL and MALICIOUS_SYNTHETIC
traffic share heavily overlapping marginal byte distributions (mean, std, entropy,
zero-ratio, ff-ratio). 

Differences between classes are primarily sequential and spatial:
  - 2D Spatial Packet Grid (RGB CNN): Extracts spatial layout, patch-level vertical
    correlations, and 2D visual anomaly patterns.
  - 1D Sequential Byte Features (MLP): Analyzes 18 derived features including packet
    length variations, direction change frequency, consecutive similarity, repeated
    n-gram blocks, and byte transition entropy.
  - Score Fusion: Sweeps candidate fusion weights (0.9/0.1, 0.8/0.2, 0.7/0.3, 0.6/0.4, 0.5/0.5)
    strictly on the VALIDATION SET, selects the best configuration, and evaluates once on
    the held-out TEST SET.

IMPORTANT RESEARCH NOTICE:
MALICIOUS_SYNTHETIC is controlled synthetic anomalous traffic and does not represent
real-world attacks. This experiment tests architectural representation capability and
score fusion under challenging distribution overlap.
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

# Candidate fusion weights to sweep on the validation set
CANDIDATE_WEIGHTS = [
    (0.9, 0.1),
    (0.8, 0.2),
    (0.7, 0.3),
    (0.6, 0.4),
    (0.5, 0.5)
]

DECISION_THRESHOLD = 0.50
CLASS_NAMES = ["NORMAL", "MALICIOUS"]

LABEL_MAP = {
    "NORMAL": 0,
    "MALICIOUS_SYNTHETIC": 1,
    "MALICIOUS": 1
}

FEATURE_NAMES = [
    "mean_byte",
    "std_byte",
    "min_byte",
    "max_byte",
    "unique_byte_count",
    "byte_entropy",
    "zero_ratio",
    "ff_ratio",
    "high_byte_ratio",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_max",
    "packet_length_min",
    "direction_change_count",
    "direction_change_ratio",
    "consecutive_packet_similarity",
    "repeated_block_score",
    "byte_transition_entropy"
]


# ==============================================================================
# 2. PATH RESOLUTION HELPERS
# ==============================================================================
def get_project_root() -> Path:
    current = Path(__file__).resolve().parent
    if current.name == "ml":
        return current.parent
    return current


# ==============================================================================
# 3. FEATURE EXTRACTION & DATA LOADING
# ==============================================================================
def extract_18_features(byte_matrix: np.ndarray) -> np.ndarray:
    """
    Computes 18 byte-level and sequential features strictly without using labels:
      1. mean_byte
      2. std_byte
      3. min_byte
      4. max_byte
      5. unique_byte_count
      6. byte_entropy (Shannon entropy in bits, base 2)
      7. zero_ratio
      8. ff_ratio
      9. high_byte_ratio
      10. packet_length_mean
      11. packet_length_std
      12. packet_length_max
      13. packet_length_min
      14. direction_change_count
      15. direction_change_ratio
      16. consecutive_packet_similarity (mean pairwise cosine similarity)
      17. repeated_block_score (1 - fraction of unique 4-grams)
      18. byte_transition_entropy (Shannon entropy of adjacent byte differences)
    """
    byte_matrix = np.asarray(byte_matrix, dtype=np.uint8)
    n_samples, n_bytes = byte_matrix.shape
    features = np.zeros((n_samples, 18), dtype=np.float32)

    features[:, 0] = np.mean(byte_matrix, axis=1)
    features[:, 1] = np.std(byte_matrix, axis=1)
    features[:, 2] = np.min(byte_matrix, axis=1)
    features[:, 3] = np.max(byte_matrix, axis=1)

    for i in range(n_samples):
        row = byte_matrix[i]
        counts = np.bincount(row, minlength=256)
        features[i, 4] = np.count_nonzero(counts)
        probs = counts[counts > 0] / float(n_bytes)
        features[i, 5] = -np.sum(probs * np.log2(probs))

    features[:, 6] = np.mean(byte_matrix == 0, axis=1)
    features[:, 7] = np.mean(byte_matrix == 255, axis=1)
    features[:, 8] = np.mean(byte_matrix >= 128, axis=1)

    for i in range(n_samples):
        w = byte_matrix[i]
        packets = w.reshape(9, 243)

        lengths = (packets[:, 2].astype(np.int32) << 8) | packets[:, 3].astype(np.int32)
        features[i, 9] = np.mean(lengths)
        features[i, 10] = np.std(lengths)
        features[i, 11] = np.max(lengths)
        features[i, 12] = np.min(lengths)

        dirs = packets[:, 0]
        dir_changes = np.sum(dirs[1:] != dirs[:-1])
        features[i, 13] = dir_changes
        features[i, 14] = dir_changes / 8.0

        p_fl = packets.astype(np.float32)
        dot = np.sum(p_fl[:-1] * p_fl[1:], axis=1)
        norm1 = np.linalg.norm(p_fl[:-1], axis=1)
        norm2 = np.linalg.norm(p_fl[1:], axis=1)
        cos_sims = dot / (norm1 * norm2 + 1e-6)
        features[i, 15] = np.mean(cos_sims)

        w32 = w.astype(np.uint32)
        n_4grams = 2187 - 4 + 1
        four_grams = (w32[:-3] << 24) | (w32[1:-2] << 16) | (w32[2:-1] << 8) | w32[3:]
        unique_4grams = len(np.unique(four_grams))
        features[i, 16] = 1.0 - (unique_4grams / float(n_4grams))

        diffs = (w.astype(np.int16)[1:] - w.astype(np.int16)[:-1]) % 256
        diff_counts = np.bincount(diffs, minlength=256)
        diff_probs = diff_counts[diff_counts > 0] / float(len(diffs))
        features[i, 17] = -np.sum(diff_probs * np.log2(diff_probs))

    return features


class FeatureStandardScaler:
    """Standardizes feature columns to zero mean and unit variance."""
    def __init__(self):
        self.mean_ = None
        self.scale_ = None

    def fit(self, X: np.ndarray):
        X = np.asarray(X, dtype=np.float32)
        self.mean_ = np.mean(X, axis=0)
        self.scale_ = np.std(X, axis=0)
        self.scale_[self.scale_ == 0.0] = 1.0
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float32)
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)


def load_dataset_split(csv_path: Path):
    """Loads a split CSV and extracts window IDs, labels, RGB tensors, and byte features."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset split file not found: {csv_path}")

    print(f"Loading {csv_path.name} from {csv_path.parent}...")
    df = pd.read_csv(csv_path)

    window_ids = df["window_id"].tolist()
    raw_labels = df["label"].tolist()
    labels = np.array([LABEL_MAP.get(l, 1) for l in raw_labels], dtype=np.int64)

    byte_cols = [f"b{i:04d}" for i in range(2187)]
    missing_cols = [col for col in byte_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"CSV {csv_path.name} is missing {len(missing_cols)} byte columns!")

    raw_bytes = df[byte_cols].to_numpy(dtype=np.uint8)

    # Reshape 2187 bytes into (27, 27, 3) normalized to [0, 1]
    rgb_images = (raw_bytes.reshape(-1, 27, 27, 3).astype(np.float32)) / 255.0

    # Extract 18 sequential and byte statistical features
    byte_features = extract_18_features(raw_bytes)

    return {
        "window_ids": window_ids,
        "labels": labels,
        "rgb_images": rgb_images,
        "byte_features": byte_features,
        "raw_labels": raw_labels
    }


# ==============================================================================
# 4. MODEL BUILDERS
# ==============================================================================
def build_rgb_cnn_model(input_shape=(27, 27, 3), num_classes=2):
    """
    Lightweight 2D CNN matching SPIN-IDS architecture:
      - Conv2D 32, 3x3, ReLU, same
      - MaxPooling2D 2x2
      - Conv2D 64, 3x3, ReLU, same
      - MaxPooling2D 2x2
      - Flatten
      - Dense 64 ReLU
      - Dropout 0.3
      - Dense 2 softmax
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
    ], name="spin_ids_rgb_cnn_hard")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model


def build_byte_mlp_model(input_dim=18, num_classes=2):
    """
    Small MLP architecture for 18 sequential & statistical byte features:
      - Dense 64 ReLU
      - Dropout 0.2
      - Dense 32 ReLU
      - Dense 2 softmax
    """
    model = keras.Sequential([
        layers.Input(shape=(input_dim,), name="byte_features_input"),
        layers.Dense(64, activation="relu", name="mlp_dense_1"),
        layers.Dropout(0.2, name="mlp_dropout_1"),
        layers.Dense(32, activation="relu", name="mlp_dense_2"),
        layers.Dense(num_classes, activation="softmax", name="mlp_output_softmax")
    ], name="spin_ids_byte_mlp_hard")

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
    """Computes accuracy, precision, recall, f1, and confusion matrix using pure NumPy."""
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    total = len(y_true)

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
# 6. MAIN EXPERIMENT PIPELINE
# ==============================================================================
def main():
    start_time = time.time()
    project_root = get_project_root()
    dataset_dir = project_root / "dataset" / "Synthetic_Hard"

    results_dir = project_root / "ml" / "results" / "hybrid_hard"
    models_dir = project_root / "ml" / "models" / "hybrid_hard"
    results_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("SPIN-IDS EXPERIMENT 2: HYBRID RGB + BYTE/HEX HARD DATASET")
    print("=" * 70)
    print("Keras Version        :", keras.__version__)
    print("Keras Backend        :", keras.backend.backend())
    print("PyTorch Version      :", torch.__version__)
    print("Random Seed          :", SEED)
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
    print(f"Byte Features Dim: {train_data['byte_features'].shape[1]} features (18 sequential & statistical)")
    print("--------------------------------------------------\n")

    # --------------------------------------------------------------------------
    # Step 2: Prepare Feature Scaler for 18 Byte Features
    # --------------------------------------------------------------------------
    scaler = FeatureStandardScaler()
    x_byte_train = scaler.fit_transform(train_data["byte_features"])
    x_byte_val = scaler.transform(val_data["byte_features"])
    x_byte_test = scaler.transform(test_data["byte_features"])

    x_rgb_train = train_data["rgb_images"]
    x_rgb_val = val_data["rgb_images"]
    x_rgb_test = test_data["rgb_images"]

    # --------------------------------------------------------------------------
    # Step 3: Train Model 1 - RGB CNN
    # --------------------------------------------------------------------------
    print("\n" + "#" * 60)
    print("TRAINING MODEL 1: RGB CNN (27x27x3 Spatial Image)")
    print("#" * 60)

    rgb_model = build_rgb_cnn_model(input_shape=(27, 27, 3), num_classes=2)
    rgb_model.summary()

    rgb_model_path = models_dir / "spin_ids_rgb_hard.keras"
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
    rgb_max_epochs = 30
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
    # Step 4: Train Model 2 - Byte/Hex MLP (18 Features)
    # --------------------------------------------------------------------------
    print("\n" + "#" * 60)
    print("TRAINING MODEL 2: BYTE/HEX MLP (18 Sequential & Byte Features)")
    print("#" * 60)

    byte_model = build_byte_mlp_model(input_dim=18, num_classes=2)
    byte_model.summary()

    byte_model_path = models_dir / "spin_ids_byte_hard.keras"
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
    byte_max_epochs = 30
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
    # Step 5: Validation Set Evaluation & Fusion Weight Selection
    # --------------------------------------------------------------------------
    print("\n" + "#" * 60)
    print("EVALUATING FUSION WEIGHTS ON VALIDATION SET (450 SAMPLES)")
    print("IMPORTANT: Selection is strictly performed on VALIDATION set.")
    print("#" * 60)

    val_rgb_probs = rgb_model.predict(x_rgb_val, batch_size=rgb_batch_size, verbose=0)
    val_byte_probs = byte_model.predict(x_byte_val, batch_size=byte_batch_size, verbose=0)

    val_rgb_mal = val_rgb_probs[:, 1]
    val_byte_mal = val_byte_probs[:, 1]

    fusion_sweep_records = []
    best_val_f1 = -1.0
    best_val_acc = -1.0
    best_weights = None

    print(f"{'RGB Weight':<12} {'Byte Weight':<13} {'Val Acc':<10} {'Val Prec':<10} {'Val Rec':<10} {'Val F1':<10}")
    print("-" * 65)

    for w_rgb, w_byte in CANDIDATE_WEIGHTS:
        val_score = (w_rgb * val_rgb_mal) + (w_byte * val_byte_mal)
        val_pred = (val_score >= DECISION_THRESHOLD).astype(int)
        m = evaluate_predictions(y_val, val_pred)

        # Selection criterion: Highest validation F1, broken by accuracy
        is_current_best = False
        if (m["f1"] > best_val_f1) or (m["f1"] == best_val_f1 and m["accuracy"] > best_val_acc):
            best_val_f1 = m["f1"]
            best_val_acc = m["accuracy"]
            best_weights = (w_rgb, w_byte)
            is_current_best = True

        fusion_sweep_records.append({
            "rgb_weight": w_rgb,
            "byte_weight": w_byte,
            "val_accuracy": m["accuracy"],
            "val_precision": m["precision"],
            "val_recall": m["recall"],
            "val_f1": m["f1"]
        })

        print(f"{w_rgb:<12.2f} {w_byte:<13.2f} {m['accuracy']:<10.4f} {m['precision']:<10.4f} {m['recall']:<10.4f} {m['f1']:<10.4f}")

    # Annotate is_best column
    for rec in fusion_sweep_records:
        rec["is_best"] = (rec["rgb_weight"] == best_weights[0] and rec["byte_weight"] == best_weights[1])

    fusion_df = pd.DataFrame(fusion_sweep_records)
    fusion_csv_path = results_dir / "fusion_weight_results.csv"
    fusion_df.to_csv(fusion_csv_path, index=False)
    print(f"\nSaved validation sweep results to: {fusion_csv_path}")
    print(f"Selected Best Fusion Weights from Validation: RGB={best_weights[0]:.2f}, Byte={best_weights[1]:.2f}")

    # --------------------------------------------------------------------------
    # Step 6: Test Set Evaluation (Once per Model + Best Hybrid)
    # --------------------------------------------------------------------------
    print("\n" + "#" * 60)
    print("FINAL EVALUATION ON HELD-OUT TEST SET (450 SAMPLES)")
    print("#" * 60)

    # 6.1 RGB Model Evaluation on Test
    test_rgb_probs = rgb_model.predict(x_rgb_test, batch_size=rgb_batch_size, verbose=0)
    test_rgb_preds = np.argmax(test_rgb_probs, axis=1)
    rgb_test_metrics = evaluate_predictions(y_test, test_rgb_preds)

    # 6.2 Byte Model Evaluation on Test
    test_byte_probs = byte_model.predict(x_byte_test, batch_size=byte_batch_size, verbose=0)
    test_byte_preds = np.argmax(test_byte_probs, axis=1)
    byte_test_metrics = evaluate_predictions(y_test, test_byte_preds)

    # 6.3 Best Hybrid Model Evaluation on Test
    sel_w_rgb, sel_w_byte = best_weights
    test_rgb_mal = test_rgb_probs[:, 1]
    test_byte_mal = test_byte_probs[:, 1]
    test_hybrid_score = (sel_w_rgb * test_rgb_mal) + (sel_w_byte * test_byte_mal)
    test_hybrid_preds = (test_hybrid_score >= DECISION_THRESHOLD).astype(int)
    hybrid_test_metrics = evaluate_predictions(y_test, test_hybrid_preds)

    # --------------------------------------------------------------------------
    # Step 7: Save All Evaluation Artifacts
    # --------------------------------------------------------------------------
    print("\nSaving evaluation artifacts to:", results_dir)

    # 7.1 Metrics Text Reports
    save_metrics_text_file(
        results_dir / "rgb_metrics.txt",
        "RGB CNN Model (Synthetic_Hard)",
        "2D Sequential CNN with Conv2D(32)-MaxPool-Conv2D(64)-MaxPool-Dense(64)-Dropout(0.3)-Softmax(2)",
        rgb_test_metrics, y_test, test_rgb_preds
    )

    save_metrics_text_file(
        results_dir / "byte_metrics.txt",
        "Byte/Hex MLP Model (18 Features, Synthetic_Hard)",
        "Sequential MLP with Dense(64, ReLU)-Dropout(0.2)-Dense(32, ReLU)-Softmax(2)",
        byte_test_metrics, y_test, test_byte_preds
    )

    save_metrics_text_file(
        results_dir / "hybrid_metrics.txt",
        f"Hybrid Score Fusion Model ({sel_w_rgb:.2f} RGB + {sel_w_byte:.2f} BYTE, Synthetic_Hard)",
        f"Validation-selected weighted ensemble: {sel_w_rgb:.2f}*P(malicious|RGB) + {sel_w_byte:.2f}*P(malicious|BYTE) >= {DECISION_THRESHOLD:.2f}",
        hybrid_test_metrics, y_test, test_hybrid_preds
    )

    # 7.2 Confusion Matrix CSVs
    cm_index = ["Actual_NORMAL", "Actual_MALICIOUS"]
    cm_columns = ["Predicted_NORMAL", "Predicted_MALICIOUS"]

    pd.DataFrame(rgb_test_metrics["confusion_matrix"], index=cm_index, columns=cm_columns).to_csv(
        results_dir / "rgb_confusion_matrix.csv"
    )
    pd.DataFrame(byte_test_metrics["confusion_matrix"], index=cm_index, columns=cm_columns).to_csv(
        results_dir / "byte_confusion_matrix.csv"
    )
    pd.DataFrame(hybrid_test_metrics["confusion_matrix"], index=cm_index, columns=cm_columns).to_csv(
        results_dir / "hybrid_confusion_matrix.csv"
    )

    # 7.3 Confusion Matrix PNG Heatmaps
    plot_and_save_confusion_matrix(
        rgb_test_metrics["confusion_matrix"],
        "SPIN-IDS Hard: RGB CNN Confusion Matrix",
        results_dir / "rgb_confusion_matrix.png"
    )
    plot_and_save_confusion_matrix(
        byte_test_metrics["confusion_matrix"],
        "SPIN-IDS Hard: Byte/Hex MLP Confusion Matrix",
        results_dir / "byte_confusion_matrix.png"
    )
    plot_and_save_confusion_matrix(
        hybrid_test_metrics["confusion_matrix"],
        f"SPIN-IDS Hard: Hybrid (RGB {int(sel_w_rgb*100)}% + Byte {int(sel_w_byte*100)}%)",
        results_dir / "hybrid_confusion_matrix.png"
    )

    # 7.4 Prediction CSVs
    test_wids = test_data["window_ids"]

    # rgb_predictions.csv
    pd.DataFrame({
        "window_id": test_wids,
        "true_label": [CLASS_NAMES[y] for y in y_test],
        "predicted_label": [CLASS_NAMES[p] for p in test_rgb_preds],
        "prob_normal": test_rgb_probs[:, 0],
        "prob_malicious": test_rgb_probs[:, 1],
        "correct": (y_test == test_rgb_preds)
    }).to_csv(results_dir / "rgb_predictions.csv", index=False)

    # byte_predictions.csv
    pd.DataFrame({
        "window_id": test_wids,
        "true_label": [CLASS_NAMES[y] for y in y_test],
        "predicted_label": [CLASS_NAMES[p] for p in test_byte_preds],
        "prob_normal": test_byte_probs[:, 0],
        "prob_malicious": test_byte_probs[:, 1],
        "correct": (y_test == test_byte_preds)
    }).to_csv(results_dir / "byte_predictions.csv", index=False)

    # hybrid_predictions.csv
    pd.DataFrame({
        "window_id": test_wids,
        "true_label": [CLASS_NAMES[y] for y in y_test],
        "predicted_label": [CLASS_NAMES[p] for p in test_hybrid_preds],
        "rgb_prob_malicious": test_rgb_mal,
        "byte_prob_malicious": test_byte_mal,
        "final_malicious_score": test_hybrid_score,
        "correct": (y_test == test_hybrid_preds)
    }).to_csv(results_dir / "hybrid_predictions.csv", index=False)

    # 7.5 Comparison CSV
    comparison_df = pd.DataFrame([
        {
            "model": "RGB",
            "accuracy": rgb_test_metrics["accuracy"],
            "precision": rgb_test_metrics["precision"],
            "recall": rgb_test_metrics["recall"],
            "f1": rgb_test_metrics["f1"]
        },
        {
            "model": "BYTE_HEX",
            "accuracy": byte_test_metrics["accuracy"],
            "precision": byte_test_metrics["precision"],
            "recall": byte_test_metrics["recall"],
            "f1": byte_test_metrics["f1"]
        },
        {
            "model": "HYBRID",
            "accuracy": hybrid_test_metrics["accuracy"],
            "precision": hybrid_test_metrics["precision"],
            "recall": hybrid_test_metrics["recall"],
            "f1": hybrid_test_metrics["f1"]
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
    print("SPIN-IDS HARD DATASET EXPERIMENT")
    print("==================================================")
    print()
    print("RGB CNN")
    print(f"Accuracy:  {rgb_test_metrics['accuracy']:.4f} ({rgb_test_metrics['accuracy'] * 100:.2f}%)")
    print(f"Precision: {rgb_test_metrics['precision']:.4f}")
    print(f"Recall:    {rgb_test_metrics['recall']:.4f}")
    print(f"F1:        {rgb_test_metrics['f1']:.4f}")
    print()
    print("BYTE/HEX MODEL")
    print(f"Accuracy:  {byte_test_metrics['accuracy']:.4f} ({byte_test_metrics['accuracy'] * 100:.2f}%)")
    print(f"Precision: {byte_test_metrics['precision']:.4f}")
    print(f"Recall:    {byte_test_metrics['recall']:.4f}")
    print(f"F1:        {byte_test_metrics['f1']:.4f}")
    print()
    print("BEST HYBRID")
    print(f"RGB Weight:  {sel_w_rgb:.2f}")
    print(f"Byte Weight: {sel_w_byte:.2f}")
    print(f"Accuracy:    {hybrid_test_metrics['accuracy']:.4f} ({hybrid_test_metrics['accuracy'] * 100:.2f}%)")
    print(f"Precision:   {hybrid_test_metrics['precision']:.4f}")
    print(f"Recall:      {hybrid_test_metrics['recall']:.4f}")
    print(f"F1:          {hybrid_test_metrics['f1']:.4f}")
    print()
    print("Validation performance for every fusion weight:")
    for rec in fusion_sweep_records:
        mark = " <-- SELECTED" if rec["is_best"] else ""
        print(f"  RGB={rec['rgb_weight']:.1f} / Byte={rec['byte_weight']:.1f} -> "
              f"Acc={rec['val_accuracy']:.4f}, Prec={rec['val_precision']:.4f}, "
              f"Rec={rec['val_recall']:.4f}, F1={rec['val_f1']:.4f}{mark}")
    print()
    print(f"Selected fusion weight: RGB={sel_w_rgb:.2f}, Byte={sel_w_byte:.2f}")
    print()
    print("Final test confusion matrix:")
    print(f"  TN = {hybrid_test_metrics['tn']} (Normal correctly classified)")
    print(f"  FP = {hybrid_test_metrics['fp']} (Normal misclassified as Malicious)")
    print(f"  FN = {hybrid_test_metrics['fn']} (Malicious misclassified as Normal)")
    print(f"  TP = {hybrid_test_metrics['tp']} (Malicious correctly classified)")
    print()
    print(f"Total Experiment Time: {total_elapsed:.2f} seconds")
    print("==================================================")

    # --------------------------------------------------------------------------
    # Step 9: 10 Sample Predictions Display
    # --------------------------------------------------------------------------
    print("\n" + "=" * 95)
    print("SAMPLE PREDICTIONS (10 WINDOWS FROM HELD-OUT TEST SET)")
    print("=" * 95)
    print(f"{'Index':<6} {'Window ID':<18} {'True Label':<12} {'RGB Prob':<10} {'Byte Prob':<10} {'Final Score':<12} {'Final Pred':<11} {'Status'}")
    print("-" * 95)

    normal_idxs = np.where(y_test == 0)[0][:5]
    malicious_idxs = np.where(y_test == 1)[0][:5]
    sample_idxs = np.concatenate([normal_idxs, malicious_idxs])

    for rank, idx in enumerate(sample_idxs, 1):
        wid = test_wids[idx]
        t_label = CLASS_NAMES[y_test[idx]]
        rgb_p = test_rgb_mal[idx]
        byte_p = test_byte_mal[idx]
        f_score = test_hybrid_score[idx]
        pred_label = CLASS_NAMES[test_hybrid_preds[idx]]
        status = "[CORRECT]" if pred_label == t_label else "[MISMATCH]"

        print(f"{rank:<6} {wid:<18} {t_label:<12} {rgb_p:<10.4f} {byte_p:<10.4f} {f_score:<12.4f} {pred_label:<11} {status}")
    print("=" * 95)
    print()
    print("RESEARCH NOTICE: MALICIOUS_SYNTHETIC is controlled synthetic anomalous traffic and does not represent real-world attacks.")
    print()


if __name__ == "__main__":
    main()
