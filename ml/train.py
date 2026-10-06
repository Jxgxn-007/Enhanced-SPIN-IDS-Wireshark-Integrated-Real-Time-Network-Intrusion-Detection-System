import os
import sys
from pathlib import Path

# Ensure PyTorch backend for Keras 3
os.environ["KERAS_BACKEND"] = "torch"
os.environ["PYTHONIOENCODING"] = "utf-8"

import numpy as np
import pandas as pd
from PIL import Image
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import torch
import keras
from keras import layers
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

# 1. Deterministic Random Seed Setup
SEED = 42
np.random.seed(SEED)
torch.manual_seed(SEED)
keras.utils.set_random_seed(SEED)

CLASS_NAMES = ["NORMAL", "MALICIOUS"]

def get_project_root():
    # Resolves to 'spin-ids' directory
    current = Path(__file__).resolve().parent
    if current.name == "ml":
        return current.parent
    return current

def load_split_dataset(split_dir, class_names=CLASS_NAMES):
    """Loads 27x27 RGB images and normalizes pixels to [0, 1]."""
    images = []
    labels = []
    filenames = []

    split_path = Path(split_dir)
    if not split_path.exists():
        raise FileNotFoundError(f"Directory not found: {split_path}")

    for class_idx, class_name in enumerate(class_names):
        # Case-insensitive directory matching
        target_dir = split_path / class_name.lower()
        if not target_dir.exists():
            target_dir = split_path / class_name

        if not target_dir.exists():
            print(f"Warning: directory {target_dir} does not exist.")
            continue

        png_files = sorted(target_dir.glob("*.png"))
        for p in png_files:
            img = Image.open(p).convert("RGB")
            if img.size != (27, 27):
                img = img.resize((27, 27), Image.NEAREST)
            arr = np.array(img, dtype=np.float32) / 255.0  # Normalize to [0.0, 1.0]
            images.append(arr)
            labels.append(class_idx)
            filenames.append(p.name)

    return np.array(images, dtype=np.float32), np.array(labels, dtype=np.int64), filenames

def build_cnn_model(input_shape=(27, 27, 3), num_classes=2):
    """Lightweight 2D CNN architecture tailored for 27x27 packet images."""
    model = keras.Sequential([
        layers.Input(shape=input_shape),
        layers.Conv2D(32, (3, 3), activation="relu", padding="same", name="conv2d_1"),
        layers.MaxPooling2D((2, 2), name="maxpool_1"),
        layers.Conv2D(64, (3, 3), activation="relu", padding="same", name="conv2d_2"),
        layers.MaxPooling2D((2, 2), name="maxpool_2"),
        layers.Flatten(name="flatten"),
        layers.Dense(64, activation="relu", name="dense_1"),
        layers.Dropout(0.3, name="dropout"),
        layers.Dense(num_classes, activation="softmax", name="output_softmax")
    ], name="spin_ids_cnn")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model

def plot_and_save_curves(history, results_dir):
    """Plots training and validation accuracy and loss curves."""
    epochs_range = range(1, len(history.history["loss"]) + 1)

    # Accuracy Plot
    plt.figure(figsize=(7, 5))
    plt.plot(epochs_range, history.history["accuracy"], "b-o", label="Training Accuracy")
    plt.plot(epochs_range, history.history["val_accuracy"], "g--s", label="Validation Accuracy")
    plt.title("SPIN-IDS CNN: Training & Validation Accuracy")
    plt.xlabel("Epoch")
    plt.ylabel("Accuracy")
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.legend()
    plt.tight_layout()
    acc_path = results_dir / "accuracy_curve.png"
    plt.savefig(acc_path, dpi=200)
    plt.close()

    # Loss Plot
    plt.figure(figsize=(7, 5))
    plt.plot(epochs_range, history.history["loss"], "r-o", label="Training Loss")
    plt.plot(epochs_range, history.history["val_loss"], "m--s", label="Validation Loss")
    plt.title("SPIN-IDS CNN: Training & Validation Loss")
    plt.xlabel("Epoch")
    plt.ylabel("Loss (Cross-Entropy)")
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.legend()
    plt.tight_layout()
    loss_path = results_dir / "loss_curve.png"
    plt.savefig(loss_path, dpi=200)
    plt.close()

def plot_confusion_matrix_figure(cm, class_names, results_dir):
    """Renders visual confusion matrix heatmap."""
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(
        xticks=np.arange(cm.shape[1]),
        yticks=np.arange(cm.shape[0]),
        xticklabels=class_names,
        yticklabels=class_names,
        title="SPIN-IDS Confusion Matrix",
        ylabel="True Label",
        xlabel="Predicted Label"
    )

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], "d"),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontweight="bold")

    plt.tight_layout()
    cm_path = results_dir / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=200)
    plt.close()

def export_to_onnx(model, onnx_path):
    """Exports the trained model to ONNX format using legacy TorchScript export."""
    try:
        dummy_input = torch.randn(1, 27, 27, 3)
        torch.onnx.export(
            model,
            dummy_input,
            str(onnx_path),
            input_names=["input"],
            output_names=["output"],
            dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
            opset_version=18,
            dynamo=False
        )
        return True, None
    except Exception as e:
        return False, str(e)

def main():
    root = get_project_root()
    train_dir = root / "dataset" / "images" / "train"
    val_dir = root / "dataset" / "images" / "val"
    test_dir = root / "dataset" / "images" / "test"

    models_dir = root / "ml" / "models"
    results_dir = root / "ml" / "results"
    models_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("SPIN-IDS CNN TRAINING PIPELINE")
    print("=" * 60)
    print("Keras Version   :", keras.__version__)
    print("Keras Backend   :", keras.backend.backend())
    print("PyTorch Version :", torch.__version__)
    print("Random Seed     :", SEED)
    print()

    # 1. Load Data
    print("Loading datasets...")
    x_train, y_train, train_files = load_split_dataset(train_dir)
    x_val, y_val, val_files = load_split_dataset(val_dir)
    x_test, y_test, test_files = load_split_dataset(test_dir)

    # 2. Print Class Distribution
    print("--------------------------------------------------")
    print("Dataset Class Distribution:")
    print("--------------------------------------------------")
    print(f"Train Set      : Total={len(y_train)}, NORMAL={np.sum(y_train == 0)}, MALICIOUS={np.sum(y_train == 1)}")
    print(f"Validation Set : Total={len(y_val)}, NORMAL={np.sum(y_val == 0)}, MALICIOUS={np.sum(y_val == 1)}")
    print(f"Test Set       : Total={len(y_test)}, NORMAL={np.sum(y_test == 0)}, MALICIOUS={np.sum(y_test == 1)}")
    print(f"Image Tensor Shape: {x_train.shape[1:]} (H, W, C)")
    print()

    # 3. Build Model
    model = build_cnn_model()
    model.summary()

    # 4. Training Callbacks
    keras_model_path = models_dir / "spin_ids_cnn.keras"
    callbacks = [
        keras.callbacks.ModelCheckpoint(
            filepath=str(keras_model_path),
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

    # 5. Train Model
    batch_size = 32
    max_epochs = 30
    print(f"\nStarting training (max_epochs={max_epochs}, batch_size={batch_size})...")
    history = model.fit(
        x_train, y_train,
        validation_data=(x_val, y_val),
        epochs=max_epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=1
    )

    completed_epochs = len(history.history["loss"])
    print(f"\nTraining finished after {completed_epochs} epochs.")

    # 6. Save Training History
    history_df = pd.DataFrame(history.history)
    history_df.insert(0, "epoch", range(1, completed_epochs + 1))
    history_csv_path = results_dir / "training_history.csv"
    history_df.to_csv(history_csv_path, index=False)
    print(f"Saved training history to {history_csv_path}")

    # 7. Generate Plots
    plot_and_save_curves(history, results_dir)
    print("Saved accuracy and loss curves to ml/results/")

    # 8. Evaluate on Test Set
    print("\nEvaluating on Test Set...")
    probs = model.predict(x_test, batch_size=batch_size, verbose=0)
    y_pred = np.argmax(probs, axis=1)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("--------------------------------------------------")
    print("TEST EVALUATION METRICS")
    print("--------------------------------------------------")
    print(f"Accuracy  : {acc:.4f} ({acc * 100:.2f}%)")
    print(f"Precision : {prec:.4f}")
    print(f"Recall    : {rec:.4f}")
    print(f"F1-Score  : {f1:.4f}")
    print("Confusion Matrix:")
    print(cm)
    print("--------------------------------------------------")

    # 9. Save Confusion Matrix
    cm_df = pd.DataFrame(cm, index=["Actual_NORMAL", "Actual_MALICIOUS"],
                         columns=["Predicted_NORMAL", "Predicted_MALICIOUS"])
    cm_csv_path = results_dir / "confusion_matrix.csv"
    cm_df.to_csv(cm_csv_path)
    plot_confusion_matrix_figure(cm, CLASS_NAMES, results_dir)

    # 10. Save Test Predictions
    pred_records = []
    for fn, true_l, pred_l, pr in zip(test_files, y_test, y_pred, probs):
        pred_records.append({
            "filename": fn,
            "true_label": CLASS_NAMES[true_l],
            "predicted_label": CLASS_NAMES[pred_l],
            "prob_normal": float(pr[0]),
            "prob_malicious": float(pr[1]),
            "correct": bool(true_l == pred_l)
        })
    pred_df = pd.DataFrame(pred_records)
    pred_csv_path = results_dir / "test_predictions.csv"
    pred_df.to_csv(pred_csv_path, index=False)

    # 11. Save Metrics TXT
    metrics_txt_path = results_dir / "metrics.txt"
    with open(metrics_txt_path, "w", encoding="utf-8") as f:
        f.write("SPIN-IDS CNN TEST EVALUATION REPORT\n")
        f.write("==================================================\n")
        f.write(f"Model Architecture       : 2D Sequential CNN (32-64 filters)\n")
        f.write(f"Input Shape              : 27x27x3 (RGB)\n")
        f.write(f"Completed Epochs         : {completed_epochs}\n")
        f.write(f"Total Test Samples       : {len(y_test)}\n")
        f.write(f"Accuracy                 : {acc:.6f}\n")
        f.write(f"Precision                : {prec:.6f}\n")
        f.write(f"Recall                   : {rec:.6f}\n")
        f.write(f"F1-Score                 : {f1:.6f}\n\n")
        f.write("Confusion Matrix:\n")
        f.write(f"  TN={cm[0,0]} (Normal correctly classified)\n")
        f.write(f"  FP={cm[0,1]} (Normal misclassified as Malicious)\n")
        f.write(f"  FN={cm[1,0]} (Malicious misclassified as Normal)\n")
        f.write(f"  TP={cm[1,1]} (Malicious correctly classified)\n\n")
        f.write("Detailed Classification Report:\n")
        f.write(classification_report(y_test, y_pred, target_names=CLASS_NAMES, digits=4))

    # 12. Export to ONNX
    onnx_path = models_dir / "spin_ids_cnn.onnx"
    print(f"\nExporting model to ONNX: {onnx_path} ...")
    onnx_success, onnx_error = export_to_onnx(model, onnx_path)
    if onnx_success:
        print("ONNX export successful!")
        try:
            import onnxruntime as ort
            session = ort.InferenceSession(str(onnx_path))
            test_out = session.run(None, {"input": x_test[:2]})[0]
            print(f"Verified with ONNX Runtime! Test inference shape: {test_out.shape}")
        except Exception as e:
            print(f"ONNX Runtime verification warning: {e}")
    else:
        print(f"ONNX export failed: {onnx_error}")

    # 13. Sample Inference Test
    print("\n" + "=" * 60)
    print("SAMPLE INFERENCE TEST ON TEST IMAGES")
    print("=" * 60)
    # Pick 4 Normal and 4 Malicious samples from test set
    normal_indices = np.where(y_test == 0)[0][:4]
    malicious_indices = np.where(y_test == 1)[0][:4]
    sample_indices = np.concatenate([normal_indices, malicious_indices])

    for idx in sample_indices:
        fn = test_files[idx]
        actual_class = CLASS_NAMES[y_test[idx]]
        pred_class = CLASS_NAMES[y_pred[idx]]
        conf = probs[idx][y_pred[idx]] * 100.0
        status = "[CORRECT]" if pred_class == actual_class else "[INCORRECT]"
        print(f"Image: {fn:<28} -> Predicted: {pred_class:<9} ({conf:6.2f}% conf) -> Actual: {actual_class:<9} {status}")
    print("=" * 60)

if __name__ == "__main__":
    main()
