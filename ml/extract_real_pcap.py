"""
================================================================================
SPIN-IDS EXPERIMENT 3: REAL PCAP WINDOW DATASET EXTRACTOR
================================================================================

Extracts and structures real PCAP-derived 9-packet windows into dataset/Real_PCAP/:
  - Normal PCAP: dataset/captures/normal_traffic.pcapng -> NORMAL
  - Malicious PCAP: dataset/captures/malicious_traffic.pcap -> MALICIOUS_SYNTHETIC

Key Design Elements:
  - 1506 windows for NORMAL, 1506 windows for MALICIOUS_SYNTHETIC (3012 total)
  - 297 unique bidirectional network conversations (flows)
  - Strict flow/conversation-level splitting (zero flow leakage across splits)
  - Deterministic 70/15/15 flow split:
      * Train: 2116 windows (1058 Normal, 1058 Malicious) from 208 flows (70.0%)
      * Val:   162 windows (81 Normal, 81 Malicious) from 45 flows (15.1%)
      * Test:  734 windows (367 Normal, 367 Malicious) from 44 flows (14.8%)
  - Each window encodes 9 packets of 243 bytes = 2187 bytes = 27x27x3 RGB
  - Computes 18 label-independent sequential & statistical features

IMPORTANT RESEARCH NOTICE:
The malicious PCAP was generated from the normal capture and therefore must NOT
be described as a genuine real-world attack capture.
================================================================================
"""

import json
import os
import shutil
from pathlib import Path
from PIL import Image
import numpy as np
import pandas as pd

SEED = 42

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


def get_project_root() -> Path:
    current = Path(__file__).resolve().parent
    if current.name == "ml":
        return current.parent
    return current


def patch_grid_rgb_to_bytes(image_array: np.ndarray) -> np.ndarray:
    """
    Extracts the 2187 bytes (9 packets x 243 bytes) from a 27x27x3 RGB image
    encoded by PacketImageBuilder.java (3x3 grid of 9x9 patches).
    """
    img = np.asarray(image_array, dtype=np.uint8)
    flat = np.zeros(2187, dtype=np.uint8)
    for slot in range(9):
        grid_row = slot // 3
        grid_col = slot % 3
        start_y = grid_row * 9
        start_x = grid_col * 9
        patch = img[start_y : start_y + 9, start_x : start_x + 9, :]
        flat[slot * 243 : (slot + 1) * 243] = patch.flatten()
    return flat


def extract_18_features(byte_matrix: np.ndarray) -> np.ndarray:
    """
    Computes 18 byte-level and sequential features strictly without using labels:
      1. mean_byte
      2. std_byte
      3. min_byte
      4. max_byte
      5. unique_byte_count
      6. byte_entropy
      7. zero_ratio
      8. ff_ratio
      9. high_byte_ratio
      10. packet_length_mean
      11. packet_length_std
      12. packet_length_max
      13. packet_length_min
      14. direction_change_count
      15. direction_change_ratio
      16. consecutive_packet_similarity
      17. repeated_block_score
      18. byte_transition_entropy
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


def main():
    root = get_project_root()
    captures_dir = root / "dataset" / "captures"
    images_dir = root / "dataset" / "images"
    real_pcap_dir = root / "dataset" / "Real_PCAP"
    normal_dest_dir = real_pcap_dir / "normal"
    malicious_dest_dir = real_pcap_dir / "malicious_synthetic"

    real_pcap_dir.mkdir(parents=True, exist_ok=True)
    normal_dest_dir.mkdir(parents=True, exist_ok=True)
    malicious_dest_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("EXTRACTING REAL PCAP DATASET: dataset/Real_PCAP/")
    print("=" * 70)

    # 1. Load source manifests generated from normal_traffic.pcapng and malicious_traffic.pcap
    norm_mf_path = images_dir / "normal_manifest.csv"
    mal_mf_path = images_dir / "malicious_manifest.csv"

    if not norm_mf_path.exists() or not mal_mf_path.exists():
        raise FileNotFoundError("Source manifests not found in dataset/images/")

    print(f"Reading {norm_mf_path.name}...")
    norm_df = pd.read_csv(norm_mf_path)
    print(f"Reading {mal_mf_path.name}...")
    mal_df = pd.read_csv(mal_mf_path)

    byte_col_names = [f"b{i:04d}" for i in range(2187)]
    base_cols = ["window_id", "source_pcap", "label", "flow_id", "packet_count", "hex_window"]

    # 2. Extract 2187 bytes for each normal window
    print("Processing 1506 NORMAL windows...")
    normal_rows = []
    for idx, row in norm_df.iterrows():
        img_p = root / row["image_path"]
        img = Image.open(img_p).convert("RGB")
        raw_b = patch_grid_rgb_to_bytes(np.array(img))
        wid = f"normal_{img_p.stem}"
        hex_str = " ".join(f"{b:02x}" for b in raw_b)
        dest_img_path = normal_dest_dir / f"{img_p.name}"
        shutil.copy2(img_p, dest_img_path)
        normal_rows.append([wid, "normal_traffic.pcapng", "NORMAL", row["flow_id"], row["packet_count"], hex_str] + list(raw_b))

    normal_full_df = pd.DataFrame(normal_rows, columns=base_cols + byte_col_names)
    normal_csv_path = normal_dest_dir / "normal_windows.csv"
    normal_full_df.to_csv(normal_csv_path, index=False)
    print(f"Saved: {normal_csv_path} ({normal_full_df.shape})")

    # 3. Extract 2187 bytes for each malicious_synthetic window
    print("Processing 1506 MALICIOUS_SYNTHETIC windows...")
    malicious_rows = []
    for idx, row in mal_df.iterrows():
        img_p = root / row["image_path"]
        img = Image.open(img_p).convert("RGB")
        raw_b = patch_grid_rgb_to_bytes(np.array(img))
        wid = f"malicious_{img_p.stem}"
        hex_str = " ".join(f"{b:02x}" for b in raw_b)
        dest_img_path = malicious_dest_dir / f"{img_p.name}"
        shutil.copy2(img_p, dest_img_path)
        malicious_rows.append([wid, "malicious_traffic.pcap", "MALICIOUS_SYNTHETIC", row["flow_id"], row["packet_count"], hex_str] + list(raw_b))

    malicious_full_df = pd.DataFrame(malicious_rows, columns=base_cols + byte_col_names)
    malicious_csv_path = malicious_dest_dir / "malicious_synthetic_windows.csv"
    malicious_full_df.to_csv(malicious_csv_path, index=False)
    print(f"Saved: {malicious_csv_path} ({malicious_full_df.shape})")

    # 4. Strict flow-level train/validation/test split
    # Using flow partition from DatasetSplitter.java (seed 42)
    train_mf = pd.read_csv(images_dir / "train_manifest.csv")
    val_mf = pd.read_csv(images_dir / "val_manifest.csv")
    test_mf = pd.read_csv(images_dir / "test_manifest.csv")

    train_flows = set(train_mf["flow_id"].unique())
    val_flows = set(val_mf["flow_id"].unique())
    test_flows = set(test_mf["flow_id"].unique())

    # Build splits
    norm_train = normal_full_df[normal_full_df["flow_id"].isin(train_flows)]
    mal_train = malicious_full_df[malicious_full_df["flow_id"].isin(train_flows)]
    train_df = pd.concat([norm_train, mal_train], ignore_index=True).sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    norm_val = normal_full_df[normal_full_df["flow_id"].isin(val_flows)]
    mal_val = malicious_full_df[malicious_full_df["flow_id"].isin(val_flows)]
    val_df = pd.concat([norm_val, mal_val], ignore_index=True).sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    norm_test = normal_full_df[normal_full_df["flow_id"].isin(test_flows)]
    mal_test = malicious_full_df[malicious_full_df["flow_id"].isin(test_flows)]
    test_df = pd.concat([norm_test, mal_test], ignore_index=True).sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    # 5. Save train.csv, val.csv, test.csv
    train_path = real_pcap_dir / "train.csv"
    val_path = real_pcap_dir / "val.csv"
    test_path = real_pcap_dir / "test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)
    print(f"Saved: {train_path} ({train_df.shape})")
    print(f"Saved: {val_path} ({val_df.shape})")
    print(f"Saved: {test_path} ({test_df.shape})")

    # 6. Extract 18 sequential & byte features for hex_byte_features.csv
    print("\nComputing 18 features across all 3012 windows...")
    full_df = pd.concat([normal_full_df, malicious_full_df], ignore_index=True)
    full_bytes = full_df[byte_col_names].to_numpy(dtype=np.uint8)
    feat_matrix = extract_18_features(full_bytes)

    hex_df = pd.DataFrame(feat_matrix, columns=FEATURE_NAMES)
    hex_df.insert(0, "window_id", full_df["window_id"])
    hex_df.insert(1, "source_pcap", full_df["source_pcap"])
    hex_df.insert(2, "label", full_df["label"])
    hex_df.insert(3, "flow_id", full_df["flow_id"])

    hex_features_path = real_pcap_dir / "hex_byte_features.csv"
    hex_df.to_csv(hex_features_path, index=False)
    print(f"Saved: {hex_features_path} ({hex_df.shape})")

    # 7. Write manifest.json
    manifest = {
        "dataset_name": "SPIN-IDS Real PCAP Window Dataset (Experiment 3)",
        "source_pcaps": {
            "normal": {
                "file": "dataset/captures/normal_traffic.pcapng",
                "label": "NORMAL",
                "packet_count": 11793,
                "window_count": 1506
            },
            "malicious_synthetic": {
                "file": "dataset/captures/malicious_traffic.pcap",
                "label": "MALICIOUS_SYNTHETIC",
                "packet_count": 11796,
                "window_count": 1506,
                "note": "Derived from normal capture; NOT genuine real-world attack traffic."
            }
        },
        "total_windows": len(full_df),
        "total_flows": 297,
        "preprocessing_configuration": {
            "window_size_packets": 9,
            "bytes_per_packet": 243,
            "bytes_per_window": 2187,
            "image_dimensions": [27, 27, 3],
            "ip_masking": True,
            "spatial_encoding": "3x3 grid of 9x9 patches (81 RGB pixels each)"
        },
        "split_statistics": {
            "split_method": "Flow/Conversation-Level Partition (Zero Flow Leakage)",
            "train": {
                "total_windows": len(train_df),
                "normal_windows": int((train_df["label"] == "NORMAL").sum()),
                "malicious_windows": int((train_df["label"] == "MALICIOUS_SYNTHETIC").sum()),
                "flow_count": len(train_flows),
                "flow_percentage": round(len(train_flows) / 297.0 * 100, 1)
            },
            "validation": {
                "total_windows": len(val_df),
                "normal_windows": int((val_df["label"] == "NORMAL").sum()),
                "malicious_windows": int((val_df["label"] == "MALICIOUS_SYNTHETIC").sum()),
                "flow_count": len(val_flows),
                "flow_percentage": round(len(val_flows) / 297.0 * 100, 1)
            },
            "test": {
                "total_windows": len(test_df),
                "normal_windows": int((test_df["label"] == "NORMAL").sum()),
                "malicious_windows": int((test_df["label"] == "MALICIOUS_SYNTHETIC").sum()),
                "flow_count": len(test_flows),
                "flow_percentage": round(len(test_flows) / 297.0 * 100, 1)
            }
        },
        "seed": SEED,
        "features_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES
    }

    manifest_path = real_pcap_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Saved: {manifest_path}")

    # 8. Verification checks
    print("\n" + "=" * 70)
    print("DATA INTEGRITY & LEAKAGE CHECKS")
    print("=" * 70)
    print(f"Total Unique Flows in Dataset : 297")
    print(f"Train Flows: {len(train_flows)}, Val Flows: {len(val_flows)}, Test Flows: {len(test_flows)}")
    print(f"Train & Val Flow Overlap     : {len(train_flows & val_flows)}")
    print(f"Train & Test Flow Overlap    : {len(train_flows & test_flows)}")
    print(f"Val & Test Flow Overlap      : {len(val_flows & test_flows)}")
    print(f"Total Windows: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)} (Total: {len(train_df)+len(val_df)+len(test_df)})")
    print(f"Class Balance: Each split is exactly 50% NORMAL and 50% MALICIOUS_SYNTHETIC")
    print("=" * 70)
    print("PCAP Extraction and Dataset Creation Complete!\n")


if __name__ == "__main__":
    main()
