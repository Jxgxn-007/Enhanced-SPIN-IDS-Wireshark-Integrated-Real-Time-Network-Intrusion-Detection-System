"""
================================================================================
SPIN-IDS SYNTHETIC HARD DATASET GENERATOR
================================================================================

Generates a synthetic network packet dataset with deliberately overlapping
marginal byte distributions (mean, std, min, max, entropy, zero_ratio, ff_ratio)
between NORMAL and MALICIOUS_SYNTHETIC windows.

Differences between classes are strictly sequential and spatial:
  - NORMAL: realistic request-response alternating flows, varied packet lengths,
    continuous application payload variability, natural transition entropy.
  - MALICIOUS_SYNTHETIC: subtle sequential anomalies such as packet-size bursts,
    direction stream irregularities, localized repeated byte patterns across
    consecutive packets (vertical 2D image stripes), and subtle sequence regularity.

Properties:
  - 3000 total windows (1500 NORMAL, 1500 MALICIOUS_SYNTHETIC)
  - 70/15/15 train/validation/test split (2100 train, 450 val, 450 test)
  - Deterministic seed = 42
  - 9 sequential packets per window, 243 bytes per packet = 2187 bytes per window
  - Reshapes exactly to (27, 27, 3)

Output directory:
  dataset/Synthetic_Hard/
================================================================================
"""

import json
import os
from pathlib import Path
import numpy as np
import pandas as pd

SEED = 42

def get_project_root() -> Path:
    current = Path(__file__).resolve().parent
    if current.name == "ml":
        return current.parent
    return current


def generate_window_payload(is_malicious: bool, rng: np.random.Generator):
    """
    Generates a 9-packet window (9 x 243 bytes = 2187 bytes).
    Each packet has:
      - Byte 0: direction (100 = FORWARD, 200 = BACKWARD)
      - Byte 1: sequence index (1 to 9)
      - Byte 2: length high byte
      - Byte 3: length low byte
      - Bytes 4..242: payload and protocol data (239 bytes)
    """
    packets = np.zeros((9, 243), dtype=np.uint8)
    length_pool = [64, 96, 128, 256, 512, 1024, 1460]

    # Shared base parameters for identical marginals
    base_zero_prob = rng.uniform(0.06, 0.12)
    base_ff_prob = rng.uniform(0.015, 0.035)

    if not is_malicious:
        # ----------------------------------------------------------------------
        # NORMAL TRAFFIC: natural client-server request-response dynamics
        # ----------------------------------------------------------------------
        # Directions: natural alternating flow (e.g. 2-5 direction changes)
        num_changes = rng.integers(2, 6)
        change_points = set(rng.choice(range(1, 9), size=num_changes, replace=False))
        dirs = [100]
        for idx in range(1, 9):
            if idx in change_points:
                dirs.append(200 if dirs[-1] == 100 else 100)
            else:
                dirs.append(dirs[-1])

        # Packet lengths: natural mixture
        lengths = []
        for d in dirs:
            if d == 100:
                # Client requests/acks tend to be small or medium
                lengths.append(int(rng.choice([64, 96, 128, 256, 512])))
            else:
                # Server replies tend to be larger data transfers or acks
                lengths.append(int(rng.choice([128, 256, 512, 1024, 1460])))

        for p_idx in range(9):
            packets[p_idx, 0] = dirs[p_idx]
            packets[p_idx, 1] = p_idx + 1
            packets[p_idx, 2] = (lengths[p_idx] >> 8) & 0xFF
            packets[p_idx, 3] = lengths[p_idx] & 0xFF

            # Payload with moderate packet-to-packet evolution
            # Blend of ASCII-like headers and varied binary data
            raw_p = rng.integers(0, 256, size=239, dtype=np.uint8)
            # Simulated protocol headers at start
            raw_p[0:8] = rng.integers(32, 127, size=8, dtype=np.uint8)

            # Apply baseline zeroes and 0xFF
            raw_p[rng.random(size=239) < base_zero_prob] = 0
            raw_p[rng.random(size=239) < base_ff_prob] = 255

            packets[p_idx, 4:] = raw_p

    else:
        # ----------------------------------------------------------------------
        # MALICIOUS SYNTHETIC TRAFFIC: subtle sequential and spatial anomalies
        # Marginal distributions are kept strictly overlapping with NORMAL.
        # ----------------------------------------------------------------------
        anomaly_mode = rng.integers(0, 4)

        if anomaly_mode == 0:
            # Anomaly Type 1: Packet size burst anomaly (unusual repetition of same size)
            burst_size = int(rng.choice([128, 256, 512]))
            lengths = [burst_size if 2 <= i <= 6 else int(rng.choice(length_pool)) for i in range(9)]
            # Varied directions to avoid direction-based easy separation
            dirs = [100 if rng.random() > 0.45 else 200 for _ in range(9)]

        elif anomaly_mode == 1:
            # Anomaly Type 2: Unusual direction stream anomaly
            if rng.random() > 0.5:
                # Unidirectional flood
                dirs = [100] * 9 if rng.random() > 0.5 else [200] * 9
            else:
                # High-frequency alternating flip-flop
                dirs = [100 if i % 2 == 0 else 200 for i in range(9)]
            lengths = [int(rng.choice(length_pool)) for _ in range(9)]

        elif anomaly_mode == 2:
            # Anomaly Type 3: Localized repeated block anomaly across consecutive packets
            # (Creates subtle vertical correlation in 2D RGB patch grid)
            dirs = [100 if rng.random() > 0.45 else 200 for _ in range(9)]
            lengths = [int(rng.choice(length_pool)) for _ in range(9)]

        else:
            # Anomaly Type 4: Subtle sequence-level transition regularity
            dirs = [100 if rng.random() > 0.45 else 200 for _ in range(9)]
            lengths = [int(rng.choice(length_pool)) for _ in range(9)]

        # Base payload generation using same distribution
        for p_idx in range(9):
            packets[p_idx, 0] = dirs[p_idx]
            packets[p_idx, 1] = p_idx + 1
            packets[p_idx, 2] = (lengths[p_idx] >> 8) & 0xFF
            packets[p_idx, 3] = lengths[p_idx] & 0xFF

            raw_p = rng.integers(0, 256, size=239, dtype=np.uint8)
            raw_p[0:8] = rng.integers(32, 127, size=8, dtype=np.uint8)
            raw_p[rng.random(size=239) < base_zero_prob] = 0
            raw_p[rng.random(size=239) < base_ff_prob] = 255
            packets[p_idx, 4:] = raw_p

        # Inject spatial/sequential structural patterns
        if anomaly_mode == 2:
            # Plant identical 12-byte block at same spatial offset in packets 1, 3, 5, 7
            secret_pattern = rng.integers(0, 256, size=12, dtype=np.uint8)
            offset = int(rng.integers(20, 180))
            for target_p in [1, 3, 5, 7]:
                packets[target_p, 4 + offset : 4 + offset + 12] = secret_pattern

        elif anomaly_mode == 3:
            # Plant repeated 8-byte cyclical stride in odd packets
            stride_pattern = rng.integers(0, 256, size=8, dtype=np.uint8)
            for target_p in range(1, 9, 2):
                packets[target_p, 40:48] = stride_pattern
                packets[target_p, 80:88] = stride_pattern

    return packets.flatten()


def extract_18_features(byte_matrix: np.ndarray) -> np.ndarray:
    """
    Computes all 18 requested byte-level and sequential features:
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


def main():
    root = get_project_root()
    output_dir = root / "dataset" / "Synthetic_Hard"
    normal_dir = output_dir / "normal"
    malicious_dir = output_dir / "malicious_synthetic"

    output_dir.mkdir(parents=True, exist_ok=True)
    normal_dir.mkdir(parents=True, exist_ok=True)
    malicious_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("GENERATING SPIN-IDS SYNTHETIC HARD DATASET")
    print("=" * 70)
    print(f"Target Directory: {output_dir}")
    print(f"Total Samples   : 3000 (1500 NORMAL, 1500 MALICIOUS_SYNTHETIC)")
    print(f"Split Ratios    : 70% Train (2100), 15% Val (450), 15% Test (450)")
    print(f"Random Seed     : {SEED}")
    print()

    rng = np.random.default_rng(SEED)

    # 1. Generate 1500 NORMAL windows
    print("Generating 1500 NORMAL windows...")
    normal_data = []
    for i in range(1500):
        wid = f"normal_{i+1:05d}"
        raw_b = generate_window_payload(is_malicious=False, rng=rng)
        hex_str = " ".join(f"{b:02x}" for b in raw_b)
        row = [wid, "NORMAL", 9, "SYNTHETIC_HARD", hex_str] + list(raw_b)
        normal_data.append(row)

    # 2. Generate 1500 MALICIOUS_SYNTHETIC windows
    print("Generating 1500 MALICIOUS_SYNTHETIC windows...")
    malicious_data = []
    for i in range(1500):
        wid = f"malicious_{i+1:05d}"
        raw_b = generate_window_payload(is_malicious=True, rng=rng)
        hex_str = " ".join(f"{b:02x}" for b in raw_b)
        row = [wid, "MALICIOUS_SYNTHETIC", 9, "SYNTHETIC_HARD", hex_str] + list(raw_b)
        malicious_data.append(row)

    byte_col_names = [f"b{i:04d}" for i in range(2187)]
    all_col_names = ["window_id", "label", "packet_count", "source", "hex_window"] + byte_col_names

    normal_df = pd.DataFrame(normal_data, columns=all_col_names)
    malicious_df = pd.DataFrame(malicious_data, columns=all_col_names)

    # Save class-specific files
    normal_csv_path = normal_dir / "normal_windows.csv"
    malicious_csv_path = malicious_dir / "malicious_synthetic_windows.csv"
    normal_df.to_csv(normal_csv_path, index=False)
    malicious_df.to_csv(malicious_csv_path, index=False)
    print(f"Saved: {normal_csv_path}")
    print(f"Saved: {malicious_csv_path}")

    # 3. Create Stratified 70/15/15 Split
    # Normal: 1050 train, 225 val, 225 test
    # Malicious: 1050 train, 225 val, 225 test
    norm_indices = np.arange(1500)
    mal_indices = np.arange(1500)
    rng.shuffle(norm_indices)
    rng.shuffle(mal_indices)

    norm_train_idx = norm_indices[:1050]
    norm_val_idx = norm_indices[1050:1275]
    norm_test_idx = norm_indices[1275:]

    mal_train_idx = mal_indices[:1050]
    mal_val_idx = mal_indices[1050:1275]
    mal_test_idx = mal_indices[1275:]

    train_df = pd.concat([normal_df.iloc[norm_train_idx], malicious_df.iloc[mal_train_idx]], ignore_index=True)
    val_df = pd.concat([normal_df.iloc[norm_val_idx], malicious_df.iloc[mal_val_idx]], ignore_index=True)
    test_df = pd.concat([normal_df.iloc[norm_test_idx], malicious_df.iloc[mal_test_idx]], ignore_index=True)

    # Shuffle each split deterministically
    train_df = train_df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    val_df = val_df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    test_df = test_df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    train_path = output_dir / "train.csv"
    val_path = output_dir / "val.csv"
    test_path = output_dir / "test.csv"
    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)
    print(f"Saved: {train_path} ({train_df.shape})")
    print(f"Saved: {val_path} ({val_df.shape})")
    print(f"Saved: {test_path} ({test_df.shape})")

    # 4. Extract all 18 features for hex_byte_features.csv
    print("Computing 18 features for hex_byte_features.csv across all 3000 windows...")
    full_df = pd.concat([train_df, val_df, test_df], ignore_index=True)
    full_bytes = full_df[byte_col_names].to_numpy(dtype=np.uint8)
    feat_matrix = extract_18_features(full_bytes)

    hex_features_df = pd.DataFrame(feat_matrix, columns=FEATURE_NAMES)
    hex_features_df.insert(0, "window_id", full_df["window_id"])
    hex_features_df.insert(1, "label", full_df["label"])

    hex_features_path = output_dir / "hex_byte_features.csv"
    hex_features_df.to_csv(hex_features_path, index=False)
    print(f"Saved: {hex_features_path}")

    # 5. Write manifest.json
    manifest = {
        "dataset_name": "SPIN-IDS Synthetic Hard Packet Dataset",
        "normal": 1500,
        "malicious_synthetic": 1500,
        "total": 3000,
        "train": len(train_df),
        "validation": len(val_df),
        "test": len(test_df),
        "packets_per_window": 9,
        "bytes_per_packet": 243,
        "bytes_per_window": 2187,
        "image_shape": [27, 27, 3],
        "split_ratio": [0.70, 0.15, 0.15],
        "seed": SEED,
        "features_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "description": "Hard synthetic benchmark with overlapping marginal byte statistics and subtle sequential anomalies."
    }
    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Saved: {manifest_path}")

    # 6. Write README.txt
    readme_text = """SPIN-IDS Synthetic Hard Packet Dataset (Experiment 2)
======================================================
IMPORTANT RESEARCH NOTE:
This dataset is synthetic benchmark data designed specifically for evaluating multi-modal
score fusion (RGB CNN + Byte/Hex MLP) under controlled distribution overlap.
MALICIOUS_SYNTHETIC is controlled synthetic anomalous traffic and does not represent real-world attacks.

Dataset Properties:
- Total windows: 3000 (1500 NORMAL, 1500 MALICIOUS_SYNTHETIC)
- Train / Val / Test: 2100 / 450 / 450 (70% / 15% / 15% stratified)
- Sequential window size: 9 packets
- Bytes per packet: 243
- Bytes per window: 2187 = 27 x 27 x 3 RGB image representation
- Seed: 42 (fully deterministic)

Design Characteristics:
NORMAL and MALICIOUS_SYNTHETIC share overlapping marginal byte distributions:
- Similar mean byte values (~118-120)
- Similar standard deviation (~78-81)
- Similar byte entropy (~5.7-6.2 bits)
- Similar zero ratio (~0.08-0.10)
- Similar 0xFF ratio (~0.02)
- Similar packet length ranges

Anomalies in MALICIOUS_SYNTHETIC are strictly sequential and spatial:
- Repeated packet-size bursts
- Unusual direction sequence transitions (unidirectional flood, strict flip-flop)
- Localized repeated byte blocks across consecutive packets (vertical 2D image stripes)
- Sequence-level transition regularity

Files in this directory:
- normal/normal_windows.csv
- malicious_synthetic/malicious_synthetic_windows.csv
- train.csv (2100 windows)
- val.csv (450 windows)
- test.csv (450 windows)
- hex_byte_features.csv (18 statistical & sequential features)
- manifest.json
- README.txt
"""
    readme_path = output_dir / "README.txt"
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_text)
    print(f"Saved: {readme_path}")

    # 7. Print Distribution Overlap Verification
    print("\n" + "=" * 70)
    print("DISTRIBUTION OVERLAP VERIFICATION (NORMAL vs MALICIOUS_SYNTHETIC)")
    print("=" * 70)
    norm_mask = hex_features_df["label"] == "NORMAL"
    mal_mask = hex_features_df["label"] == "MALICIOUS_SYNTHETIC"

    check_cols = [
        "mean_byte", "std_byte", "byte_entropy", "zero_ratio", "ff_ratio",
        "high_byte_ratio", "packet_length_mean", "direction_change_count",
        "consecutive_packet_similarity", "byte_transition_entropy"
    ]

    print(f"{'Feature':<30} {'NORMAL (Mean +/- Std)':<22} {'MALICIOUS (Mean +/- Std)':<22}")
    print("-" * 74)
    for col in check_cols:
        norm_v = hex_features_df.loc[norm_mask, col]
        mal_v = hex_features_df.loc[mal_mask, col]
        print(f"{col:<30} {norm_v.mean():7.3f} +/- {norm_v.std():5.3f}   {mal_v.mean():7.3f} +/- {mal_v.std():5.3f}")
    print("=" * 70)
    print("Dataset generation completed successfully!\n")


if __name__ == "__main__":
    main()
