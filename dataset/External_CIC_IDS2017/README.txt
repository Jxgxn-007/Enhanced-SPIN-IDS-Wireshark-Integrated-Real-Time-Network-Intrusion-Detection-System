================================================================================
SPIN-IDS PHASE 4: EXTERNAL BENCHMARK DATASET (CIC-IDS2017)
================================================================================

1. OVERVIEW
-----------
This directory is designated for the genuine, labelled external benchmark dataset
derived from the Canadian Institute for Cybersecurity (UNB) CIC-IDS2017 project.

Official Benchmark Source:
https://www.unb.ca/cic/datasets/ids-2017.html

Direct Data Repository:
http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/

2. DIRECTORY STRUCTURE
----------------------
dataset/External_CIC_IDS2017/
    ├── raw/
    │   ├── benign/       <- Storage for genuine benign PCAPs / extracted flows
    │   └── malicious/    <- Storage for genuine attack PCAPs (DoS, PortScan, Brute Force)
    ├── processed/        <- Generated windows.csv, flow_manifest.csv, and split CSVs
    ├── manifest.json     <- Dataset metadata, hash records, and configuration
    ├── dataset_audit.txt <- Comprehensive audit of files, flows, windows, and leakage
    └── README.txt        <- This specification and guide

3. REQUIRED SUBSET FOR SPIN-IDS
-------------------------------
To avoid downloading the entire 50+ GB dataset, a targeted subset containing:
- NORMAL: Benign traffic flows
- MALICIOUS: At least two distinct attack categories from:
    1. DoS (e.g. DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest)
    2. PortScan
    3. Brute Force (e.g. FTP-Patator, SSH-Patator)

Recommended PCAP Candidates & Timings:
- Wednesday-workingHours.pcap (Contains Benign + DoS Slowloris, Slowhttptest, Hulk, GoldenEye)
  Timing: 09:00 - 12:00 (Wednesday, July 5, 2017)
- Friday-WorkingHours.pcap (Contains Benign + PortScan 13:55-15:29, DDoS 15:56-16:16)
  Timing: 13:00 - 17:00 (Friday, July 7, 2017)
- Tuesday-WorkingHours.pcap (Contains Benign + FTP-Patator 09:20-10:20, SSH-Patator 14:00-15:00)
  Timing: 09:00 - 15:30 (Tuesday, July 4, 2017)

Labelled Flow Ground Truth:
- GeneratedLabelledFlows.zip: Contains CSV files mapping flow 5-tuples and timestamps
  to ground truth attack classifications.

4. LABEL MAPPING SPECIFICATION
------------------------------
- BENIGN                    -> NORMAL (label = 0)
- DoS Hulk                  -> MALICIOUS (label = 1, attack_category = "DoS Hulk")
- DoS GoldenEye             -> MALICIOUS (label = 1, attack_category = "DoS GoldenEye")
- DoS Slowloris             -> MALICIOUS (label = 1, attack_category = "DoS Slowloris")
- DoS Slowhttptest          -> MALICIOUS (label = 1, attack_category = "DoS Slowhttptest")
- PortScan                  -> MALICIOUS (label = 1, attack_category = "PortScan")
- FTP-Patator               -> MALICIOUS (label = 1, attack_category = "FTP-Patator")
- SSH-Patator               -> MALICIOUS (label = 1, attack_category = "SSH-Patator")

Rule: An entire day's PCAP is NOT treated as homogenous malicious traffic. Official flow CSVs
and attack start/stop timestamps are strictly cross-referenced to establish packet ground truth.

5. SPIN-IDS 27x27x3 IMAGE REPRESENTATION
----------------------------------------
- Flow Grouping: Canonical bidirectional flow key:
  protocol + min(src_ip, dst_ip) + max(src_ip, dst_ip) + min(src_port, dst_port) + max(src_port, dst_port)
- Flow Direction: First seen packet defines forward direction (0). Reverse packets marked (1).
- IP Privacy Masking: Raw IP addresses are masked (zeroed) in the byte payload to prevent IP memorization.
- Packet Layout (243 bytes):
  Byte 0:    Direction marker (0 or 1)
  Byte 1:    Sequential index (0 to 8)
  Bytes 2-3: Packet length (16-bit uint)
  Bytes 4-242: Masked packet bytes (zero-padded if < 239 payload bytes)
- Window Layout: 9 sequential packets x 243 bytes = 2187 bytes = 27 x 27 x 3 RGB image.

6. LEAKAGE PREVENTION GUARANTEE
-------------------------------
Splits must be executed at the flow/conversation level:
- train ∩ validation = 0
- train ∩ test = 0
- validation ∩ test = 0
No window originating from the same flow may appear in multiple partitions.
