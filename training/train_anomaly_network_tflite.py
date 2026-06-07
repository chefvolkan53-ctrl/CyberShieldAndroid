import argparse
import csv
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import average_precision_score, classification_report, precision_recall_curve, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
    "Src Port", "Dst Port", "Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet", "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max",
    "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "FWD Init Win Bytes",
    "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58, "ARP": 2054, "DNS": 17, "HTTP": 6, "SSHV2": 6, "FTP": 6}


def safe_float(value, default=0.0):
    try:
        if value is None or value == "":
            return default
        v = float(value)
        if math.isfinite(v):
            return v
    except Exception:
        pass
    return default


def flag(row, name):
    direct = safe_float(row.get(f"TCP {name} Flag"), -1)
    if direct >= 0:
        return direct
    text = (row.get("TCP Flags") or row.get("Info") or "").upper()
    return 1.0 if name.upper() in text else 0.0


def port(row, prefix):
    tcp = safe_float(row.get(f"TCP {prefix} Port"), -1)
    if tcp >= 0:
        return tcp
    udp = safe_float(row.get(f"UDP {prefix} Port"), -1)
    return max(0.0, udp)


def protocol_number(value):
    text = str(value or "").strip().upper()
    return PROTO.get(text, 6 if text in {"TLSV1.2", "TLSV1.3", "QUIC"} else 0)


def packet_features(row):
    src_port = port(row, "Source")
    dst_port = port(row, "Destination")
    proto = protocol_number(row.get("Protocol"))
    length = max(0.0, safe_float(row.get("Length") or row.get("frame length")))
    tcp_len = max(0.0, safe_float(row.get("TCP Length"), 0.0))
    udp_len = max(0.0, safe_float(row.get("UDP Length"), 0.0))
    payload = max(tcp_len, udp_len, max(0.0, length - 54.0))
    duration = max(1.0, safe_float(row.get("deltatime"), 0.0) * 1000.0)
    syn = flag(row, "SYN")
    ack = flag(row, "ACK")
    fin = flag(row, "FIN")
    rst = flag(row, "RST")
    psh = 1.0 if "PSH" in str(row.get("TCP Flags") or row.get("Info") or "").upper() else 0.0
    urg = flag(row, "URG")
    packet_count = 1.0
    byte_count = max(length, payload)
    pps = packet_count / max(duration / 1000.0, 0.001)
    bps = byte_count / max(duration / 1000.0, 0.001)
    x = np.zeros(len(FEATURE_COLUMNS), dtype=np.float32)
    values = {
        "Src Port": src_port, "Dst Port": dst_port, "Protocol": proto, "Flow Duration": duration,
        "Total Fwd Packet": 1, "Total Bwd packets": 0, "Total Length of Fwd Packet": byte_count,
        "Total Length of Bwd Packet": 0, "Fwd Packet Length Max": length, "Fwd Packet Length Min": length,
        "Fwd Packet Length Mean": length, "Fwd Packet Length Std": 0, "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 0, "Bwd Packet Length Std": 0,
        "Flow Bytes/s": bps, "Flow Packets/s": pps, "Flow IAT Mean": duration, "Flow IAT Std": 0,
        "Flow IAT Max": duration, "Flow IAT Min": duration, "Fwd IAT Total": duration, "Fwd IAT Mean": duration,
        "Fwd IAT Std": 0, "Fwd IAT Max": duration, "Fwd IAT Min": duration, "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0, "Bwd IAT Std": 0, "Bwd IAT Max": 0, "Bwd IAT Min": 0,
        "Fwd PSH Flags": psh, "Bwd PSH Flags": 0, "Fwd URG Flags": urg, "Bwd URG Flags": 0,
        "Fwd Header Length": 40 if proto == 6 else 28, "Bwd Header Length": 0, "Fwd Packets/s": pps,
        "Bwd Packets/s": 0, "Packet Length Min": length, "Packet Length Max": length,
        "Packet Length Mean": length, "Packet Length Std": 0, "Packet Length Variance": 0,
        "FIN Flag Count": fin, "SYN Flag Count": syn, "RST Flag Count": rst, "PSH Flag Count": psh,
        "ACK Flag Count": ack, "URG Flag Count": urg, "CWR Flag Count": 0, "ECE Flag Count": 1 if "ECN" in str(row.get("Info") or "").upper() else 0,
        "Down/Up Ratio": 0, "Average Packet Size": length, "Fwd Segment Size Avg": payload,
        "Bwd Segment Size Avg": 0, "Fwd Bytes/Bulk Avg": 0, "Fwd Packet/Bulk Avg": 0, "Fwd Bulk Rate Avg": 0,
        "Bwd Bytes/Bulk Avg": 0, "Bwd Packet/Bulk Avg": 0, "Bwd Bulk Rate Avg": 0,
        "Subflow Fwd Packets": 1, "Subflow Fwd Bytes": byte_count, "Subflow Bwd Packets": 0,
        "Subflow Bwd Bytes": 0, "FWD Init Win Bytes": safe_float(row.get("TCP Window Size"), 0),
        "Bwd Init Win Bytes": 0, "Fwd Act Data Pkts": 1 if payload > 0 else 0, "Fwd Seg Size Min": payload,
        "Active Mean": duration, "Active Std": 0, "Active Max": duration, "Active Min": duration,
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
    }
    for idx, col in enumerate(FEATURE_COLUMNS):
        x[idx] = values.get(col, 0.0)
    return x


def label_for_path(path: Path):
    parts = [p.lower() for p in path.parts]
    if "benign" in parts:
        return 0
    return 1


def read_rows(path: Path, label: int, max_rows: int, seed: int):
    rng = np.random.default_rng(seed)
    rows = []
    try:
        total = sum(1 for _ in path.open("rb")) - 1
        keep_probability = min(1.0, max_rows / max(1, total))
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
            sample = f.read(8192)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except Exception:
                dialect = csv.excel
            reader = csv.DictReader(f, dialect=dialect)
            for row in reader:
                if len(rows) < max_rows and (keep_probability >= 1.0 or rng.random() <= keep_probability):
                    rows.append(packet_features(row))
    except Exception as exc:
        print(f"skip {path}: {exc}")
    if not rows:
        return np.zeros((0, len(FEATURE_COLUMNS)), dtype=np.float32), np.zeros((0,), dtype=np.float32)
    return np.vstack(rows).astype(np.float32), np.full((len(rows),), label, dtype=np.float32)


def threshold_for_recall(y_true, y_score, target_recall=0.92):
    precision, recall, thresholds = precision_recall_curve(y_true, y_score)
    candidates = []
    for idx, threshold in enumerate(thresholds):
        if recall[idx] >= target_recall:
            candidates.append((precision[idx], recall[idx], float(threshold)))
    if not candidates:
        return 0.5
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def class_metric(report, label, metric):
    for key in (str(label), f"{float(label):.1f}", int(label) if isinstance(label, str) and label.isdigit() else label):
        if key in report:
            return float(report[key].get(metric, 0.0))
    return 0.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=r"C:\Users\Monster\Desktop\anomali\Dataset-Ready (Use This)")
    parser.add_argument("--output-dir", default="training/outputs/anomaly_network")
    parser.add_argument("--max-rows-per-file", type=int, default=45_000)
    parser.add_argument("--epochs", type=int, default=14)
    parser.add_argument("--seed", type=int, default=53)
    args = parser.parse_args()

    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)
    data_dir = Path(args.data_dir)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    xs, ys, file_rows = [], [], []
    for idx, path in enumerate(sorted(data_dir.rglob("*.csv"))):
        label = label_for_path(path)
        x, y = read_rows(path, label, args.max_rows_per_file, args.seed + idx)
        if len(y) == 0:
            continue
        xs.append(x)
        ys.append(y)
        file_rows.append({"file": str(path), "rows": int(len(y)), "label": int(label)})

    x_all = np.vstack(xs)
    y_all = np.concatenate(ys)
    x_train, x_val, y_train, y_val = train_test_split(
        x_all, y_all, test_size=0.22, random_state=args.seed, stratify=y_all
    )
    scaler = StandardScaler()
    x_train = scaler.fit_transform(x_train).astype(np.float32)
    x_val = scaler.transform(x_val).astype(np.float32)

    class_weight = {
        0: float(len(y_train) / (2 * max(1, np.sum(y_train == 0)))),
        1: float(len(y_train) / (2 * max(1, np.sum(y_train == 1)))),
    }
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(len(FEATURE_COLUMNS),), name="network_flow_features"),
        tf.keras.layers.Dense(128, activation="relu"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.18),
        tf.keras.layers.Dense(64, activation="relu"),
        tf.keras.layers.Dropout(0.12),
        tf.keras.layers.Dense(24, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid", name="attack_probability"),
    ])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=[tf.keras.metrics.AUC(name="auc"), tf.keras.metrics.AUC(curve="PR", name="pr_auc")],
    )
    history = model.fit(
        x_train, y_train,
        validation_data=(x_val, y_val),
        epochs=args.epochs,
        batch_size=1024,
        class_weight=class_weight,
        callbacks=[tf.keras.callbacks.EarlyStopping(monitor="val_pr_auc", mode="max", patience=3, restore_best_weights=True)],
        verbose=2,
    )
    scores = model.predict(x_val, batch_size=4096, verbose=0).reshape(-1)
    threshold = threshold_for_recall(y_val, scores, 0.92)
    pred = (scores >= threshold).astype(int)
    report = classification_report(y_val, pred, output_dict=True, zero_division=0)

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite = converter.convert()
    model_path = out / "network_anomaly_attack_detector.tflite"
    model_path.write_bytes(tflite)
    model.save(out / "network_anomaly_attack_detector.keras")

    metadata = {
        "model_type": "TFLite binary network anomaly attack detector",
        "model_id": "network_attack",
        "model_file": model_path.name,
        "input_name": "network_flow_features",
        "input_shape": [1, len(FEATURE_COLUMNS)],
        "feature_strategy": "Packet CSV rows mapped to CyberShield 79 flow-compatible features. IP/timestamp identifiers excluded.",
        "feature_columns": FEATURE_COLUMNS,
        "scaler_mean": scaler.mean_.astype(float).tolist(),
        "scaler_scale": scaler.scale_.astype(float).tolist(),
        "recommended_attack_threshold": threshold,
        "output": {"name": "attack_probability", "shape": [1, 1]},
        "training_files": file_rows,
        "note": "This replaces the older multiclass network detector with a binary alert-safe model. Runtime still depends on Android VPN flow feature quality.",
    }
    (out / "network_labels.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    summary = {
        "model_id": "network_attack",
        "train_rows": int(len(y_train)),
        "val_rows": int(len(y_val)),
        "input_size": len(FEATURE_COLUMNS),
        "threshold": threshold,
        "roc_auc": float(roc_auc_score(y_val, scores)),
        "pr_auc": float(average_precision_score(y_val, scores)),
        "accuracy": float(report["accuracy"]),
        "attack_precision": class_metric(report, 1, "precision"),
        "attack_recall": class_metric(report, 1, "recall"),
        "tflite_size": model_path.stat().st_size,
        "history": {k: [float(v) for v in vals] for k, vals in history.history.items()},
    }
    (out / "network_anomaly_attack_training_report.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
