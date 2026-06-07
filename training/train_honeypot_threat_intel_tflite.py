import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import classification_report, precision_recall_curve
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


FEATURE_ORDER = [
    "dst_port_norm",
    "is_ssh_22",
    "is_telnet_23",
    "is_smb_445",
    "is_mssql_1433",
    "is_vnc_5900",
    "is_known_honeypot_port",
    "port_attack_prior",
    "port_attack_count_scaled",
    "global_attack_count_scaled",
    "unique_ip_count_scaled",
    "honeypot_cowrie_scaled",
    "honeypot_dionaea_scaled",
    "honeypot_heralding_scaled",
    "honeypot_honeytrap_scaled",
    "honeypot_tanner_scaled",
    "honeypot_mailoney_scaled",
    "flow_packet_count_scaled",
    "flow_byte_count_scaled",
    "flow_packets_per_second_scaled",
    "flow_bytes_per_second_scaled",
    "flow_duration_scaled",
    "tcp_flag_syn_ratio",
    "tcp_flag_rst_ratio",
    "tcp_flag_ack_ratio",
    "dns_flow_hint",
    "doh_flow_hint",
    "tcp_flow_hint",
    "udp_flow_hint",
    "bruteforce_scan_hint",
    "high_unique_ip_hint",
    "bias",
]

PORT_COLUMNS = {
    22: "Attack_counts_22",
    23: "Attack_counts_23",
    445: "Attack_counts_445",
    1433: "Attack_counts_1433",
    5900: "Attack_counts_5900",
}

HONEYPOT_COLUMNS = [
    "Attack_counts_Cowrie",
    "Attack_counts_Dionaea",
    "Attack_counts_Heralding",
    "Attack_counts_Honeytrap",
    "Attack_counts_Tanner",
    "Attack_counts_Mailoney",
]

BENIGN_PORTS = [53, 80, 123, 443, 853, 993, 995, 5228, 5229, 5230, 8080]


def read_csv(path):
    return pd.read_csv(path)


def prep_timestamps(df):
    out = df.copy()
    out["ts"] = pd.to_datetime(out["Timestamp"], errors="coerce", utc=True)
    return out.dropna(subset=["ts"])


def safe_float(value):
    try:
        if pd.isna(value):
            return 0.0
        return float(value)
    except Exception:
        return 0.0


def log_scale(value, denom):
    return math.log1p(max(0.0, float(value))) / math.log1p(max(1.0, float(denom)))


def base_features(port, port_count, global_count, unique_ips, honeypots, maxima, benign=False):
    x = np.zeros(len(FEATURE_ORDER), dtype=np.float32)
    port_prior = maxima["port_totals"].get(str(port), 0.0) / max(1.0, maxima["max_port_total"])
    x[0] = min(1.0, port / 65535.0)
    x[1] = 1.0 if port == 22 else 0.0
    x[2] = 1.0 if port == 23 else 0.0
    x[3] = 1.0 if port == 445 else 0.0
    x[4] = 1.0 if port == 1433 else 0.0
    x[5] = 1.0 if port == 5900 else 0.0
    x[6] = 1.0 if port in PORT_COLUMNS else 0.0
    x[7] = port_prior
    x[8] = log_scale(port_count, maxima["max_port_window"])
    x[9] = log_scale(global_count, maxima["max_global_attack"])
    x[10] = min(1.0, unique_ips / max(1.0, maxima["max_unique_ips"]))
    for idx, name in enumerate(HONEYPOT_COLUMNS, start=11):
        x[idx] = log_scale(honeypots.get(name, 0.0), maxima["honeypot_max"].get(name, 1.0))
    if benign:
        flow_packets = max(1.0, port_count)
        flow_bytes = flow_packets * 320.0
        pps = min(12.0, flow_packets / 6.0)
        bps = pps * 320.0
        duration = 20_000.0
        syn_ratio = 0.05
        rst_ratio = 0.01
        ack_ratio = 0.60
    else:
        flow_packets = max(1.0, min(4000.0, port_count / 2.0))
        flow_bytes = flow_packets * (80.0 if port in {22, 23, 445, 1433, 5900} else 450.0)
        pps = max(1.0, min(800.0, port_count / 30.0))
        bps = pps * (80.0 if port in {22, 23, 445, 1433, 5900} else 450.0)
        duration = max(500.0, min(60_000.0, 30_000.0 / max(1.0, pps / 25.0)))
        syn_ratio = 0.65 if port in {22, 23, 445, 1433, 5900} else 0.10
        rst_ratio = 0.15 if port in {22, 23, 445, 1433, 5900} else 0.03
        ack_ratio = 0.20 if port in {22, 23, 445, 1433, 5900} else 0.70
    x[17] = log_scale(flow_packets, 4000.0)
    x[18] = log_scale(flow_bytes, 320000.0)
    x[19] = log_scale(pps, 800.0)
    x[20] = log_scale(bps, 64000.0)
    x[21] = min(1.0, duration / 60_000.0)
    x[22] = syn_ratio
    x[23] = rst_ratio
    x[24] = ack_ratio
    x[25] = 1.0 if port == 53 else 0.0
    x[26] = 1.0 if port in {443, 853} else 0.0
    x[27] = 1.0 if port not in {53, 123} else 0.0
    x[28] = 1.0 if port in {53, 123} else 0.0
    x[29] = min(1.0, 0.55 * x[6] + 0.35 * x[22] + 0.25 * x[23] + 0.25 * x[8])
    x[30] = 1.0 if unique_ips >= maxima["unique_p90"] else 0.0
    x[31] = 1.0
    return x


def make_dataset(data_dir):
    data_dir = Path(data_dir)
    ports = prep_timestamps(read_csv(data_dir / "merged_ports_new.csv")).fillna(0)
    honeypots = prep_timestamps(read_csv(data_dir / "merged_honeypots_new.csv")).fillna(0)
    allstats = prep_timestamps(read_csv(data_dir / "out_all_unique_and_attacks_all_new.csv")).fillna(0)
    merged = ports.merge(honeypots, on="ts", suffixes=("_port", "_honeypot")).merge(allstats, on="ts", suffixes=("", "_all"))

    port_totals = {str(port): float(ports[col].fillna(0).sum()) for port, col in PORT_COLUMNS.items()}
    port_p70 = {port: float(ports[col].fillna(0).quantile(0.70)) for port, col in PORT_COLUMNS.items()}
    port_p90 = {port: float(ports[col].fillna(0).quantile(0.90)) for port, col in PORT_COLUMNS.items()}
    maxima = {
        "port_totals": port_totals,
        "max_port_total": max(port_totals.values()),
        "max_port_window": max(float(ports[col].fillna(0).max()) for col in PORT_COLUMNS.values()),
        "max_global_attack": float(allstats["Attack_counts"].max()),
        "max_unique_ips": float(allstats["Unique_ips"].max()),
        "unique_p90": float(allstats["Unique_ips"].quantile(0.90)),
        "honeypot_max": {name: float(honeypots[name].fillna(0).max()) for name in HONEYPOT_COLUMNS},
        "port_p70": {str(k): v for k, v in port_p70.items()},
        "port_p90": {str(k): v for k, v in port_p90.items()},
    }

    rows = []
    labels = []
    for _, row in merged.iterrows():
        global_count = safe_float(row.get("Attack_counts"))
        unique_ips = safe_float(row.get("Unique_ips"))
        hp = {name: safe_float(row.get(name)) for name in HONEYPOT_COLUMNS}
        for port, col in PORT_COLUMNS.items():
            port_count = safe_float(row.get(col))
            x = base_features(port, port_count, global_count, unique_ips, hp, maxima, benign=False)
            # Risk-intelligence label: high exposure service and current activity above normal.
            label = 1 if (
                port_count >= port_p70[port]
                or port_count >= port_p90[port] * 0.75
                or global_count >= maxima["max_global_attack"] * 0.55
                or unique_ips >= maxima["unique_p90"] and port_count >= port_p70[port] * 0.50
            ) else 0
            rows.append(x)
            labels.append(label)

        for port in BENIGN_PORTS:
            port_count = max(0.0, np.random.normal(loc=8.0, scale=4.0))
            x = base_features(port, port_count, global_count * 0.02, min(unique_ips, 8.0), hp, maxima, benign=True)
            rows.append(x)
            labels.append(0)

    x = np.vstack(rows).astype(np.float32)
    y = np.asarray(labels, dtype=np.float32)
    return x, y, maxima


def build_model(input_size):
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_size,)),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dropout(0.10),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
                  loss="binary_crossentropy",
                  metrics=["accuracy", tf.keras.metrics.Recall(name="recall"), tf.keras.metrics.Precision(name="precision")])
    return model


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=r"C:\Users\Monster\Desktop\Honeypots")
    parser.add_argument("--output-dir", default="training/outputs/honeypot_threat_intel")
    parser.add_argument("--epochs", type=int, default=30)
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    x, y, maxima = make_dataset(args.data_dir)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.20, random_state=53, stratify=y)

    scaler = StandardScaler()
    x_train_s = scaler.fit_transform(x_train).astype(np.float32)
    x_test_s = scaler.transform(x_test).astype(np.float32)

    model = build_model(x.shape[1])
    weights = {0: 1.0, 1: max(1.0, (len(y_train) - y_train.sum()) / max(1.0, y_train.sum()))}
    history = model.fit(
        x_train_s, y_train,
        validation_split=0.15,
        epochs=args.epochs,
        batch_size=256,
        class_weight=weights,
        verbose=2,
    )

    probs = model.predict(x_test_s, verbose=0).reshape(-1)
    precision, recall, thresholds = precision_recall_curve(y_test, probs)
    candidates = []
    for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
        if r >= 0.90:
            candidates.append((p, r, t))
    if candidates:
        best = max(candidates, key=lambda v: (v[0], v[2]))
        threshold = float(best[2])
    else:
        threshold = 0.85
    pred = (probs >= threshold).astype(int)
    report = classification_report(y_test.astype(int), pred, output_dict=True, zero_division=0)

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite = converter.convert()
    (out / "honeypot_threat_intel_detector.tflite").write_bytes(tflite)
    model.save(out / "honeypot_threat_intel_detector.keras")

    metadata = {
        "model_id": "honeypot_threat_intel",
        "input_size": len(FEATURE_ORDER),
        "feature_columns": FEATURE_ORDER,
        "transform": "standard_scaler",
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
        "recommended_threshold": threshold,
        "role": "supporting threat-intelligence risk scorer; does not make destructive decisions alone",
        "source_data": str(Path(args.data_dir)),
        "port_priors": maxima["port_totals"],
        "port_p70": maxima["port_p70"],
        "port_p90": maxima["port_p90"],
    }
    (out / "honeypot_threat_intel_feature_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    summary = {
        "samples": int(len(y)),
        "positive_samples": int(y.sum()),
        "negative_samples": int(len(y) - y.sum()),
        "threshold": threshold,
        "accuracy": report.get("accuracy", 0.0),
        "attack_precision": report.get("1", {}).get("precision", 0.0),
        "attack_recall": report.get("1", {}).get("recall", 0.0),
        "classification_report": report,
        "history_last": {k: float(v[-1]) for k, v in history.history.items()},
        "note": "Labels are derived from honeypot activity quantiles and benign synthetic platform traffic. Use as risk support, not as standalone blocking proof.",
    }
    (out / "honeypot_threat_intel_training_report.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
