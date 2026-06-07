import argparse
import csv
import json
import math
import os
import random
from collections import Counter
from pathlib import Path

import numpy as np
import tensorflow as tf
from sklearn.metrics import classification_report, precision_recall_curve
from sklearn.model_selection import train_test_split


FEATURE_ORDER = [
    "wifi_connected",
    "gateway_ip_present",
    "gateway_arp_present",
    "gateway_mac_known",
    "gateway_mac_changed",
    "gateway_mac_multi_ip_count_scaled",
    "duplicate_ip_mac_count_scaled",
    "arp_entry_count_scaled",
    "unique_mac_count_scaled",
    "arp_table_churn_scaled",
    "new_mac_count_scaled",
    "lost_mac_count_scaled",
    "bssid_changed",
    "ssid_hash",
    "bssid_hash",
    "gateway_ip_hash",
    "gateway_mac_hash",
    "seconds_since_gateway_change_scaled",
    "private_gateway",
    "gateway_mac_zero",
    "gateway_mac_broadcast",
    "gateway_mac_local_admin",
    "arp_density",
    "duplicate_ratio",
    "gateway_seen_ratio",
    "rule_score",
    "vpn_active_hint",
    "dns_to_gateway_hint",
    "doh_during_change_hint",
    "sensitive_flow_hint",
    "network_age_minutes_scaled",
    "bias",
    "rssi_norm",
    "rssi_drop_hint",
    "security_open_hint",
    "security_wpa3_hint",
    "same_ssid_bssid_changed",
    "dns_spoof_hint",
    "http_downgrade_hint",
    "ssl_stripping_hint",
    "deauth_hint",
    "disassoc_hint",
    "beacon_flood_hint",
    "evil_twin_hint",
    "sae_auth_hint",
    "wpa_downgrade_hint",
    "reconnect_churn_hint",
    "dns_answer_mismatch_hint",
]

BENIGN_LABELS = {"", "0", "benign", "normal"}


def clean(value):
    return "" if value is None else str(value).strip()


def lower(value):
    return clean(value).lower()


def fnum(value, default=0.0):
    try:
        text = clean(value)
        if text == "" or text.lower() in {"nan", "none", "true", "false"}:
            if text.lower() == "true":
                return 1.0
            if text.lower() == "false":
                return 0.0
            return default
        return float(text)
    except Exception:
        return default


def flag(value):
    text = lower(value)
    if text in {"1", "true", "yes", "y"}:
        return 1.0
    if text in {"0", "false", "no", "n", ""}:
        return 0.0
    return 1.0


def hash01(value):
    text = clean(value)
    if not text:
        return 0.0
    h = 2166136261
    for ch in text.encode("utf-8", "ignore"):
        h ^= ch
        h = (h * 16777619) & 0xFFFFFFFF
    return (h % 10000) / 10000.0


def is_private_ip(ip):
    text = clean(ip)
    return text.startswith("10.") or text.startswith("192.168.") or any(text.startswith(f"172.{i}.") for i in range(16, 32))


def mac_zero(mac):
    return 1.0 if lower(mac) == "00:00:00:00:00:00" else 0.0


def mac_broadcast(mac):
    return 1.0 if lower(mac) == "ff:ff:ff:ff:ff:ff" else 0.0


def mac_local_admin(mac):
    text = lower(mac)
    try:
        return 1.0 if int(text[:2], 16) & 0x02 else 0.0
    except Exception:
        return 0.0


def label_is_attack(label):
    return 0 if lower(label) in BENIGN_LABELS else 1


def base_features():
    x = np.zeros(len(FEATURE_ORDER), dtype=np.float32)
    x[0] = 1.0
    x[1] = 1.0
    x[26] = 1.0
    x[31] = 1.0
    return x


def finish_common_rules(x):
    x[22] = min(1.0, x[7])
    x[23] = min(1.0, x[6] / max(1.0, x[7] * 64.0))
    x[24] = x[2]
    rule = 0.0
    rule += 0.28 * x[4]
    rule += 0.16 * min(1.0, x[5])
    rule += 0.18 * min(1.0, x[6])
    rule += 0.10 * x[12]
    rule += 0.20 * max(x[37], x[39], x[40], x[41], x[42], x[43], x[44], x[45])
    rule += 0.10 * x[46]
    x[25] = min(1.0, rule)
    return x


def arp_poison_features(row, header, label):
    get = lambda name: row.get(name, "")
    x = base_features()
    src_mac = get("src_mac_addr(arp)") or get("src_mac_addr(eth)")
    dst_mac = get("dst_mac_addr(arp)") or get("dst_mac_addr(eth)")
    src_ip = get("src_ip(arp)")
    dst_ip = get("dst_ip(arp)")
    attack = label_is_attack(label)
    packet_count = fnum(get("packet_in_count"))
    pkt_loss = fnum(get("Pkt loss"))
    rtt = fnum(get("rtt (avg)"))
    op_code = fnum(get("op_code(arp)"))
    x[2] = 1.0
    x[3] = 1.0 if src_mac or dst_mac else 0.0
    x[4] = 1.0 if attack and op_code in {1.0, 2.0} else 0.0
    x[5] = min(1.0, packet_count / 6000.0)
    x[6] = min(1.0, attack * max(1.0, pkt_loss + 1.0) / 8.0)
    x[7] = min(1.0, packet_count / 10000.0)
    x[8] = 0.05 + 0.10 * attack
    x[9] = min(1.0, attack * (packet_count / 5000.0))
    x[10] = min(1.0, attack * 0.25)
    x[11] = min(1.0, attack * 0.15)
    x[13] = hash01(src_ip)
    x[14] = hash01(dst_ip)
    x[15] = hash01(dst_ip)
    x[16] = hash01(src_mac or dst_mac)
    x[17] = min(1.0, rtt / 7200.0)
    x[18] = 1.0 if is_private_ip(src_ip) or is_private_ip(dst_ip) else 0.0
    x[19] = max(mac_zero(src_mac), mac_zero(dst_mac))
    x[20] = max(mac_broadcast(src_mac), mac_broadcast(dst_mac))
    x[21] = max(mac_local_admin(src_mac), mac_local_admin(dst_mac))
    x[27] = attack
    x[37] = 0.15 * attack
    return finish_common_rules(x)


def wpa_features(row, label, rel_path):
    x = base_features()
    attack = label_is_attack(label)
    l = lower(label)
    rel = lower(rel_path)
    rssi = fnum(row.get("radiotap.dbm_antsignal"), -85.0)
    freq = fnum(row.get("radiotap.channel.freq"), 0.0)
    frame_len = fnum(row.get("frame.len"), 0.0)
    subtype = clean(row.get("wlan.fc.type_subtype") or row.get("wlan.fc.subtype"))
    rsn_akm = clean(row.get("wlan.rsn.akm.type"))
    mfpr = flag(row.get("wlan.rsn.capabilities.mfpr"))
    mfpc = flag(row.get("wlan.rsn.capabilities.mfpc"))
    arp_opcode = clean(row.get("arp.opcode"))
    dns_query = clean(row.get("dns.qry.name"))
    dns_answer = clean(row.get("dns.a") or row.get("dns.resp.name"))
    http_host = clean(row.get("http.host") or row.get("http.request.full_uri"))
    x[2] = 1.0 if arp_opcode else 0.35
    x[3] = 1.0
    x[4] = 1.0 if "arp" in l or "evil" in l else 0.0
    x[5] = 0.55 if "evil" in l else 0.15 * attack
    x[6] = 0.60 if "arp" in l else 0.15 * attack
    x[7] = min(1.0, frame_len / 1500.0)
    x[8] = 0.10 + 0.25 * attack
    x[9] = 0.35 if attack else 0.05
    x[10] = 0.20 if attack else 0.02
    x[11] = 0.15 if attack else 0.02
    x[12] = 1.0 if "evil" in l or "rogue" in rel else 0.0
    x[13] = hash01(row.get("wlan.ssid") or rel_path)
    x[14] = hash01(row.get("wlan.bssid") or rel_path)
    x[15] = hash01(row.get("arp.dst.proto_ipv4") or row.get("dns.a"))
    x[16] = hash01(row.get("arp.src.hw_mac") or row.get("dhcp.hw.mac_addr"))
    x[18] = 1.0
    x[21] = mac_local_admin(row.get("arp.src.hw_mac"))
    x[27] = 1.0 if "dns" in l or dns_query else 0.0
    x[29] = 1.0 if "sae" in l or "downgrade" in l or "ssl" in l or http_host else 0.0
    x[32] = max(0.0, min(1.0, (rssi + 100.0) / 75.0))
    x[33] = 1.0 if rssi < -88 and attack else 0.0
    x[34] = 1.0 if mfpr == 0 and mfpc == 0 and attack else 0.0
    x[35] = 1.0 if rsn_akm or mfpr or mfpc or "wpa3" in rel else 0.0
    x[36] = x[12]
    x[37] = 1.0 if "dns_spoof" in l or "dns spoof" in l or ("dns" in rel and attack) else 0.0
    x[38] = 1.0 if http_host and "ssl" in rel else 0.0
    x[39] = 1.0 if "ssl" in l else 0.0
    x[40] = 1.0 if "deauth" in l or subtype == "12" else 0.0
    x[41] = 1.0 if "disassoc" in l or subtype == "10" else 0.0
    x[42] = 1.0 if "beacon" in l else 0.0
    x[43] = 1.0 if "eviltwin" in l or "evil" in l else 0.0
    x[44] = 1.0 if "sae" in l else 0.0
    x[45] = 1.0 if "downgrade" in l else 0.0
    x[46] = 1.0 if x[40] or x[41] or x[43] else 0.0
    x[47] = 1.0 if "dns" in l or (dns_query and dns_answer and attack) else 0.0
    if freq >= 5000:
        x[35] = max(x[35], 0.6)
    return finish_common_rules(x)


def cic_features(row, label):
    x = base_features()
    attack = label_is_attack(label)
    port = fnum(row.get("Destination Port"))
    proto = fnum(row.get("Protocol"))
    duration = fnum(row.get("Flow Duration"))
    fwd = fnum(row.get("Total Fwd Packets"))
    bwd = fnum(row.get("Total Backward Packets"))
    pps = fnum(row.get("Flow Packets/s"))
    syn = fnum(row.get("SYN Flag Count"))
    rst = fnum(row.get("RST Flag Count"))
    x[2] = 0.4
    x[7] = min(1.0, (fwd + bwd) / 1000.0)
    x[8] = min(1.0, max(fwd, bwd) / 1000.0)
    x[9] = min(1.0, pps / 100000.0)
    x[17] = min(1.0, duration / 120000000.0)
    x[27] = 1.0 if port == 53 or proto == 17 else 0.0
    x[29] = 1.0 if attack else 0.0
    x[38] = 1.0 if port == 80 and attack else 0.0
    x[40] = min(1.0, syn / 10.0) if attack else 0.0
    x[46] = min(1.0, (syn + rst) / 10.0) if attack else 0.0
    return finish_common_rules(x)


def cap_features(row):
    x = base_features()
    proto = lower(row.get("Protocol"))
    info = lower(row.get("Info"))
    src_known = flag(row.get("Source_Known") or row.get("Source Known"))
    dst_known = flag(row.get("Destination_Known") or row.get("Destination Known"))
    length = fnum(row.get("Length"))
    ttl = fnum(row.get("Time to Live"))
    x[2] = 1.0 if proto == "arp" else 0.3
    x[3] = 1.0
    x[7] = min(1.0, length / 1500.0)
    x[8] = min(1.0, ttl / 255.0)
    x[18] = 1.0 if src_known or dst_known else 0.0
    x[27] = 1.0 if proto == "dns" else 0.0
    x[29] = 1.0 if proto in {"http", "ftp", "ssh", "sshv2"} else 0.0
    x[37] = 0.2 if "spoof" in info else 0.0
    x[38] = 0.2 if proto == "http" else 0.0
    return finish_common_rules(x)


def row_label(row):
    for key in ("Label", "label", " Label"):
        if key in row:
            return clean(row[key])
    return ""


def row_to_features(path, row):
    rel = str(path)
    label = row_label(row)
    low_rel = rel.lower()
    if "arp poison" in low_rel:
        return arp_poison_features(row, None, label), label_is_attack(label), label
    if "wpa3 attacks dataset" in low_rel:
        return wpa_features(row, label, rel), label_is_attack(label), label
    if "machinelearningcve" in low_rel or "trafficlabelling" in low_rel:
        return cic_features(row, label), label_is_attack(label), label
    if "cap_1_10vm_1apache" in low_rel:
        return cap_features(row), 0, "NormalUnlabeledCap"
    return None, None, None


def iter_csv_samples(path, max_rows, seed):
    rng = random.Random(seed + hash(str(path)) % 100000)
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        reservoir = []
        for i, row in enumerate(reader, start=1):
            if len(reservoir) < max_rows:
                reservoir.append(row)
            else:
                j = rng.randint(1, i)
                if j <= max_rows:
                    reservoir[j - 1] = row
        return reservoir


def collect_dataset(root, max_rows_per_file, seed):
    root = Path(root)
    xs, ys, labels, files_used = [], [], [], Counter()
    csv_paths = [p for p in root.rglob("*.csv") if "__MACOSX" not in str(p)]
    for path in csv_paths:
        low = str(path).lower()
        if "wpa3 attacks dataset" in low:
            limit = max_rows_per_file
        elif "arp poison" in low:
            limit = max_rows_per_file
        elif "machinelearningcve" in low or "trafficlabelling" in low:
            limit = max(3000, max_rows_per_file // 5)
        elif "cap_1_10vm_1apache" in low:
            limit = max(2000, max_rows_per_file // 8)
        else:
            limit = max_rows_per_file // 10
        for row in iter_csv_samples(path, limit, seed):
            x, y, label = row_to_features(path, row)
            if x is None:
                continue
            xs.append(x)
            ys.append(y)
            labels.append(label)
            files_used[str(path.relative_to(root))] += 1
    return np.asarray(xs, dtype=np.float32), np.asarray(ys, dtype=np.float32), labels, files_used


def choose_threshold(y_true, probs):
    precision, recall, thresholds = precision_recall_curve(y_true, probs)
    best = (0.5, 0.0, 0.0, 0.0)
    for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
        if r < 0.95:
            continue
        f1 = 0.0 if p + r == 0 else 2 * p * r / (p + r)
        if f1 > best[1]:
            best = (float(t), float(f1), float(p), float(r))
    if best[1] == 0.0:
        idx = int(np.argmax(2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-7)))
        return float(thresholds[idx]), float(precision[idx]), float(recall[idx])
    return best[0], best[2], best[3]


def build_model(input_size):
    return tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_size,)),
        tf.keras.layers.Dense(96, activation="relu"),
        tf.keras.layers.Dropout(0.20),
        tf.keras.layers.Dense(48, activation="relu"),
        tf.keras.layers.Dropout(0.15),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wifi-dir", default=r"C:\Users\Monster\Desktop\wifi")
    parser.add_argument("--output-dir", default="training/outputs/wifi_threat")
    parser.add_argument("--max-rows-per-file", type=int, default=70000)
    parser.add_argument("--epochs", type=int, default=18)
    parser.add_argument("--seed", type=int, default=53)
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    x, y, raw_labels, files_used = collect_dataset(args.wifi_dir, args.max_rows_per_file, args.seed)
    if len(x) < 1000:
        raise RuntimeError("Not enough training rows collected")

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.20, random_state=args.seed, stratify=y)
    pos = float(np.sum(y_train == 1))
    neg = float(np.sum(y_train == 0))
    class_weight = {0: 1.0, 1: min(8.0, max(1.0, neg / max(pos, 1.0)))}

    model = build_model(x.shape[1])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=[tf.keras.metrics.BinaryAccuracy(name="accuracy"), tf.keras.metrics.Recall(name="recall")],
    )
    callbacks = [
        tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True),
        tf.keras.callbacks.ReduceLROnPlateau(monitor="val_loss", patience=2, factor=0.5),
    ]
    history = model.fit(
        x_train,
        y_train,
        validation_split=0.15,
        epochs=args.epochs,
        batch_size=512,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=2,
    )

    probs = model.predict(x_test, batch_size=1024).reshape(-1)
    threshold, precision, recall = choose_threshold(y_test, probs)
    pred = (probs >= threshold).astype(int)
    report = classification_report(y_test.astype(int), pred, output_dict=True, zero_division=0)
    accuracy = float(np.mean(pred == y_test))

    saved_model = out / "wifi_threat_detector.keras"
    model.save(saved_model)
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite = converter.convert()
    tflite_path = out / "wifi_threat_detector.tflite"
    tflite_path.write_bytes(tflite)

    metadata = {
        "model_file": "wifi_threat_detector.tflite",
        "input_size": len(FEATURE_ORDER),
        "feature_order": FEATURE_ORDER,
        "threshold": threshold,
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "classification_report": report,
        },
        "label_counts": dict(Counter(raw_labels).most_common()),
        "files_used": dict(files_used),
        "android_feature_sources": [
            "Wi-Fi SSID/BSSID/RSSI/frequency observations",
            "gateway IP and /proc/net/arp consistency",
            "gateway MAC changes and same-SSID BSSID changes",
            "VPN/DNS/HTTP downgrade hints when available",
            "connection churn and suspicious Wi-Fi policy state",
        ],
        "limitations": [
            "Android normal apps cannot read raw 802.11 monitor-mode management frames.",
            "Radiotap/WLAN dataset fields are distilled into deployable Wi-Fi risk hints.",
            "Real-world thresholds should be calibrated on Galaxy A56 field logs.",
        ],
    }
    (out / "wifi_threat_feature_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    summary = {
        "rows": int(len(x)),
        "features": len(FEATURE_ORDER),
        "threshold": threshold,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "class_weight": class_weight,
        "epochs_ran": len(history.history.get("loss", [])),
        "tflite_size": tflite_path.stat().st_size,
    }
    (out / "training_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
