import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.dataset as ds
import tensorflow as tf
from sklearn.metrics import average_precision_score, classification_report, precision_recall_curve, roc_auc_score
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
    "amount",
    "account_age_days",
    "sensitive_data_change_last_7d",
    "registered_devices_count",
    "active_devices_last_30d",
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "is_local_holiday",
    "seconds_since_last_login",
    "seconds_since_last_transaction",
    "transactions_last_1h",
    "transactions_last_24h",
    "transactions_last_7d",
    "transactions_last_30d",
    "amount_sum_last_24h",
    "amount_sum_last_7d",
    "amount_sum_last_30d",
    "amount_mean_last_30d",
    "amount_std_last_30d",
    "logins_last_24h",
    "login_failures_last_24h",
    "password_resets_last_30d",
    "is_round_amount",
    "is_international",
    "amount_increase_vs_30d_mean",
    "is_vpn",
    "is_datacenter_ip",
    "ip_blacklisted",
    "is_proxy",
    "is_tor",
    "is_location_anomaly",
    "distance_from_registered_location_km",
    "is_emulator",
    "is_rooted_or_jailbroken",
    "is_new_device_for_user",
    "devices_last_30d",
    "is_device_compromised",
    "cipher_strength_bits",
    "waf_present",
    "ids_present",
    "ips_present",
    "antimalware_present",
    "mfa_enabled",
    "device_binding_enabled",
    "security_score_tech",
    "previous_fraud_count",
    "previous_chargeback_count",
    "account_takeover_flag",
    "velocity_alert_flag",
    "blacklist_hit",
    "whitelist_hit",
    "money_mule_score",
    "device_fingerprint_match_count",
    "ip_reputation_score",
    "fraud_probability",
    "message_length",
    "contains_url",
    "contains_phone",
    "num_special_chars",
    "llm_risk_score",
    "llm_phishing_detected",
    "llm_sentiment_score",
    "llm_urgency_score",
]

CATEGORICAL_COLUMNS = [
    "event_type",
    "event_source",
    "channel",
    "user_type",
    "user_segment",
    "user_risk_class",
    "transaction_type",
    "connection_type",
    "device_type",
    "os_family",
    "browser_family",
    "mfa_method",
]


def load_sample(path: Path, max_rows: int, seed: int) -> pd.DataFrame:
    columns = FEATURE_COLUMNS + CATEGORICAL_COLUMNS + ["is_fraud"]
    dataset = ds.dataset(path, format="parquet")
    frames = []
    remaining = max_rows
    for batch in dataset.to_batches(columns=columns, batch_size=200_000):
        df = batch.to_pandas()
        if len(df) > remaining:
            df = df.sample(n=remaining, random_state=seed)
        frames.append(df)
        remaining -= len(df)
        if remaining <= 0:
            break
    if not frames:
        raise RuntimeError(f"No rows loaded from {path}")
    out = pd.concat(frames, ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def build_matrix(df: pd.DataFrame, scaler: StandardScaler | None = None, vocab: dict | None = None):
    numeric = df.reindex(columns=FEATURE_COLUMNS).apply(pd.to_numeric, errors="coerce").fillna(0.0)
    if scaler is None:
        scaler = StandardScaler()
        x_num = scaler.fit_transform(numeric).astype(np.float32)
    else:
        x_num = scaler.transform(numeric).astype(np.float32)

    if vocab is None:
        vocab = {}
        for col in CATEGORICAL_COLUMNS:
            values = df[col].fillna("missing").astype(str).value_counts().head(24).index.tolist()
            vocab[col] = {value: idx for idx, value in enumerate(values)}

    one_hot_parts = []
    for col in CATEGORICAL_COLUMNS:
        mapping = vocab[col]
        arr = np.zeros((len(df), len(mapping) + 1), dtype=np.float32)
        values = df[col].fillna("missing").astype(str)
        for row_idx, value in enumerate(values):
            arr[row_idx, mapping.get(value, len(mapping))] = 1.0
        one_hot_parts.append(arr)

    x = np.concatenate([x_num] + one_hot_parts, axis=1).astype(np.float32)
    y = df["is_fraud"].astype(int).to_numpy(dtype=np.float32)
    return x, y, scaler, vocab


def threshold_for_recall(y_true, y_score, target_recall=0.90):
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
    parser.add_argument("--data-dir", default=r"C:\Users\Monster\Desktop\anomali")
    parser.add_argument("--output-dir", default="training/outputs/anomaly_contextual")
    parser.add_argument("--max-train-rows", type=int, default=450_000)
    parser.add_argument("--max-val-rows", type=int, default=140_000)
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--seed", type=int, default=53)
    args = parser.parse_args()

    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)
    data_dir = Path(args.data_dir)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    train_df = load_sample(data_dir / "dataset_train.parquet", args.max_train_rows, args.seed)
    val_df = load_sample(data_dir / "dataset_val.parquet", args.max_val_rows, args.seed + 1)
    x_train, y_train, scaler, vocab = build_matrix(train_df)
    x_val, y_val, _, _ = build_matrix(val_df, scaler, vocab)

    class_weight = {
        0: float(len(y_train) / (2 * max(1, np.sum(y_train == 0)))),
        1: float(len(y_train) / (2 * max(1, np.sum(y_train == 1)))),
    }
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(x_train.shape[1],), name="contextual_security_features"),
        tf.keras.layers.Dense(160, activation="relu"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.20),
        tf.keras.layers.Dense(96, activation="relu"),
        tf.keras.layers.Dropout(0.15),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid", name="fraud_anomaly_probability"),
    ])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=[tf.keras.metrics.AUC(name="auc"), tf.keras.metrics.AUC(curve="PR", name="pr_auc")],
    )
    callbacks = [
        tf.keras.callbacks.EarlyStopping(monitor="val_pr_auc", mode="max", patience=3, restore_best_weights=True)
    ]
    history = model.fit(
        x_train,
        y_train,
        validation_data=(x_val, y_val),
        epochs=args.epochs,
        batch_size=1024,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=2,
    )
    scores = model.predict(x_val, batch_size=4096, verbose=0).reshape(-1)
    threshold = threshold_for_recall(y_val, scores, 0.90)
    pred = (scores >= threshold).astype(int)
    report = classification_report(y_val, pred, output_dict=True, zero_division=0)

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite = converter.convert()
    model_path = out / "contextual_fraud_anomaly_detector.tflite"
    model_path.write_bytes(tflite)
    model.save(out / "contextual_fraud_anomaly_detector.keras")

    metadata = {
        "model_id": "contextual_fraud_anomaly",
        "model_file": model_path.name,
        "input_size": int(x_train.shape[1]),
        "feature_columns_numeric": FEATURE_COLUMNS,
        "feature_columns_categorical": CATEGORICAL_COLUMNS,
        "categorical_vocab": vocab,
        "scaler_mean": scaler.mean_.astype(float).tolist(),
        "scaler_scale": scaler.scale_.astype(float).tolist(),
        "threshold": threshold,
        "output": "fraud_anomaly_probability",
        "note": "Contextual fraud/account-takeover anomaly model. It is not a chat LLM; use it to score risk and feed assistant explanations.",
    }
    (out / "contextual_fraud_anomaly_feature_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    summary = {
        "model_id": "contextual_fraud_anomaly",
        "train_rows": int(len(y_train)),
        "val_rows": int(len(y_val)),
        "input_size": int(x_train.shape[1]),
        "threshold": threshold,
        "roc_auc": float(roc_auc_score(y_val, scores)),
        "pr_auc": float(average_precision_score(y_val, scores)),
        "accuracy": float(report["accuracy"]),
        "fraud_precision": class_metric(report, 1, "precision"),
        "fraud_recall": class_metric(report, 1, "recall"),
        "tflite_size": model_path.stat().st_size,
        "history": {k: [float(v) for v in vals] for k, vals in history.history.items()},
    }
    (out / "contextual_fraud_anomaly_training_report.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
