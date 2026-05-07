"""
train_model.py
==============
NetShield AI – Model Training Module
Trains a Random Forest classifier to detect network threats.
Saves the trained model and label encoder for use in the dashboard.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os

# ─── Constants ──────────────────────────────────────────────────────────────

MODEL_PATH  = "model/netshield_model.pkl"
ENCODER_PATH = "model/label_encoder.pkl"
DATASET_PATH = "sample_dataset.csv"

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "OTHER": 3}


def encode_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert raw packet features into numeric values suitable for ML.
    - Protocols are mapped to integers.
    - IP addresses are hashed to integers (deterministic).
    - All other columns are kept as-is.
    """
    df = df.copy()

    # Encode protocol as integer
    df["protocol_enc"] = df["protocol"].map(PROTOCOL_MAP).fillna(3).astype(int)

    # Encode IP addresses by hashing (fast, deterministic, no data leakage)
    df["src_ip_enc"] = df["src_ip"].apply(lambda x: hash(x) % 10_000)
    df["dst_ip_enc"] = df["dst_ip"].apply(lambda x: hash(x) % 10_000)

    return df


def get_feature_columns():
    """Return the list of feature columns used for model training/inference."""
    return ["src_ip_enc", "dst_ip_enc", "protocol_enc", "packet_length", "traffic_freq"]


def train_and_save_model(dataset_path: str = DATASET_PATH):
    """
    Full pipeline:
      1. Load dataset
      2. Encode features
      3. Train Random Forest
      4. Evaluate & print metrics
      5. Save model + encoder to disk
    """
    print("=" * 60)
    print("  NetShield AI – Model Training")
    print("=" * 60)

    # ── 1. Load dataset ───────────────────────────────────────────
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")

    df = pd.read_csv(dataset_path)
    print(f"\n[✓] Loaded dataset: {len(df)} rows, {df['label'].nunique()} classes")
    print(f"    Class distribution:\n{df['label'].value_counts().to_string()}\n")

    # ── 2. Encode features ────────────────────────────────────────
    df = encode_features(df)
    feature_cols = get_feature_columns()

    X = df[feature_cols].values
    y_raw = df["label"].values

    # Encode target labels to integers
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    print(f"[✓] Label classes: {list(le.classes_)}")

    # ── 3. Train-test split ───────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"[✓] Train: {len(X_train)} | Test: {len(X_test)}")

    # ── 4. Train Random Forest ────────────────────────────────────
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print("\n[✓] Model trained successfully.")

    # ── 5. Evaluate ───────────────────────────────────────────────
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[✓] Test Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # ── 6. Save model & encoder ───────────────────────────────────
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    print(f"[✓] Model saved  → {MODEL_PATH}")
    print(f"[✓] Encoder saved → {ENCODER_PATH}")
    print("\n[✓] Training complete. Run app.py to launch the dashboard.\n")

    return model, le


if __name__ == "__main__":
    train_and_save_model()
