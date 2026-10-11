"""
feature_extractor.py — Feature Engineering for ML Anomaly Detection
---------------------------------------------------------------------
Loads NSL-KDD dataset, encodes categorical features, normalises
numeric features, and returns train/test arrays ready for
Isolation Forest.

The same feature pipeline is used for both training and inference
to ensure consistency.
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DATASET_DIR = os.path.join(PROJECT_DIR, "datasets")
MODEL_DIR   = os.path.join(BASE_DIR, "models")

TRAIN_CSV = os.path.join(DATASET_DIR, "KDDTrain+.csv")
TEST_CSV  = os.path.join(DATASET_DIR, "KDDTest+.csv")


# ── Feature column groups ────────────────────────────────────────────────────
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

NUMERIC_COLS = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


def load_dataset(csv_path: str) -> pd.DataFrame:
    """Load a NSL-KDD CSV file into a DataFrame."""
    if not os.path.isfile(csv_path):
        print(f"[ERROR] Dataset not found: {csv_path}")
        print("        Run: python datasets/download_nslkdd.py")
        sys.exit(1)

    df = pd.read_csv(csv_path, low_memory=False)
    print(f"[INFO] Loaded {len(df):,} records from {os.path.basename(csv_path)}")
    return df


def fit_encoders(df_train: pd.DataFrame) -> dict:
    """
    Fit LabelEncoders for categorical columns and StandardScaler for
    numeric columns using the TRAINING set. Save encoders for reuse.

    Returns:
        dict with 'label_encoders' and 'scaler'
    """
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Label encode categoricals
    label_encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        # Fit on all possible values (train may not have all test categories)
        le.fit(df_train[col].astype(str))
        label_encoders[col] = le

    # StandardScaler for numerics
    scaler = StandardScaler()
    scaler.fit(df_train[NUMERIC_COLS].values.astype(float))

    # Save
    encoders = {"label_encoders": label_encoders, "scaler": scaler}
    encoder_path = os.path.join(MODEL_DIR, "feature_encoders.joblib")
    joblib.dump(encoders, encoder_path)
    print(f"[INFO] Feature encoders saved to {encoder_path}")

    return encoders


def load_encoders() -> dict:
    """Load saved feature encoders."""
    encoder_path = os.path.join(MODEL_DIR, "feature_encoders.joblib")
    if not os.path.isfile(encoder_path):
        print("[ERROR] No saved encoders found. Run training first.")
        sys.exit(1)
    return joblib.load(encoder_path)


def transform_features(df: pd.DataFrame, encoders: dict) -> np.ndarray:
    """
    Transform a DataFrame into a feature matrix using fitted encoders.

    Args:
        df:       DataFrame with NSL-KDD columns
        encoders: dict from fit_encoders() or load_encoders()

    Returns:
        np.ndarray of shape (n_samples, n_features)
    """
    label_encoders = encoders["label_encoders"]
    scaler = encoders["scaler"]

    # Encode categoricals using fast dictionary lookup
    cat_encoded = []
    for col in CATEGORICAL_COLS:
        le = label_encoders[col]
        class_map = {c: i for i, c in enumerate(le.classes_)}
        col_values = df[col].astype(str)
        encoded = col_values.map(class_map).fillna(-1).values.astype(int)
        cat_encoded.append(encoded.reshape(-1, 1))

    cat_matrix = np.hstack(cat_encoded)

    # Scale numerics
    num_matrix = scaler.transform(df[NUMERIC_COLS].values.astype(float))

    # Combine
    X = np.hstack([cat_matrix, num_matrix])
    return X


def get_labels(df: pd.DataFrame) -> tuple:
    """
    Extract binary labels and attack categories from DataFrame.

    Returns:
        (labels, attack_types, attack_categories)
        - labels:            np.ndarray of 0 (normal) / 1 (attack)
        - attack_types:      list of specific attack names
        - attack_categories: list of category names (DoS, Probe, R2L, U2R, Normal)
    """
    labels = df["label"].values.astype(int)
    attack_types = df["attack_type"].values
    attack_categories = df["attack_category"].values if "attack_category" in df.columns else None
    return labels, attack_types, attack_categories


def prepare_training_data() -> tuple:
    """
    Full pipeline: load train set, fit encoders, return (X_train_normal, encoders).
    Only normal traffic is used for Isolation Forest training.
    """
    df_train = load_dataset(TRAIN_CSV)

    # Fit encoders on ALL training data (both normal and attack)
    encoders = fit_encoders(df_train)

    # Filter to normal traffic only for Isolation Forest training
    df_normal = df_train[df_train["label"] == 0]
    print(f"[INFO] Training on {len(df_normal):,} normal records "
          f"(out of {len(df_train):,} total)")

    X_train = transform_features(df_normal, encoders)
    return X_train, encoders


def prepare_test_data(encoders: dict = None) -> tuple:
    """
    Load test set and transform features.

    Returns:
        (X_test, y_test, attack_types, attack_categories, df_test)
    """
    if encoders is None:
        encoders = load_encoders()

    df_test = load_dataset(TEST_CSV)
    X_test = transform_features(df_test, encoders)
    y_test, attack_types, attack_categories = get_labels(df_test)

    return X_test, y_test, attack_types, attack_categories, df_test
