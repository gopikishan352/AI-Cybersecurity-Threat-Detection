"""
Data Preprocessing Pipeline for NSL-KDD Training and Inference.
Ensures 100% feature consistency, categorical handling, and scaling.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from utils.constants import COLUMNS, FEATURE_COLUMNS, CATEGORICAL_COLUMNS, ATTACK_MAP


def load_data(path):
    """Load NSL-KDD dataset with correct column names."""
    df = pd.read_csv(path, names=COLUMNS)
    return df


def map_attack_category(label):
    """Map granular NSL-KDD attack name to 5 standard classes: Normal, DoS, Probe, R2L, U2R."""
    clean_label = str(label).strip(".").lower()
    return ATTACK_MAP.get(clean_label, "Normal")


def preprocess_for_training(df):
    """
    Preprocess training dataset:
    - Drop difficulty column
    - Map labels to 5 categories
    - Fit LabelEncoders on categorical columns
    - Fit StandardScaler on 41 numeric features
    Returns: X_scaled, y, scaler, encoders
    """
    df = df.copy()
    if "difficulty" in df.columns:
        df.drop(columns=["difficulty"], inplace=True)

    # 5-class target
    df["category"] = df["label"].apply(map_attack_category)
    y = df["category"]

    # Drop label column
    if "label" in df.columns:
        df.drop(columns=["label"], inplace=True)

    encoders = {}
    for col in CATEGORICAL_COLUMNS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    # Reorder to ensure exact feature column order
    X = df[FEATURE_COLUMNS]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y, scaler, encoders


def preprocess_inference_features(input_data, encoders, scaler):
    """
    Preprocess input features for inference (single record or batch).
    Accepts:
      - list of 41 values (mix of strings and numbers)
      - pandas DataFrame of 41 or more columns
    Returns:
      - X_scaled: scaled numpy array of shape (N, 41)
      - df_clean: DataFrame with original/validated feature values
    """
    if isinstance(input_data, list):
        if len(input_data) != 41:
            raise ValueError(f"Expected exactly 41 features, received {len(input_data)}.")
        df = pd.DataFrame([input_data], columns=FEATURE_COLUMNS)
    elif isinstance(input_data, dict):
        df = pd.DataFrame([input_data])
        # Ensure all columns exist
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0
        df = df[FEATURE_COLUMNS]
    elif isinstance(input_data, pd.DataFrame):
        df = input_data.copy()
        # Drop label or difficulty if present
        for col in ["label", "difficulty", "category"]:
            if col in df.columns:
                df.drop(columns=[col], inplace=True)
        if len(df.columns) == 41 and list(df.columns) != FEATURE_COLUMNS:
            df.columns = FEATURE_COLUMNS
        elif len(df.columns) != 41:
            raise ValueError(f"Data must contain 41 feature columns. Found {len(df.columns)} columns.")
    else:
        raise TypeError("Unsupported input data type for inference preprocessing.")

    df_clean = df.copy()

    # Encode categorical columns safely
    for col in CATEGORICAL_COLUMNS:
        le = encoders.get(col)
        if le is not None:
            # Check if column is already numeric
            if pd.api.types.is_numeric_dtype(df[col]):
                # Clip to valid range of classes
                df[col] = df[col].fillna(0).astype(int).clip(0, len(le.classes_) - 1)
            else:
                # String labels - handle unseen categories gracefully
                known_classes = set(le.classes_)
                default_class = le.classes_[0]
                df[col] = df[col].astype(str).apply(
                    lambda x: x if x in known_classes else default_class
                )
                df[col] = le.transform(df[col])

    # Convert all numeric features to float
    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    # Scale using the fitted scaler
    X_scaled = scaler.transform(df[FEATURE_COLUMNS])

    return X_scaled, df_clean