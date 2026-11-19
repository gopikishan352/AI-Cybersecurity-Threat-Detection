"""
Model Training & Evaluation Script.
Trains a 5-class Random Forest Classifier on NSL-KDD (KDDTrain+)
and evaluates genuine performance on validation split and KDDTest+.
Outputs model.pkl, scaler.pkl, label_encoders.pkl, and metrics.json.
"""

import os
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split

from utils.constants import COLUMNS, THREAT_CATEGORIES, FEATURE_COLUMNS
from utils.preprocess import load_data, preprocess_for_training, preprocess_inference_features, map_attack_category


def train_and_evaluate():
    print("=" * 60)
    print("AI Cyber Threat Detection - Model Training & Evaluation")
    print("=" * 60)

    # 1. Load Training Data
    train_path = os.path.join("dataset", "KDDTrain+.txt")
    print(f"[1/5] Loading training dataset from {train_path}...")
    df_train = load_data(train_path)
    print(f"      Total training samples: {len(df_train):,}")

    # 2. Preprocess Training Data
    print("[2/5] Preprocessing features and categorical encoding...")
    X_scaled, y, scaler, encoders = preprocess_for_training(df_train)
    print(f"      Feature matrix shape: {X_scaled.shape}")
    print(f"      Class distribution:\n{y.value_counts().to_string()}")

    # 3. Train/Validation Split (80/20 Stratified)
    print("[3/5] Splitting into 80% train / 20% validation...")
    X_train, X_val, y_train, y_val = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Train Random Forest Classifier
    print("[4/5] Training Random Forest Classifier (n_estimators=100)...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample"
    )
    model.fit(X_train, y_train)

    # 5. Evaluate on Validation Split
    print("[5/5] Evaluating performance...")
    val_preds = model.predict(X_val)
    val_acc = accuracy_score(y_val, val_preds)
    val_precision = precision_score(y_val, val_preds, average="weighted", zero_division=0)
    val_recall = recall_score(y_val, val_preds, average="weighted", zero_division=0)
    val_f1 = f1_score(y_val, val_preds, average="weighted", zero_division=0)

    cm_labels = THREAT_CATEGORIES
    val_cm = confusion_matrix(y_val, val_preds, labels=cm_labels).tolist()

    print(f"\n--- Validation Split Results (20% Holdout) ---")
    print(f"Accuracy  : {val_acc * 100:.2f}%")
    print(f"Precision : {val_precision * 100:.2f}%")
    print(f"Recall    : {val_recall * 100:.2f}%")
    print(f"F1-Score  : {val_f1 * 100:.2f}%")

    # Evaluate on KDDTest+
    test_path = os.path.join("dataset", "KDDTest+.txt")
    test_metrics = {}
    if os.path.exists(test_path):
        print(f"\nEvaluating on external benchmark {test_path}...")
        df_test = pd.read_csv(test_path, names=COLUMNS)
        y_test_true = df_test["label"].apply(map_attack_category)
        X_test_scaled, _ = preprocess_inference_features(df_test, encoders, scaler)
        test_preds = model.predict(X_test_scaled)

        test_acc = accuracy_score(y_test_true, test_preds)
        test_precision = precision_score(y_test_true, test_preds, average="weighted", zero_division=0)
        test_recall = recall_score(y_test_true, test_preds, average="weighted", zero_division=0)
        test_f1 = f1_score(y_test_true, test_preds, average="weighted", zero_division=0)
        test_cm = confusion_matrix(y_test_true, test_preds, labels=cm_labels).tolist()

        test_metrics = {
            "accuracy": round(test_acc * 100, 2),
            "precision": round(test_precision * 100, 2),
            "recall": round(test_recall * 100, 2),
            "f1_score": round(test_f1 * 100, 2),
            "samples": len(df_test),
            "confusion_matrix": test_cm
        }
        print(f"KDDTest+ Accuracy : {test_acc * 100:.2f}%")
        print(f"KDDTest+ F1-Score : {test_f1 * 100:.2f}%")

    # Detailed per-class metrics
    report = classification_report(y_val, val_preds, labels=cm_labels, output_dict=True, zero_division=0)

    # Save artifacts
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, os.path.join("model", "model.pkl"))
    joblib.dump(scaler, os.path.join("model", "scaler.pkl"))
    joblib.dump(encoders, os.path.join("model", "label_encoders.pkl"))

    metrics_payload = {
        "model_type": "Random Forest Classifier (n_estimators=100)",
        "training_dataset": "NSL-KDD (KDDTrain+.txt)",
        "training_samples": len(df_train),
        "validation_samples": len(X_val),
        "num_features": len(FEATURE_COLUMNS),
        "classes": cm_labels,
        "validation": {
            "accuracy": round(val_acc * 100, 2),
            "precision": round(val_precision * 100, 2),
            "recall": round(val_recall * 100, 2),
            "f1_score": round(val_f1 * 100, 2),
            "confusion_matrix": val_cm,
            "per_class": {
                c: {
                    "precision": round(report[c]["precision"] * 100, 2),
                    "recall": round(report[c]["recall"] * 100, 2),
                    "f1_score": round(report[c]["f1-score"] * 100, 2),
                    "support": report[c]["support"]
                }
                for c in cm_labels if c in report
            }
        },
        "benchmark_test": test_metrics
    }

    metrics_file = os.path.join("model", "metrics.json")
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=4)

    print(f"\nModel artifacts and real metrics saved to model/ directory:")
    print(f"  - model/model.pkl")
    print(f"  - model/scaler.pkl")
    print(f"  - model/label_encoders.pkl")
    print(f"  - model/metrics.json")
    print("=" * 60)
    print("Model Training Successfully Completed!")
    print("=" * 60)


if __name__ == "__main__":
    train_and_evaluate()