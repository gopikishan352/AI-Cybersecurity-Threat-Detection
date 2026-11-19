"""
Unit tests for Machine Learning Model Loading and Inference.
"""

import os
import joblib
import numpy as np
import pytest

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")


def test_model_artifacts_exist():
    """Verify that all required trained model artifacts exist."""
    assert os.path.exists(os.path.join(MODEL_DIR, "model.pkl")), "model.pkl missing"
    assert os.path.exists(os.path.join(MODEL_DIR, "scaler.pkl")), "scaler.pkl missing"
    assert os.path.exists(os.path.join(MODEL_DIR, "label_encoders.pkl")), "label_encoders.pkl missing"
    assert os.path.exists(os.path.join(MODEL_DIR, "metrics.json")), "metrics.json missing"


def test_model_inference_structure():
    """Verify model can predict classes and output expected categories."""
    model = joblib.load(os.path.join(MODEL_DIR, "model.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))

    # Synthesize dummy scaled features
    dummy_input = np.zeros((1, 41))
    scaled_input = scaler.transform(dummy_input)

    pred = model.predict(scaled_input)[0]
    probs = model.predict_proba(scaled_input)[0]

    expected_classes = {"Normal", "DoS", "Probe", "R2L", "U2R"}
    assert set(model.classes_) == expected_classes
    assert pred in expected_classes
    assert len(probs) == 5
    assert np.isclose(np.sum(probs), 1.0)
