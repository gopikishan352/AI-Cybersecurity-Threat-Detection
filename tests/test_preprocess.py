"""
Unit tests for NSL-KDD Preprocessing and Feature Engineering.
"""

import os
import joblib
import pandas as pd
import pytest
from utils.constants import FEATURE_COLUMNS
from utils.preprocess import map_attack_category, preprocess_inference_features

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")


@pytest.fixture
def encoders_and_scaler():
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    encoders = joblib.load(os.path.join(MODEL_DIR, "label_encoders.pkl"))
    return encoders, scaler


def test_map_attack_category():
    assert map_attack_category("normal") == "Normal"
    assert map_attack_category("normal.") == "Normal"
    assert map_attack_category("neptune") == "DoS"
    assert map_attack_category("smurf") == "DoS"
    assert map_attack_category("portsweep") == "Probe"
    assert map_attack_category("nmap") == "Probe"
    assert map_attack_category("guess_passwd") == "R2L"
    assert map_attack_category("buffer_overflow") == "U2R"
    assert map_attack_category("unknown_attack_xyz") == "Normal"


def test_preprocess_inference_list(encoders_and_scaler):
    encoders, scaler = encoders_and_scaler
    # 41 features with string categoricals
    sample = [0, "tcp", "http", "SF", 215, 45076, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    X_scaled, df_clean = preprocess_inference_features(sample, encoders, scaler)
    assert X_scaled.shape == (1, 41)
    assert df_clean.shape == (1, 41)


def test_preprocess_unseen_categorical(encoders_and_scaler):
    encoders, scaler = encoders_and_scaler
    # Contains unknown protocol 'quantum_proto' and unknown service 'warp_drive'
    sample = [0, "quantum_proto", "warp_drive", "UNKNOWN_FLAG", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    # Should not throw exception, handles unseen categories safely
    X_scaled, df_clean = preprocess_inference_features(sample, encoders, scaler)
    assert X_scaled.shape == (1, 41)


def test_preprocess_invalid_feature_count(encoders_and_scaler):
    encoders, scaler = encoders_and_scaler
    with pytest.raises(ValueError):
        preprocess_inference_features([0, 1, 2], encoders, scaler)
