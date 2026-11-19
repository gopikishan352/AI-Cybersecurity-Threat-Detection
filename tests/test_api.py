"""
Integration tests for Flask Web App and REST API endpoints.
"""

import io
import json
import pytest
from app import app
from utils.constants import PRESET_SAMPLES


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_home_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"AI Cyber Threat Detection" in res.data


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "online"
    assert data["model_loaded"] is True
    assert data["scaler_loaded"] is True
    assert data["encoders_loaded"] is True


def test_legacy_metrics(client):
    res = client.get("/metrics")
    assert res.status_code == 200
    data = res.get_json()
    assert "accuracy" in data
    assert "f1_score" in data


def test_api_model_performance(client):
    res = client.get("/api/model-performance")
    assert res.status_code == 200
    data = res.get_json()
    assert "model_type" in data
    assert "validation" in data
    assert data["num_features"] == 41


def test_api_predict_preset(client):
    # Test DoS preset
    res = client.post("/api/predict", json={"preset": "dos"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["prediction"] == "Threat Detected"
    assert data["threat_type"] == "DoS"
    assert data["risk_level"] == "HIGH"
    assert "confidence" in data
    assert "ai_analysis" in data


def test_api_predict_normal_preset(client):
    res = client.post("/api/predict", json={"preset": "normal"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["prediction"] == "Safe Traffic"
    assert data["threat_type"] == "Normal"
    assert data["risk_level"] == "LOW"


def test_api_predict_invalid_features(client):
    res = client.post("/api/predict", json={"features": [0, 1, 2]})
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_api_upload_batch(client):
    # Create sample in-memory CSV (2 rows: one normal, one dos)
    normal_row = ",".join(str(x) for x in PRESET_SAMPLES["normal"]["features"])
    dos_row = ",".join(str(x) for x in PRESET_SAMPLES["dos"]["features"])
    csv_content = f"{normal_row}\n{dos_row}\n"

    data = {
        "file": (io.BytesIO(csv_content.encode("utf-8")), "test_traffic.csv")
    }

    res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    result = res.get_json()
    assert result["total"] == 2
    assert "threat_counts" in result
    assert "ai_report" in result


def test_api_simulation_feed(client):
    res = client.get("/api/simulation/feed?count=2")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "active"
    assert len(data["events"]) == 2
    assert "threat_type" in data["events"][0]


def test_api_statistics_and_history(client):
    res_stats = client.get("/api/statistics")
    assert res_stats.status_code == 200

    res_hist = client.get("/api/history?page=1&per_page=10")
    assert res_hist.status_code == 200
    data_hist = res_hist.get_json()
    assert "records" in data_hist
    assert "total" in data_hist
