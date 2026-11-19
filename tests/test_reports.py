"""
Unit and integration tests for PDF Report and CSV Export generation.
"""

import pytest
from app import app
from utils.pdf_generator import generate_threat_report_pdf


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_pdf_generation_buffer():
    stats = {
        "total_analyzed": 100,
        "threats_detected": 40,
        "normal_traffic": 60,
        "detection_rate": 40.0,
        "high_risk_threats": 25,
        "threat_distribution": {"Normal": 60, "DoS": 25, "Probe": 10, "R2L": 4, "U2R": 1},
        "risk_distribution": {"LOW": 60, "MEDIUM": 10, "HIGH": 25, "CRITICAL": 5}
    }
    recent = [
        {
            "timestamp": "2026-09-20 14:00:00",
            "source": "192.168.1.10:5000",
            "destination": "10.0.0.1:80",
            "protocol": "TCP",
            "threat_type": "DoS",
            "risk_level": "HIGH",
            "confidence": 98.2
        }
    ]
    pdf_buffer = generate_threat_report_pdf(stats, recent_records=recent, ai_analysis="Test SOC analysis.")
    assert pdf_buffer is not None
    pdf_bytes = pdf_buffer.getvalue()
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")


def test_api_export_csv(client):
    res = client.get("/api/export/csv")
    assert res.status_code == 200
    assert "text/csv" in res.content_type
    assert b"ID,Timestamp,Source,Destination,Protocol,Prediction" in res.data


def test_api_export_pdf(client):
    res = client.get("/api/export/pdf")
    assert res.status_code == 200
    assert "application/pdf" in res.content_type
    assert res.data.startswith(b"%PDF")
