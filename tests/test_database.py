"""
Unit tests for SQLite Database Threat History and Aggregations.
"""

import pytest
from utils.database import (
    init_db, add_log, add_logs_batch, get_logs, get_log_by_id,
    clear_logs, get_statistics
)


def test_database_crud_flow():
    init_db()
    clear_logs()

    # 1. Insert a log
    log_id = add_log(
        source="192.168.1.50:12345",
        destination="10.0.0.1:80",
        protocol="TCP",
        prediction="Threat Detected",
        threat_type="DoS",
        risk_level="HIGH",
        confidence=98.5,
        ai_analysis="SYN flood profile.",
        details={"service": "http"}
    )
    assert log_id is not None
    assert log_id > 0

    # 2. Retrieve log by ID
    log = get_log_by_id(log_id)
    assert log is not None
    assert log["source"] == "192.168.1.50:12345"
    assert log["threat_type"] == "DoS"
    assert log["risk_level"] == "HIGH"
    assert log["confidence"] == 98.5

    # 3. Batch insert
    batch_count = add_logs_batch([
        {
            "source": "10.0.0.5:54321",
            "destination": "10.0.0.1:22",
            "protocol": "TCP",
            "prediction": "Safe Traffic",
            "threat_type": "Normal",
            "risk_level": "LOW",
            "confidence": 99.1
        },
        {
            "source": "185.220.101.5:8000",
            "destination": "10.0.0.1:443",
            "protocol": "TCP",
            "prediction": "Threat Detected",
            "threat_type": "Probe",
            "risk_level": "MEDIUM",
            "confidence": 95.0
        }
    ])
    assert batch_count == 2

    # 4. Search and filters
    dos_logs = get_logs(threat_type="DoS")
    assert dos_logs["total"] == 1

    search_logs = get_logs(search="185.220")
    assert search_logs["total"] == 1

    # 5. Check statistics
    stats = get_statistics()
    assert stats["total_analyzed"] == 3
    assert stats["threats_detected"] == 2
    assert stats["normal_traffic"] == 1
    assert stats["high_risk_threats"] == 1
    assert stats["threat_distribution"]["DoS"] == 1
    assert stats["threat_distribution"]["Probe"] == 1
    assert stats["threat_distribution"]["Normal"] == 1

    # 6. Clear logs
    clear_logs()
    post_clear = get_logs()
    assert post_clear["total"] == 0
