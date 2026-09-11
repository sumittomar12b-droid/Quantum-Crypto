"""
Integration Tests for FastAPI / Vercel Serverless Endpoints.
"""

from fastapi.testclient import TestClient
from api.index import app

client = TestClient(app)


def test_api_status_endpoint():
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ONLINE"
    assert "ML-KEM-768" in data["pqc_standard"]
    assert data["hash_chain_integrity"] is True


def test_api_protocol_execute_honest():
    payload = {
        "mode": "honest",
        "signer_id": "ALICE",
        "verifier_id": "BOB",
        "message": "SIH-2026-UNIT-TEST",
        "signature_length_L": 50,
        "threshold_t": 10
    }
    resp = client.post("/api/protocol/execute", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted"] is True
    assert data["threat_detected"] is False


def test_api_protocol_execute_forgery_attack():
    payload = {
        "mode": "random_forger",
        "signer_id": "ALICE",
        "verifier_id": "BOB",
        "message": "SIH-2026-FORGERY-TEST",
        "signature_length_L": 100,
        "threshold_t": 15
    }
    resp = client.post("/api/protocol/execute", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted"] is False
    assert data["threat_detected"] is True
    assert data["primary_threat"]["rule_id"] == "RULE-FORGERY"


def test_api_audit_logs_endpoint():
    resp = client.get("/api/audit/logs?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["integrity_verified"] is True
    assert len(data["events"]) > 0
