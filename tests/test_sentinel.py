from pathlib import Path

from fastapi.testclient import TestClient

from sentinel import database
from sentinel.main import app
from sentinel.ml_anomaly import anomaly_score
from sentinel.models import RequestContext


def test_demo_api_and_enumeration_incident():
    with TestClient(app) as client:
        assert client.get("/products").status_code == 200
        for user_id in range(1, 12):
            response = client.get(f"/users/{user_id}", headers={"x-forwarded-for": "10.0.0.20"})
            assert response.status_code == 200
        incidents = client.get("/api/incidents").json()
        assert any(item["threat_type"] == "API_ENUMERATION" for item in incidents)


def test_injection_is_detected():
    with TestClient(app) as client:
        response = client.get("/search", params={"q": "union select password from users"})
        assert response.status_code == 403
        events = client.get("/api/events").json()
        assert any(item["threat_type"] == "INJECTION" for item in events)


def test_integrated_bola_schema_and_pii_controls():
    with TestClient(app) as client:
        bola = client.get("/api/v1/orders/order_101", headers={"x-user-id": "usr_beta", "x-forwarded-for": "10.0.0.71"})
        owner = client.get("/api/v1/orders/order_101", headers={"x-user-id": "usr_alpha", "x-forwarded-for": "10.0.0.72"})
        schema = client.post("/api/v1/user/profile", headers={"x-forwarded-for": "10.0.0.73"}, json={"display_name": "Demo", "unknown_field": "rejected"})
        statement = client.get("/api/v1/user/statement", headers={"x-forwarded-for": "10.0.0.74"})

    assert bola.status_code == 403
    assert owner.status_code == 200
    assert schema.status_code == 403
    assert statement.status_code == 200
    assert "4532" not in statement.text
    assert "[REDACTED_BY_API_SENTINEL]" in statement.text


def test_anomaly_score_returns_a_valid_probability():
    history = [
        RequestContext(request_id="R1", timestamp="2026-01-01T00:00:00+00:00", ip="10.0.0.1", method="GET", endpoint="/products", request_size=200, response_size=500, status_code=200),
        RequestContext(request_id="R2", timestamp="2026-01-01T00:00:01+00:00", ip="10.0.0.1", method="GET", endpoint="/users/1", request_size=200, response_size=500, status_code=200),
        RequestContext(request_id="R3", timestamp="2026-01-01T00:00:02+00:00", ip="10.0.0.1", method="GET", endpoint="/users/2", request_size=200, response_size=500, status_code=200),
        RequestContext(request_id="R4", timestamp="2026-01-01T00:00:03+00:00", ip="10.0.0.1", method="GET", endpoint="/users/3", request_size=200, response_size=500, status_code=200),
        RequestContext(request_id="R5", timestamp="2026-01-01T00:00:04+00:00", ip="10.0.0.1", method="GET", endpoint="/users/4", request_size=200, response_size=500, status_code=200),
    ]
    score = anomaly_score(history)
    assert 0.0 <= score <= 1.0


def test_override_records_action_and_writes_log_file():
    event_id = database.insert("security_events", {
        "request_id": "REQ-LOG-TEST",
        "threat_type": "API_ENUMERATION",
        "rule_score": 85,
        "anomaly_score": 0.75,
        "risk_score": 75,
        "severity": "HIGH",
        "reason": "Enumeration pattern detected",
        "created_at": "2026-01-01T00:00:00+00:00",
    })
    incident_id = database.insert("incidents", {
        "event_id": event_id,
        "endpoint": "/users/{id}",
        "ip": "10.0.0.20",
        "threat_type": "API_ENUMERATION",
        "risk_score": 75,
        "action": "REVIEW",
        "status": "OPEN",
        "created_at": "2026-01-01T00:00:00+00:00",
    })
    log_path = Path(__file__).resolve().parent.parent / "sentinel_audit.log"
    if log_path.exists():
        log_path.unlink()

    with TestClient(app) as client:
        response = client.post(
            f"/api/incidents/{incident_id}/override",
            json={"action": "ALLOW", "reason": "Approved after review", "reviewer": "test-user"},
        )
        assert response.status_code == 200
        assert response.json()["action"] == "ALLOW"
        updated = client.get(f"/api/incidents/{incident_id}").json()
        assert updated["action"] == "ALLOW"

    assert log_path.exists()
    log_text = log_path.read_text(encoding="utf-8")
    assert "ALLOW" in log_text
    assert "incident_id" in log_text


def test_facie_is_live_and_persists_recommendation():
    with TestClient(app) as client:
        status = client.get("/api/facie/status")
        response = client.get("/search", params={"q": "union select password from users"})
        incidents = client.get("/api/incidents").json()

    assert status.status_code == 200
    assert status.json()["status"] == "ready"
    assert response.status_code == 403
    assert incidents[0]["ai_action"] == "BLOCK"
    assert incidents[0]["ai_confidence"] > 0.5
