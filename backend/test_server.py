import importlib
import os
from pathlib import Path

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_API_KEY", "test-api-key")

    import server

    server = importlib.reload(server)
    server.DB_FILE = str(Path(tmp_path) / "audit_logs.db")
    server.init_db()
    server.app.config["TESTING"] = True

    with server.app.test_client() as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"]


def test_incidents_requires_api_key(client):
    response = client.get("/incidents")
    assert response.status_code == 401


def test_log_and_fetch_incidents(client):
    headers = {"X-API-Key": "test-api-key"}
    payload = {
        "platform": "chatgpt.com",
        "violation": "Credential",
        "severity": "HIGH",
        "snippet": "password=abc123",
        "userAgent": "pytest"
    }

    log_response = client.post("/log", headers=headers, json=payload)
    assert log_response.status_code == 200
    assert log_response.get_json()["status"] == "logged"

    incidents_response = client.get("/incidents", headers=headers)
    assert incidents_response.status_code == 200
    incidents = incidents_response.get_json()
    assert len(incidents) == 1
    assert incidents[0]["violation"] == "Credential"
