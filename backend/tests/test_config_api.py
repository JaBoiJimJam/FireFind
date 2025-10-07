from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient
import yaml

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.api import app  # noqa: E402


@pytest.fixture()
def config_client(tmp_path, monkeypatch):
    config_path = tmp_path / "rules.yaml"
    config_path.write_text("admin_ports:\n  - 22\n", encoding="utf-8")
    history_path = tmp_path / "rules.history.jsonl"

    monkeypatch.setenv("FIRE_FIND_RULES_CONFIG", str(config_path))
    monkeypatch.setenv("FIRE_FIND_RULES_HISTORY", str(history_path))
    monkeypatch.setenv("FIRE_FIND_API_TOKEN", "secret-token")

    client = TestClient(app)
    try:
        yield client, config_path, history_path
    finally:
        client.close()


def auth_headers(token: str = "secret-token", actor: str | None = "qa") -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if actor is not None:
        headers["X-Firefind-Actor"] = actor
    return headers


def test_get_rules_requires_auth(config_client):
    client, _, _ = config_client
    resp = client.get("/api/config/rules")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Missing Authorization header"


def test_get_rules_returns_active_configuration(config_client):
    client, _, _ = config_client
    resp = client.get("/api/config/rules", headers=auth_headers())
    assert resp.status_code == 200
    payload = resp.json()
    assert "config" in payload
    assert "rules" in payload
    assert isinstance(payload["rules"], list)
    assert "thresholds" in payload
    assert "critical" in payload["thresholds"]
    assert payload["metadata"]["version"] == 0
    admin_ports = payload["config"].get("admin_ports", [])
    assert 22 in admin_ports
    # Defaults from the schema should still be present for other sections
    assert "risk_levels" in payload["config"]
    assert "critical" in payload["config"]["risk_levels"]


def test_patch_rules_updates_file_and_history(config_client):
    client, config_path, history_path = config_client
    patch_body = {
        "changes": {"admin_ports": [22, 443]},
        "message": "Allow HTTPS management",
    }
    resp = client.patch(
        "/api/config/rules",
        headers=auth_headers(),
        json=patch_body,
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["metadata"]["version"] == 1
    assert payload["metadata"]["updated_by"] == "qa"
    assert 443 in payload["config"]["admin_ports"]

    stored = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert stored["admin_ports"] == [22, 443]

    assert history_path.exists()
    history_records = [
        json.loads(line)
        for line in history_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert history_records[-1]["version"] == 1
    assert history_records[-1]["summary"] == "Allow HTTPS management"

    # Follow-up GET should surface new metadata
    follow_up = client.get("/api/config/rules", headers=auth_headers())
    assert follow_up.json()["metadata"]["version"] == 1


def _sample_rule(rule_id: str = "rule-1", port: int = 22) -> dict[str, object]:
    return {
        "id": rule_id,
        "name": "Flag sensitive port",
        "conditions": {
            "type": "all",
            "conditions": [
                {
                    "type": "comparison",
                    "field": "destination_port",
                    "operator": "equals",
                    "value": port,
                }
            ],
        },
    }


def test_put_rules_config_round_trip(config_client):
    client, config_path, history_path = config_client
    payload = {
        "rules": [_sample_rule()],
        "thresholds": {"critical": {"min_score": 95}},
        "message": "Tune thresholds",
    }

    resp = client.put(
        "/api/config/rules",
        headers=auth_headers(),
        json=payload,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["metadata"]["version"] == 1
    assert body["rules"][0]["id"] == "rule-1"
    assert body["thresholds"]["critical"]["min_score"] == 95

    stored = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert stored["rules"][0]["id"] == "rule-1"
    assert stored["risk_levels"]["critical"]["thresholds"]["min_score"] == 95

    history = history_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(history) == 1


def test_put_rules_rejects_duplicate_ids(config_client):
    client, _, _ = config_client
    payload = {
        "rules": [_sample_rule("dup"), _sample_rule("dup", port=443)],
    }

    resp = client.put(
        "/api/config/rules",
        headers=auth_headers(),
        json=payload,
    )

    assert resp.status_code == 422
    assert "Duplicate rule id" in resp.json()["detail"]


def test_put_rules_rejects_invalid_ports(config_client):
    client, _, _ = config_client
    payload = {
        "rules": [_sample_rule(port=70000)],
    }

    resp = client.put(
        "/api/config/rules",
        headers=auth_headers(),
        json=payload,
    )

    assert resp.status_code == 422
    assert "invalid port" in resp.json()["detail"]


def test_put_rules_rejects_malformed_condition_tree(config_client):
    client, _, _ = config_client
    payload = {
        "rules": [
            {
                "id": "rule-1",
                "name": "Broken",
                "conditions": {"type": "all", "conditions": []},
            }
        ]
    }

    resp = client.put(
        "/api/config/rules",
        headers=auth_headers(),
        json=payload,
    )

    assert resp.status_code == 422


def test_patch_rules_rejects_noop_changes(config_client):
    client, _, _ = config_client
    resp = client.patch(
        "/api/config/rules",
        headers=auth_headers(),
        json={"changes": {"admin_ports": [22]}},
    )
    assert resp.status_code == 422
    assert "No configuration changes" in resp.json()["detail"]


def test_config_history_limit(config_client):
    client, _, history_path = config_client
    # Create two updates to populate history
    for port in (443, 3389):
        resp = client.patch(
            "/api/config/rules",
            headers=auth_headers(actor="ops"),
            json={"changes": {"admin_ports": [22, port]}},
        )
        assert resp.status_code == 200

    resp = client.get(
        "/api/config/rules/history?limit=1",
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    history = resp.json()["history"]
    assert len(history) == 1
    assert history[0]["version"] == 2
    assert history[0]["changes"]["admin_ports"] == [22, 3389]

    # Ensure history file actually tracks both revisions
    lines = history_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2