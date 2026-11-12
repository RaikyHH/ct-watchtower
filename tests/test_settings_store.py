"""The settings through the interface: `GET` and `PUT /api/v1/settings` (§settings).

The point of these tests is the order of precedence code → `.env` → database, and
that a reset *throws the entry away* instead of typing the old value back in.
"""

from __future__ import annotations

import pytest
from conftest import copy_rule_base

from ctwatchtower import settings_store
from ctwatchtower.app import create_app
from ctwatchtower.config import settings


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "api_token", None)
    monkeypatch.setattr(settings, "enrich_enabled", False)
    rules = tmp_path / "rules"
    copy_rule_base(rules)
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    yield app.test_client()
    # The fields hang on the singleton: without tearing down, one test colours the next.
    for name, value in settings_store.DEFAULTS.items():
        setattr(settings, name, value)


def field(response, name):
    for group in response["groups"]:
        for f in group["fields"]:
            if f["name"] == name:
                return f
    raise AssertionError(name)


def test_setting_takes_effect_at_once_and_survives_a_restart(client):
    r = client.put("/api/v1/settings", json={"enrich_enabled": True})
    assert r.status_code == 200
    assert settings.enrich_enabled is True

    f = field(r.get_json(), "enrich_enabled")
    assert f["value"] is True and f["changed_here"] is True

    # What stands in the database has to take effect again at the start.
    settings.enrich_enabled = False
    assert settings_store.apply_stored(client.application.config["DB"]) >= 1
    assert settings.enrich_enabled is True


def test_a_reset_brings_the_env_value_back(client):
    client.put("/api/v1/settings", json={"enrich_enabled": True})
    r = client.put("/api/v1/settings", json={"enrich_enabled": None})
    assert r.status_code == 200
    assert settings.enrich_enabled is settings_store.DEFAULTS["enrich_enabled"]
    assert field(r.get_json(), "enrich_enabled")["changed_here"] is False


def test_an_unknown_field_and_a_nonsense_value_are_refused(client):
    assert client.put("/api/v1/settings", json={"does_not_exist": 1}).status_code == 400
    assert client.put("/api/v1/settings", json={"notify_window": 5}).status_code == 422
    assert client.put("/api/v1/settings", json={}).status_code == 400


def test_secrets_do_not_come_back(client):
    client.put("/api/v1/settings", json={"mail_smtp_password": "s3hr-secret"})
    f = field(client.get("/api/v1/settings").get_json(), "mail_smtp_password")
    assert f["is_set"] is True
    assert "s3hr-secret" not in str(f)
