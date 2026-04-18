"""Фоновая синхронизация WireGuard (wg_background_sync)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flask import Flask

from manage_site import wg_background_sync


def test_register_skips_when_wireguard_disabled(monkeypatch):
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_CONF_PATH", "")
    app = Flask(__name__)
    wg_background_sync.register_wireguard_background_sync(app)


def test_register_calls_sync_when_enabled(monkeypatch):
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_CONF_PATH", "/tmp/wg0.conf")
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_SYNC_INTERVAL_MINUTES", 0)
    app = Flask(__name__)
    with patch.object(
        wg_background_sync.vpn_clients_service,
        "sync_clients_json_with_runtime_state",
        MagicMock(return_value=[]),
    ) as mock_sync:
        wg_background_sync.register_wireguard_background_sync(app)
    mock_sync.assert_called_once()
