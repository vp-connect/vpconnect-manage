"""Доп. ветки wg_background_sync (без реального daemon)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flask import Flask

from manage_site import wg_background_sync


def test_background_loop_exits_when_interval_zero(monkeypatch):
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_SYNC_INTERVAL_MINUTES", 0)
    app = Flask(__name__)
    wg_background_sync._background_loop(app)


def test_register_starts_thread_when_interval_positive(monkeypatch):
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_CONF_PATH", "/x.conf")
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_SYNC_INTERVAL_MINUTES", 60)
    app = Flask(__name__)
    with (
        patch.object(
            wg_background_sync.vpn_clients_service,
            "sync_clients_json_with_runtime_state",
            MagicMock(return_value=[]),
        ),
        patch.object(wg_background_sync.threading, "Thread") as mock_thread,
    ):
        wg_background_sync.register_wireguard_background_sync(app)
    mock_thread.assert_called_once()
    _, kwargs = mock_thread.call_args
    assert kwargs.get("daemon") is True


def test_background_loop_calls_sync_then_exits(monkeypatch):
    """Один проход цикла: sleep → sync → выход при интервале 0 на второй итерации."""
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_SYNC_INTERVAL_MINUTES", 1)
    app = Flask(__name__)

    def sleep_flip(_secs: float) -> None:
        monkeypatch.setattr(
            wg_background_sync.settings,
            "WIREGUARD_SYNC_INTERVAL_MINUTES",
            0,
        )

    with (
        patch("manage_site.wg_background_sync.time.sleep", sleep_flip),
        patch.object(
            wg_background_sync.vpn_clients_service,
            "sync_clients_json_with_runtime_state",
            MagicMock(return_value=[]),
        ) as mock_sync,
    ):
        wg_background_sync._background_loop(app)
    mock_sync.assert_called_once()
