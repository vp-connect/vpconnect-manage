"""
Синхронизация ``vpn_clients.json`` с wg0.conf при старте и по таймеру (фоновый поток).

Подключается один раз после создания экземпляра Flask-приложения.
"""

from __future__ import annotations

import logging
import threading
import time

from flask import Flask

from . import settings
from . import vpn_clients_service

_log = logging.getLogger(__name__)


def _background_loop(app: Flask) -> None:
    """Периодически вызывать синхронизацию в контексте приложения."""
    while True:
        interval = max(0, settings.WIREGUARD_SYNC_INTERVAL_MINUTES)
        if interval <= 0:
            return
        time.sleep(interval * 60)
        try:
            with app.app_context():
                vpn_clients_service.sync_clients_json_with_runtime_state()
        except Exception:
            _log.exception("WireGuard: фоновая синхронизация")


def register_wireguard_background_sync(app: Flask) -> None:
    """
    Выполнить начальную синхронизацию и при необходимости запустить daemon-thread.

    Не вызывать, если интеграция WireGuard отключена (пустой WIREGUARD_CONF_PATH).
    """
    if not settings.wireguard_enabled():
        return
    try:
        with app.app_context():
            vpn_clients_service.sync_clients_json_with_runtime_state()
    except Exception:
        _log.exception("WireGuard: синхронизация при старте")
    if settings.WIREGUARD_SYNC_INTERVAL_MINUTES > 0:
        threading.Thread(
            target=_background_loop,
            args=(app,),
            daemon=True,
        ).start()
