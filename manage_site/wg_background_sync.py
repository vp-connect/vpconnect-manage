"""
Фоновая синхронизация **vpn_clients.json** с ``wg0.conf``.

Назначение
    После старта приложения и далее с интервалом ``WIREGUARD_SYNC_INTERVAL_MINUTES``
    вызывать ``vpn_clients_service.sync_clients_json_with_runtime_state`` в контексте Flask,
    чтобы JSON соответствовал серверному конфигу WireGuard.

Зависимости
    ``flask.Flask``, ``settings``, ``vpn_clients_service``, ``threading``, ``time``.

Кто вызывает
    ``selfvpn_app`` один раз после создания приложения: ``register_wireguard_background_sync``.

Условия
    При пустом ``WIREGUARD_CONF_PATH`` регистрация не выполняет работу. При интервале
    ``0`` фоновый поток не создаётся (только синхронизация при старте и из UI).
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
    """
    Бесконечный цикл: ``sleep`` на интервал, затем синхронизация в ``app_context``.

    Args:
        app: экземпляр Flask панели.

    Побочные эффекты:
        При ошибке синхронизации пишет исключение в лог и продолжает цикл.
    """
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
    Запустить начальную синхронизацию и при необходимости daemon-поток.

    Прецедент: сразу после создания ``selfvpn_app``.

    Args:
        app: экземпляр Flask.

    Поведение:
        Ничего не делает, если WireGuard выключен. Ошибка стартовой синхронизации
        логируется. Поток создаётся только при положительном интервале минут.
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
