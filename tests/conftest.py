"""Общие фикстуры: Flask-приложение, клиент с сессией администратора."""

from __future__ import annotations

import hashlib

import pytest

from manage_site import selfvpn_app as selfvpn_app_module


@pytest.fixture()
def app():
    """Экземпляр Flask (импорт уже выполнил загрузку настроек)."""
    selfvpn_app_module.selfvpn_app.config["TESTING"] = True
    yield selfvpn_app_module.selfvpn_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_password_md5() -> str:
    return hashlib.md5(b"pytest-admin-secret").hexdigest()


@pytest.fixture()
def authenticated_client(client, admin_password_md5, monkeypatch):
    """Клиент с установленной сессией входа (без реального POST /login)."""
    monkeypatch.setattr(
        selfvpn_app_module, "_ADMIN_PASSWORD_MD5", admin_password_md5, raising=False
    )
    with client.session_transaction() as sess:
        sess["admin_authenticated"] = True
    return client
