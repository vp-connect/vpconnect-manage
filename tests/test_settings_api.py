"""Публичные функции настроек (settings)."""

from __future__ import annotations

from manage_site import settings


def test_wireguard_enabled_true_false(monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "/etc/wg0.conf")
    assert settings.wireguard_enabled() is True
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    assert settings.wireguard_enabled() is False


def test_mtproxy_enabled_true_false(monkeypatch):
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", "/tmp/link")
    assert settings.mtproxy_enabled() is True
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", "")
    assert settings.mtproxy_enabled() is False
