"""Определение типа VPN-сервиса (manage_site.vpservice)."""

from __future__ import annotations

from pathlib import Path

from manage_site import settings
from manage_site import vpservice


def test_active_vpservice_type_from_explicit_env(monkeypatch):
    monkeypatch.setattr(settings, "VP_SERVICE_TYPE", "amneziawg")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    assert vpservice.active_vpservice_type() == "amneziawg"


def test_detect_vpservice_type_from_conf_amnezia(tmp_path: Path):
    conf = tmp_path / "wg0.conf"
    conf.write_text(
        "[Interface]\n"
        "Address = 10.8.0.1/24\n"
        "Jc = 5\n"
        "Jmin = 10\n",
        encoding="utf-8",
    )
    assert vpservice.detect_vpservice_type_from_conf(conf) == "amneziawg"


def test_detect_vpservice_type_from_conf_wireguard_default(tmp_path: Path):
    conf = tmp_path / "wg0.conf"
    conf.write_text(
        "[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\n",
        encoding="utf-8",
    )
    assert vpservice.detect_vpservice_type_from_conf(conf) == "wireguard"


def test_vpservice_display_name_map(monkeypatch):
    monkeypatch.setattr(settings, "VP_SERVICE_TYPE", "wireguard")
    assert vpservice.vpservice_display_name() == "Wireguard"
    monkeypatch.setattr(settings, "VP_SERVICE_TYPE", "amneziawg")
    assert vpservice.vpservice_display_name() == "Amnezia WG"
