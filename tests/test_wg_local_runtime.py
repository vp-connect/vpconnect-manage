"""wg, endpoint, ключи (wg_local_runtime) — с заглушками subprocess."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from manage_site import settings
from manage_site import wg_local_runtime


def test_wg_conf_path_resolved(monkeypatch, tmp_path):
    p = tmp_path / "wg0.conf"
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(p))
    assert wg_local_runtime.wg_conf_path_resolved() == p.resolve()


def test_listen_port_from_server_preamble(tmp_path: Path):
    conf = tmp_path / "wg.conf"
    conf.write_text(
        "[Interface]\nListenPort = 12345\nPrivateKey = x\n",
        encoding="utf-8",
    )
    assert wg_local_runtime.listen_port_from_server_preamble(conf) == 12345


def test_resolve_client_endpoint_direct(monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "host:51820")
    monkeypatch.setattr(settings, "WIREGUARD_PUBLIC_HOST", "")
    assert wg_local_runtime.resolve_client_endpoint(Path("/tmp/x.conf")) == "host:51820"


def test_resolve_client_endpoint_host_and_listen_port_from_conf(tmp_path, monkeypatch):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nListenPort = 4000\n", encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "")
    monkeypatch.setattr(settings, "WIREGUARD_PUBLIC_HOST", "example.com")
    monkeypatch.setattr(settings, "WIREGUARD_LISTEN_PORT", 0)
    assert wg_local_runtime.resolve_client_endpoint(conf) == "example.com:4000"


def test_resolve_client_endpoint_host_and_fixed_listen_port(tmp_path, monkeypatch):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\n", encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "")
    monkeypatch.setattr(settings, "WIREGUARD_PUBLIC_HOST", "h.example")
    monkeypatch.setattr(settings, "WIREGUARD_LISTEN_PORT", 5555)
    assert wg_local_runtime.resolve_client_endpoint(conf) == "h.example:5555"


def test_resolve_client_endpoint_missing_host(monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "")
    monkeypatch.setattr(settings, "WIREGUARD_PUBLIC_HOST", "")
    with pytest.raises(RuntimeError, match="Endpoint"):
        wg_local_runtime.resolve_client_endpoint(Path("/tmp/x.conf"))


@patch("manage_site.wg_local_runtime.subprocess.run")
def test_server_public_key_from_wg_show(mock_run: MagicMock, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_INTERFACE_NAME", "wg0")
    mock_run.return_value = MagicMock(stdout="SERVERPUBKEY\n")
    assert wg_local_runtime.server_public_key_from_interface(Path("/tmp/x.conf")) == "SERVERPUBKEY"


@patch("manage_site.wg_local_runtime.subprocess.run")
def test_server_public_key_from_conf_private_inline(mock_run: MagicMock, tmp_path: Path):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nPrivateKey = inlinepriv\n", encoding="utf-8")
    mock_run.side_effect = [
        MagicMock(stdout=""),  # wg show
        MagicMock(stdout="derivedpub\n"),  # wg pubkey
    ]
    assert wg_local_runtime.server_public_key_from_interface(conf) == "derivedpub"


@patch("manage_site.wg_local_runtime.subprocess.run")
def test_wg_gen_keypair_ok(mock_run: MagicMock):
    mock_run.side_effect = [
        MagicMock(stdout="privline\n"),
        MagicMock(stdout="publine\n"),
    ]
    priv, pub = wg_local_runtime.wg_gen_keypair()
    assert priv == "privline"
    assert pub == "publine"


@patch("manage_site.wg_local_runtime.subprocess.run")
def test_wg_gen_keypair_file_not_found(mock_run: MagicMock):
    mock_run.side_effect = FileNotFoundError()
    with pytest.raises(RuntimeError, match="wg не найдена"):
        wg_local_runtime.wg_gen_keypair()


def test_write_client_conf_file(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_DNS", "1.1.1.1")
    monkeypatch.setattr(settings, "WIREGUARD_NETWORK_CIDR", "")
    p = wg_local_runtime.write_client_conf_file(
        tmp_path,
        "client_a",
        "privk",
        "10.8.0.9",
        "srvpub",
        "ep:443",
    )
    text = p.read_text(encoding="utf-8")
    assert "PrivateKey = privk" in text
    assert "PublicKey = srvpub" in text
    assert "Endpoint = ep:443" in text
    assert (tmp_path / "qr").is_dir()


def test_apply_wg_syncconf_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    wg_local_runtime.apply_wg_syncconf_if_configured()  # no exception
