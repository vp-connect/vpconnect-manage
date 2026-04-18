"""Учёт клиентов WG и JSON (vpn_clients_service)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from manage_site import settings
from manage_site import vpn_clients_service
from manage_site import wireguard_conf


def test_ascii_slug_cyrillic_and_empty():
    assert "sch" in vpn_clients_service.ascii_slug("Щука")
    assert vpn_clients_service.ascii_slug("   ") == "user"
    assert vpn_clients_service.ascii_slug("User Name!") == "user_name"


def test_unique_wg_name_collision_avoidance():
    taken = {"u_abcd1234"}
    name = vpn_clients_service._unique_wg_name("u", taken)
    assert name not in taken


def test_list_clients_empty_doc(tmp_path, monkeypatch):
    j = tmp_path / "vpn_clients.json"
    j.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    assert vpn_clients_service.list_clients() == []


def test_list_clients_filters_non_dicts(tmp_path, monkeypatch):
    j = tmp_path / "vpn_clients.json"
    j.write_text('{"clients": [1, {"id": "x"}]}', encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    rows = vpn_clients_service.list_clients()
    assert len(rows) == 1
    assert rows[0]["id"] == "x"


def test_merge_wg_into_document_syncs_fields(tmp_path: Path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text(
        "[Interface]\nAddress = 10.8.0.1/24\n\n"
        "# Client: c1\n"
        "[Peer]\nPublicKey = PK1\nAllowedIPs = 10.8.0.2/32\n",
        encoding="utf-8",
    )
    doc = {
        "clients": [
            {
                "id": "id-1",
                "wg_name": "c1",
                "tunnel_ip": "10.8.0.99",
                "public_key": "wrong",
                "enabled": True,
            }
        ]
    }
    assert vpn_clients_service._merge_wg_into_document(doc, conf) is True
    row = doc["clients"][0]
    assert row["tunnel_ip"] == "10.8.0.2"
    assert row["public_key"] == "PK1"


def test_merge_wg_adds_peer_only_in_conf(tmp_path: Path):
    conf = tmp_path / "wg0.conf"
    conf.write_text(
        "[Interface]\nAddress = 10.8.0.1/24\n\n"
        "# Client: orphan\n"
        "[Peer]\nPublicKey = PKO\nAllowedIPs = 10.8.0.7/32\n",
        encoding="utf-8",
    )
    doc: dict = {"clients": []}
    assert vpn_clients_service._merge_wg_into_document(doc, conf) is True
    assert len(doc["clients"]) == 1
    assert doc["clients"][0]["wg_name"] == "orphan"


def test_sync_clients_json_when_wireguard_disabled(monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    assert vpn_clients_service.sync_clients_json_with_runtime_state() == []


def test_sync_clients_json_when_conf_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "missing.conf"))
    j = tmp_path / "vpn_clients.json"
    j.write_text('{"clients": []}', encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    assert vpn_clients_service.sync_clients_json_with_runtime_state() == []


def test_get_client(tmp_path, monkeypatch):
    cid = str(uuid.uuid4())
    j = tmp_path / "vpn_clients.json"
    j.write_text(json.dumps({"clients": [{"id": cid, "name": "n"}]}), encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    assert vpn_clients_service.get_client(cid)["name"] == "n"
    assert vpn_clients_service.get_client("00000000-0000-0000-0000-000000000000") is None


def test_set_delete_toggle_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    with pytest.raises(KeyError):
        vpn_clients_service.set_client_enabled("x", True)
    with pytest.raises(KeyError):
        vpn_clients_service.delete_client("x")


def test_client_config_text_placeholder(tmp_path, monkeypatch):
    cid = str(uuid.uuid4())
    j = tmp_path / "vpn_clients.json"
    j.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": cid,
                        "name": "U",
                        "tunnel_ip": "10.1.1.1",
                        "private_key_rel": "k.key",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "wg.conf"))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(tmp_path / "cc"))
    text = vpn_clients_service.client_config_text(cid)
    assert "SelfVPN" in text
    assert "10.1.1.1" in text


def test_config_download_basename(tmp_path, monkeypatch):
    cid = str(uuid.uuid4())
    j = tmp_path / "vpn_clients.json"
    j.write_text(
        json.dumps({"clients": [{"id": cid, "name": "My Client"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    name = vpn_clients_service.config_download_basename(cid)
    assert name.endswith(".conf")
    assert cid[:8] in name


def test_qr_png_bytes(tmp_path, monkeypatch):
    cid = str(uuid.uuid4())
    j = tmp_path / "vpn_clients.json"
    j.write_text(
        json.dumps({"clients": [{"id": cid, "name": "Q"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "wg.conf"))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(tmp_path / "cc"))
    png = vpn_clients_service.qr_png_bytes(cid)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


def test_create_client_happy_path(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text(
        "[Interface]\nAddress = 10.9.0.1/24\nPrivateKey = srvpriv\n\n",
        encoding="utf-8",
    )
    keys_dir = tmp_path / "keys"
    cfg_dir = tmp_path / "cfg"
    vpn_json = tmp_path / "vpn_clients.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")

    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(keys_dir))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "host:51820")
    monkeypatch.setattr(settings, "WIREGUARD_NETWORK_CIDR", "")

    with (
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "wg_gen_keypair",
            return_value=("cli_priv", "cli_pub"),
        ),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "server_public_key_from_interface",
            return_value="srv_pub",
        ),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "apply_wg_syncconf_if_configured",
            lambda: None,
        ),
    ):
        row = vpn_clients_service.create_client("Alice")

    assert row["name"] == "Alice"
    assert "wg_name" in row
    peers = wireguard_conf.list_peers_from_conf(conf)
    assert len(peers) == 1
    data = json.loads(vpn_json.read_text(encoding="utf-8"))
    assert len(data["clients"]) == 1


def test_delete_client_removes_peer_and_json(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.9.0.1/24\n\n", encoding="utf-8")
    wireguard_conf.append_peer(conf, "wg_user", "PUB", "10.9.0.2")

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    (keys_dir / "wg_user_private.key").write_text("k\n", encoding="utf-8")
    (keys_dir / "wg_user_public.key").write_text("k\n", encoding="utf-8")
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "qr").mkdir(parents=True)
    (cfg_dir / "wg_user.conf").write_text("x", encoding="utf-8")
    (cfg_dir / "qr" / "wg_user.txt").write_text("x", encoding="utf-8")

    cid = str(uuid.uuid4())
    vpn_json = tmp_path / "vpn_clients.json"
    vpn_json.write_text(
        json.dumps(
            {
                "clients": [
                    {"id": cid, "name": "Bob", "wg_name": "wg_user"},
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(keys_dir))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(cfg_dir))

    with patch.object(
        vpn_clients_service.wg_local_runtime,
        "apply_wg_syncconf_if_configured",
        lambda: None,
    ):
        vpn_clients_service.delete_client(cid)

    assert wireguard_conf.list_peers_from_conf(conf) == []
    data = json.loads(vpn_json.read_text(encoding="utf-8"))
    assert data["clients"] == []
    assert not (keys_dir / "wg_user_private.key").is_file()


def test_create_client_empty_name():
    with pytest.raises(ValueError):
        vpn_clients_service.create_client("  ")


def test_load_document_non_dict_json(tmp_path, monkeypatch):
    j = tmp_path / "vpn_clients.json"
    j.write_text("[1,2,3]", encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    doc = vpn_clients_service._load_document(j)
    assert doc == {"clients": []}


def test_load_document_clients_not_list(tmp_path, monkeypatch):
    j = tmp_path / "vpn_clients.json"
    j.write_text('{"clients": {}}', encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    doc = vpn_clients_service._load_document(j)
    assert doc["clients"] == []


def test_create_client_runtime_no_wg(monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    with pytest.raises(RuntimeError, match="WireGuard"):
        vpn_clients_service.create_client("x")


def test_create_client_missing_conf_file(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "nope.conf"))
    with pytest.raises(RuntimeError, match="Нет файла"):
        vpn_clients_service.create_client("x")


def test_create_client_bad_cidr(monkeypatch, tmp_path):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.1.0.1/24\n", encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "host:51820")
    monkeypatch.setattr(settings, "WIREGUARD_NETWORK_CIDR", "bad")
    with pytest.raises(RuntimeError, match="WIREGUARD_NETWORK_CIDR"):
        vpn_clients_service.create_client("x")


def test_set_client_enabled_toggle(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.9.0.1/24\n\n", encoding="utf-8")
    wireguard_conf.append_peer(conf, "wg_u", "PKEY", "10.9.0.3")
    cid = str(uuid.uuid4())
    vpn_json = tmp_path / "vpn_clients.json"
    vpn_json.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": cid,
                        "wg_name": "wg_u",
                        "enabled": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    with patch.object(
        vpn_clients_service.wg_local_runtime,
        "apply_wg_syncconf_if_configured",
        lambda: None,
    ):
        vpn_clients_service.set_client_enabled(cid, False)
    peers = wireguard_conf.list_peers_from_conf(conf)
    assert wireguard_conf.peer_enabled(peers[0].body_lines) is False
