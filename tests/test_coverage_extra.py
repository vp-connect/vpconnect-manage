"""Дополнительные тесты для веток и строк, ранее не покрытых coverage."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from manage_site import admin_user_store
from manage_site import login_attempts_store
from manage_site import mtproxy_link
from manage_site import selfvpn_app as app_module
from manage_site import settings
from manage_site import vpn_clients_service
from manage_site import wg_background_sync
from manage_site import wg_local_runtime
from manage_site import wireguard_conf


def test_admin_save_password_corrupt_existing_json(tmp_path, monkeypatch):
    """Сломанный admin_user.json при сохранении пароля — сброс doc (admin_user_store 68–69)."""
    path = tmp_path / "admin_user.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", path)
    digest = hashlib.md5(b"pw").hexdigest()
    admin_user_store.save_password_md5_hex(digest)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["password_md5"] == digest


def test_login_prune_non_dict_entry(tmp_path, monkeypatch):
    path = tmp_path / "la.json"
    path.write_text('{"1.2.3.4": "bad"}', encoding="utf-8")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(login_attempts_store, "_utcnow", lambda: now)
    login_attempts_store.purge_expired(path)
    assert login_attempts_store._load_raw(path) == {}


def test_login_is_locked_expired_lock_cleared(tmp_path, monkeypatch):
    path = tmp_path / "la.json"
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    past = (now - timedelta(minutes=1)).isoformat()
    path.write_text(
        '{"9.9.9.9": {"failures": 1, "locked_until": "%s"}}' % past,
        encoding="utf-8",
    )
    monkeypatch.setattr(login_attempts_store, "_utcnow", lambda: now)
    locked, until = login_attempts_store.is_locked(path, "9.9.9.9")
    assert locked is False
    data = login_attempts_store._load_raw(path)
    assert "locked_until" not in data.get("9.9.9.9", {})


def test_login_is_locked_entry_not_dict(tmp_path, monkeypatch):
    path = tmp_path / "la.json"
    path.write_text('{"9.9.9.9": []}', encoding="utf-8")
    monkeypatch.setattr(
        login_attempts_store,
        "_utcnow",
        lambda: datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    locked, _ = login_attempts_store.is_locked(path, "9.9.9.9")
    assert locked is False


def test_login_record_failure_resets_non_dict_entry(tmp_path, monkeypatch):
    path = tmp_path / "la.json"
    path.write_text('{"9.9.9.9": []}', encoding="utf-8")
    monkeypatch.setattr(
        login_attempts_store,
        "_utcnow",
        lambda: datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    login_attempts_store.record_failure(path, "9.9.9.9", max_attempts=5, lockout_minutes=10)
    data = login_attempts_store._load_raw(path)
    assert isinstance(data["9.9.9.9"], dict)
    assert data["9.9.9.9"].get("failures", 0) >= 1


def test_login_record_failure_bad_locked_until_popped(tmp_path, monkeypatch):
    path = tmp_path / "la.json"
    path.write_text(
        '{"9.9.9.9": {"failures": 0, "locked_until": "not-a-date"}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        login_attempts_store,
        "_utcnow",
        lambda: datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    login_attempts_store.record_failure(path, "9.9.9.9", max_attempts=2, lockout_minutes=10)
    data = login_attempts_store._load_raw(path)
    assert "locked_until" not in data["9.9.9.9"] or data["9.9.9.9"]["failures"] >= 1


def test_mtproxy_absolute_path(tmp_path, monkeypatch):
    f = tmp_path / "abs.link"
    f.write_text("https://mt\n", encoding="utf-8")
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(f.resolve()))
    assert mtproxy_link.read_mtproxy_link() == "https://mt"


def test_mtproxy_empty_lines_only(tmp_path, monkeypatch):
    f = tmp_path / "empty.link"
    f.write_text("  \n\t\n  \n", encoding="utf-8")
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(f))
    assert mtproxy_link.read_mtproxy_link() is None


def test_selfvpn_load_admin_md5_oserror(tmp_path, monkeypatch):
    """_load_admin_password_md5: OSError при чтении файла."""
    path = tmp_path / "admin_user.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", path)
    with patch.object(Path, "open", side_effect=OSError("denied")):
        assert app_module._load_admin_password_md5() is None


def test_selfvpn_load_admin_md5_bad_json(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", tmp_path / "admin_user.json")
    p = tmp_path / "admin_user.json"
    p.write_text("{", encoding="utf-8")
    assert app_module._load_admin_password_md5() is None


def test_selfvpn_load_admin_md5_password_not_str(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", tmp_path / "admin_user.json")
    p = tmp_path / "admin_user.json"
    p.write_text('{"password_md5": 123}', encoding="utf-8")
    assert app_module._load_admin_password_md5() is None


def test_selfvpn_password_ok_bad_stored_length(monkeypatch):
    monkeypatch.setattr(app_module, "_ADMIN_PASSWORD_MD5", "short")
    assert app_module._password_ok("any") is False


def test_selfvpn_fmt_lockout_naive_and_aware_datetime(app):
    filt = app.jinja_env.filters["fmt_lockout_utc"]
    naive = datetime(2024, 1, 2, 3, 4, 5)
    assert "UTC" in filt(naive)
    aware = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=3)))
    assert "UTC" in filt(aware)


def test_wireguard_parse_peer_no_match():
    assert wireguard_conf.parse_peer_public_key(["AllowedIPs = 1.1.1.1/32"]) is None
    assert wireguard_conf.parse_peer_tunnel_ip(["PublicKey = x"]) is None


def test_wireguard_parse_wg_conf_marker_not_at_line_start(tmp_path: Path):
    """Строка с маркером не в начале — idx += 1 (wireguard_conf 104–105)."""
    p = tmp_path / "wg.conf"
    p.write_text(
        "# Client: a\n[Peer]\nPublicKey = k\nAllowedIPs = 10.0.0.2/32\n"
        " # Client: b\n[Peer]\nPublicKey = k2\nAllowedIPs = 10.0.0.3/32\n",
        encoding="utf-8",
    )
    _, peers = wireguard_conf.parse_wg_conf(p)
    assert len(peers) >= 1


def test_wireguard_subnet_cidr_invalid_ip_octets():
    with pytest.raises(ValueError):
        wireguard_conf.subnet_prefix_from_network_cidr("10.10/24")


@patch("manage_site.wireguard_conf.subprocess.run", side_effect=FileNotFoundError())
def test_try_run_wg_syncconf_file_not_found(mock_run, tmp_path):
    unified = Path("/etc/wireguard/wg0.conf")
    warns: list[str] = []

    def logw(m: str) -> None:
        warns.append(m)

    with patch.object(Path, "resolve", lambda self: unified):
        wireguard_conf.try_run_wg_syncconf("wg0", unified, logw)
    assert any("не найден" in w or "пропущен" in w for w in warns)


@patch("manage_site.wireguard_conf.subprocess.run", side_effect=OSError("boom"))
def test_try_run_wg_syncconf_oserror(mock_run, tmp_path):
    unified = Path("/etc/wireguard/wg0.conf")
    warns: list[str] = []

    def logw(m: str) -> None:
        warns.append(m)

    with patch.object(Path, "resolve", lambda self: unified):
        wireguard_conf.try_run_wg_syncconf("wg0", unified, logw)
    assert warns


@patch("manage_site.wireguard_conf.subprocess.run")
def test_try_run_wg_syncconf_called_process_error(mock_run, tmp_path):
    import subprocess as sp

    unified = Path("/etc/wireguard/wg0.conf")
    mock_run.side_effect = sp.CalledProcessError(1, "bash", stderr="err", output="")
    warns: list[str] = []

    def logw(m: str) -> None:
        warns.append(m)

    with patch.object(Path, "resolve", lambda self: unified):
        wireguard_conf.try_run_wg_syncconf("wg0", unified, logw)
    assert warns and "ошибк" in warns[0]


def test_wg_listen_port_no_match(tmp_path: Path):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    assert wg_local_runtime.listen_port_from_server_preamble(conf) is None


@patch("manage_site.wg_local_runtime.subprocess.run", side_effect=RuntimeError("wg down"))
def test_wg_show_public_key_swallows_exception(_mock_run, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_INTERFACE_NAME", "wg0")
    assert wg_local_runtime._wg_show_interface_public_key() is None


def test_wg_expand_private_key_read_oserror(tmp_path: Path):
    keyfile = tmp_path / "srv.key"
    keyfile.write_text("secret\n", encoding="utf-8")
    conf = tmp_path / "wg.conf"
    conf.write_text(f"[Interface]\nPrivateKey = {keyfile.as_posix()}\n", encoding="utf-8")

    real_read = Path.read_text

    def read_text_selective(self, encoding="utf-8", errors=None):
        try:
            resolved = self.resolve()
        except OSError:
            resolved = self
        if resolved == keyfile.resolve():
            raise OSError("read fail")
        return real_read(self, encoding=encoding, errors=errors)

    with patch.object(Path, "read_text", read_text_selective):
        assert wg_local_runtime.server_public_key_from_interface(conf) is None


def test_wg_gen_keypair_called_process_error(monkeypatch):
    import subprocess as sp

    with patch(
        "manage_site.wg_local_runtime.subprocess.run",
        side_effect=sp.CalledProcessError(1, "wg", stderr="fail", output=""),
    ):
        with pytest.raises(RuntimeError, match="Ошибка генерации"):
            wg_local_runtime.wg_gen_keypair()


def test_wg_write_client_conf_network_cidr_branch(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_NETWORK_CIDR", "10.20.0.1/24")
    monkeypatch.setattr(settings, "WIREGUARD_DNS", "9.9.9.9")
    p = wg_local_runtime.write_client_conf_file(
        tmp_path,
        "cl1",
        "priv",
        "10.20.0.5",
        "srvpub",
        "h:1",
    )
    body = p.read_text(encoding="utf-8")
    assert "Address = 10.20.0.5/24" in body


def test_wg_write_client_conf_chmod_oserror(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_NETWORK_CIDR", "")
    with patch("manage_site.wg_local_runtime.os.chmod", side_effect=OSError("chmod")):
        p = wg_local_runtime.write_client_conf_file(
            tmp_path,
            "cl2",
            "priv",
            "10.1.1.1",
            "srv",
            "e:1",
        )
    assert p.is_file()


def test_wg_apply_syncconf_when_enabled(monkeypatch, tmp_path):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\n", encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "WIREGUARD_INTERFACE_NAME", "wg0")
    with patch("manage_site.wg_local_runtime.wireguard_conf.try_run_wg_syncconf") as m:
        wg_local_runtime.apply_wg_syncconf_if_configured()
    m.assert_called_once()


def test_vpn_keys_base_path_relative(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", "rel_keys")
    p = vpn_clients_service._keys_base_path()
    assert p == (tmp_path / "rel_keys").resolve()


def test_vpn_client_config_dir_relative_raw(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", "my_cc")
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(tmp_path / "k"))
    (tmp_path / "k").mkdir()
    d = vpn_clients_service._client_config_dir()
    assert d == (tmp_path / "my_cc").resolve()


def test_vpn_load_document_invalid_json_raises(tmp_path, monkeypatch):
    j = tmp_path / "bad.json"
    j.write_text("{", encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", j)
    with pytest.raises(json.JSONDecodeError):
        vpn_clients_service._load_document(j)


def test_vpn_unique_wg_name_collision_loop(monkeypatch):
    taken = {"user_abcd1234", "user_abcd1234_1"}
    with patch("manage_site.vpn_clients_service.uuid.uuid4", return_value=MagicMock(hex="abcd12340000")):
        name = vpn_clients_service._unique_wg_name("user", taken)
    assert name.endswith("_2")


def test_vpn_merge_row_enabled_only_change():
    peer = wireguard_conf.WgPeerBlock(
        name="p",
        body_lines=["# all commented"],
    )
    row: dict = {"wg_name": "p", "enabled": True}
    assert vpn_clients_service._merge_row_with_peer(row, peer) is True
    assert row["enabled"] is False


def test_vpn_collect_skips_bad_wg_name():
    by_wg = {"ok": wireguard_conf.WgPeerBlock(name="ok", body_lines=["AllowedIPs = 10.0.0.2/32"])}
    clients: list = [
        {"wg_name": 123},
        {"wg_name": "  "},
        {"wg_name": "missing", "id": "1"},
        {"wg_name": "ok", "id": "2", "tunnel_ip": "10.0.0.2"},
    ]
    kept, seen, changed = vpn_clients_service._collect_kept_clients_from_json(clients, by_wg)
    assert changed is True
    assert len(kept) == 1
    assert kept[0]["id"] == "2"


def test_vpn_append_conf_peer_skips_no_tunnel_ip():
    by_wg = {
        "nope": wireguard_conf.WgPeerBlock(
            name="nope",
            body_lines=["[Peer]", "PublicKey = x"],
        )
    }
    kept: list = []
    assert vpn_clients_service._append_json_rows_for_conf_only_peers(by_wg, set(), kept) is False


def test_vpn_merge_wg_doc_clients_not_list(tmp_path: Path):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.5.0.1/24\n", encoding="utf-8")
    doc = {"clients": "not-a-list"}
    assert vpn_clients_service._merge_wg_into_document(doc, conf) is False


def test_vpn_merge_wg_no_change_returns_false(tmp_path: Path, monkeypatch):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.6.0.1/24\n", encoding="utf-8")
    doc = {"clients": []}
    assert vpn_clients_service._merge_wg_into_document(doc, conf) is False


def test_vpn_sync_saves_after_merge(tmp_path, monkeypatch):
    conf = tmp_path / "wg.conf"
    conf.write_text(
        "[Interface]\nAddress = 10.7.0.1/24\n\n# Client: only\n[Peer]\nPublicKey = z\n"
        "AllowedIPs = 10.7.0.2/32\n",
        encoding="utf-8",
    )
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    vpn_clients_service.sync_clients_json_with_runtime_state()
    data = json.loads(vpn_json.read_text(encoding="utf-8"))
    assert len(data["clients"]) >= 1


def test_vpn_create_client_rollback_on_write_conf_fail(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.11.0.1/24\n", encoding="utf-8")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")
    keys = tmp_path / "keys"
    keys.mkdir()
    cc = tmp_path / "cc"
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(keys))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(cc))
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "h:1")

    with (
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "wg_gen_keypair",
            return_value=("priv", "pub"),
        ),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "server_public_key_from_interface",
            return_value="srv",
        ),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "write_client_conf_file",
            side_effect=RuntimeError("write fail"),
        ),
        patch.object(vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None),
    ):
        with pytest.raises(RuntimeError, match="write fail"):
            vpn_clients_service.create_client("Z")

    assert wireguard_conf.list_peers_from_conf(conf) == []


def test_vpn_create_client_chmod_oserror_continues(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.12.0.1/24\n", encoding="utf-8")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(tmp_path / "cc"))
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "h:1")
    monkeypatch.setattr(settings, "WIREGUARD_NETWORK_CIDR", "")

    chmod_calls = {"n": 0}

    def chmod_fail(path, mode):
        chmod_calls["n"] += 1
        raise OSError("chmod")

    with (
        patch("manage_site.vpn_clients_service.os.chmod", chmod_fail),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "wg_gen_keypair",
            return_value=("priv", "pub"),
        ),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "server_public_key_from_interface",
            return_value="srvpub",
        ),
        patch.object(vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None),
    ):
        vpn_clients_service.create_client("ChmodUser")

    assert chmod_calls["n"] >= 2


def test_vpn_set_client_bad_wg_name_raises(tmp_path, monkeypatch):
    cid = "00000000-0000-4000-8000-000000000011"
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "wg_name": ""}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "w.conf"))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    (tmp_path / "w.conf").write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    with pytest.raises(KeyError):
        vpn_clients_service.set_client_enabled(cid, True)


def test_vpn_set_client_toggle_conf_fails_raises(tmp_path, monkeypatch):
    cid = "00000000-0000-4000-8000-000000000012"
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "wg_name": "ghost"}]}),
        encoding="utf-8",
    )
    conf = tmp_path / "w.conf"
    conf.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    with (
        patch(
            "manage_site.vpn_clients_service.wireguard_conf.set_peer_block_enabled",
            return_value=False,
        ),
        patch.object(vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None),
    ):
        with pytest.raises(KeyError):
            vpn_clients_service.set_client_enabled(cid, False)


def test_vpn_unlink_oserror_swallowed(tmp_path):
    p = tmp_path / "x"
    p.write_text("z", encoding="utf-8")

    def boom(self, missing_ok=True):
        raise OSError("unlink")

    with patch.object(Path, "unlink", boom):
        vpn_clients_service._unlink_optional_paths((p,))


def test_vpn_delete_without_wg_name_json_only(tmp_path, monkeypatch):
    cid = "00000000-0000-4000-8000-000000000013"
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "name": "no wg"}]}),
        encoding="utf-8",
    )
    conf = tmp_path / "w.conf"
    conf.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    with patch.object(vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None):
        vpn_clients_service.delete_client(cid)
    assert json.loads(vpn_json.read_text(encoding="utf-8"))["clients"] == []


def test_vpn_client_config_reads_existing_file(tmp_path, monkeypatch):
    cid = "00000000-0000-4000-8000-000000000014"
    wgn = "wgfile"
    cc = tmp_path / "cc"
    cc.mkdir(parents=True, exist_ok=True)
    (cc / f"{wgn}.conf").write_text("[Interface]\nPrivateKey = x\n", encoding="utf-8")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "wg_name": wgn}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "w.conf"))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(cc))
    text = vpn_clients_service.client_config_text(cid)
    assert "[Interface]" in text
    assert "PrivateKey = x" in text


def test_wg_background_sync_register_logs_sync_exception(monkeypatch):
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_CONF_PATH", "/x.conf")
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_SYNC_INTERVAL_MINUTES", 0)
    app = __import__("flask").Flask(__name__)
    with patch.object(
        wg_background_sync.vpn_clients_service,
        "sync_clients_json_with_runtime_state",
        side_effect=RuntimeError("sync boom"),
    ):
        wg_background_sync.register_wireguard_background_sync(app)


def test_wg_background_loop_logs_exception(monkeypatch):
    monkeypatch.setattr(wg_background_sync.settings, "WIREGUARD_SYNC_INTERVAL_MINUTES", 1)
    app = __import__("flask").Flask(__name__)

    def sleep_zero(_):
        monkeypatch.setattr(
            wg_background_sync.settings,
            "WIREGUARD_SYNC_INTERVAL_MINUTES",
            0,
        )

    with (
        patch("manage_site.wg_background_sync.time.sleep", sleep_zero),
        patch.object(
            wg_background_sync.vpn_clients_service,
            "sync_clients_json_with_runtime_state",
            side_effect=ValueError("loop err"),
        ),
    ):
        wg_background_sync._background_loop(app)


def test_mtproxy_relative_path_from_repo_root(monkeypatch):
    """Ветка ``_resolved_path``: относительный путь от корня репозитория (mtproxy_link 23)."""
    name = "pytest_mtproxy_rel_link.txt"
    target = mtproxy_link._REPO_ROOT / name
    try:
        target.write_text("relative-ok\n", encoding="utf-8")
        monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", name)
        assert mtproxy_link.read_mtproxy_link() == "relative-ok"
    finally:
        if target.is_file():
            target.unlink()


def test_wireguard_parse_conf_skips_non_marker_lines(tmp_path: Path):
    """Строка без маркера клиента — увеличение idx (104–105)."""
    p = tmp_path / "wg.conf"
    p.write_text(
        "# Client: first\n[Peer]\nPublicKey = a\nAllowedIPs = 10.0.0.2/32\n"
        "\n"
        "garbage-between-peers\n"
        "# Client: second\n[Peer]\nPublicKey = b\nAllowedIPs = 10.0.0.3/32\n",
        encoding="utf-8",
    )
    _, peers = wireguard_conf.parse_wg_conf(p)
    assert len(peers) == 2


def test_wg_interface_private_key_missing_returns_none(tmp_path: Path):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    assert wg_local_runtime._interface_private_key_from_conf(conf) is None


def test_wg_server_public_key_stops_when_no_private_raw(tmp_path: Path):
    """``priv_raw`` пуст — ранний выход (wg_local_runtime 132–134)."""
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    with patch.object(wg_local_runtime, "_wg_show_interface_public_key", return_value=None):
        assert wg_local_runtime.server_public_key_from_interface(conf) is None


def test_wg_expand_private_key_missing_file(tmp_path: Path):
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nPrivateKey = /no/such/keyfile.key\n", encoding="utf-8")
    assert wg_local_runtime.server_public_key_from_interface(conf) is None


def test_wg_public_key_from_private_errors():
    with patch(
        "manage_site.wg_local_runtime.subprocess.run",
        side_effect=__import__("subprocess").CalledProcessError(1, "wg"),
    ):
        assert wg_local_runtime._public_key_from_private("x") is None


def test_wg_public_key_from_private_file_not_found():
    with patch(
        "manage_site.wg_local_runtime.subprocess.run",
        side_effect=FileNotFoundError(),
    ):
        assert wg_local_runtime._public_key_from_private("x") is None


def test_vpn_client_config_dir_fallback_next_to_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", "")
    keys = tmp_path / "vpnkeys"
    keys.mkdir()
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(keys))
    d = vpn_clients_service._client_config_dir()
    assert d.name == "client_config"
    assert d == keys.resolve().parent / "client_config"


def test_vpn_load_document_missing_file_returns_empty(tmp_path: Path):
    missing = tmp_path / "nope.json"
    doc = vpn_clients_service._load_document(missing)
    assert doc == {"clients": []}


def test_vpn_rollback_unlink_second_file_oserror(tmp_path):
    conf = tmp_path / "w.conf"
    conf.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    priv = tmp_path / "a.key"
    pub = tmp_path / "b.key"
    priv.write_text("x", encoding="utf-8")
    pub.write_text("y", encoding="utf-8")
    calls = {"n": 0}
    orig_unlink = Path.unlink

    def unlink_fail(self, missing_ok=True):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("second unlink")
        return orig_unlink(self, missing_ok=missing_ok)

    wireguard_conf.append_peer(conf, "peerx", "PUB", "10.0.0.2")
    with patch.object(Path, "unlink", unlink_fail):
        vpn_clients_service._rollback_created_peer_files(conf, "peerx", priv, pub)


def test_vpn_create_client_server_public_key_none_raises(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.30.0.1/24\n", encoding="utf-8")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(tmp_path / "cc"))
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "h:1")
    with (
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "wg_gen_keypair",
            return_value=("priv", "pub"),
        ),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "server_public_key_from_interface",
            return_value=None,
        ),
        patch.object(vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None),
    ):
        with pytest.raises(RuntimeError, match="публичный ключ"):
            vpn_clients_service.create_client("NoSrvPub")


def test_vpn_create_client_taken_wg_names_from_json(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.31.0.1/24\n", encoding="utf-8")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": "1", "wg_name": "existing_wg"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(tmp_path / "cc"))
    monkeypatch.setattr(settings, "WIREGUARD_ENDPOINT", "h:1")
    monkeypatch.setattr(settings, "WIREGUARD_NETWORK_CIDR", "")
    with (
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "wg_gen_keypair",
            return_value=("priv", "pub"),
        ),
        patch.object(
            vpn_clients_service.wg_local_runtime,
            "server_public_key_from_interface",
            return_value="srv",
        ),
        patch.object(vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None),
    ):
        vpn_clients_service.create_client("NewUser")


def test_vpn_set_client_unknown_id_raises(tmp_path, monkeypatch):
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "w.conf"))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    (tmp_path / "w.conf").write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    with pytest.raises(KeyError):
        vpn_clients_service.set_client_enabled("00000000-0000-4000-8000-000000009999", True)


def test_vpn_delete_unknown_id_raises(tmp_path, monkeypatch):
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "w.conf"))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    with pytest.raises(KeyError):
        vpn_clients_service.delete_client("00000000-0000-4000-8000-000000008888")


def test_vpn_client_config_helpers_keyerror(monkeypatch, tmp_path):
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text('{"clients": []}', encoding="utf-8")
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    cid = "00000000-0000-4000-8000-000000000001"
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "w.conf"))
    with pytest.raises(KeyError):
        vpn_clients_service.client_config_text(cid)
    with pytest.raises(KeyError):
        vpn_clients_service.client_config_bytes(cid)
    with pytest.raises(KeyError):
        vpn_clients_service.config_download_basename(cid)
    with pytest.raises(KeyError):
        vpn_clients_service.qr_png_bytes(cid)


def test_login_is_locked_parse_error_on_locked_until(tmp_path, monkeypatch):
    """Битый ``locked_until`` в ``is_locked``: ветка except (106–108); ``_prune`` иначе удаляет запись."""
    path = tmp_path / "la.json"
    path.write_text(
        '{"1.1.1.1": {"failures": 0, "locked_until": "not-valid-iso!!!"}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        login_attempts_store,
        "_utcnow",
        lambda: datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(login_attempts_store, "_prune", lambda *_args, **_kwargs: None)
    locked, _ = login_attempts_store.is_locked(path, "1.1.1.1")
    assert locked is False


def test_login_record_failure_entry_null_json(tmp_path, monkeypatch):
    """``setdefault`` вернул не dict (134–135); ``_prune`` иначе убирает ``null``."""
    path = tmp_path / "la.json"
    path.write_text('{"9.8.7.6": null}', encoding="utf-8")
    monkeypatch.setattr(
        login_attempts_store,
        "_utcnow",
        lambda: datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(login_attempts_store, "_prune", lambda *_args, **_kwargs: None)
    login_attempts_store.record_failure(path, "9.8.7.6", max_attempts=5, lockout_minutes=10)
    data = login_attempts_store._load_raw(path)
    assert isinstance(data["9.8.7.6"], dict)


def test_login_record_failure_invalid_locked_until_then_count(tmp_path, monkeypatch):
    """Ошибка разбора ``locked_until`` в record_failure (142–143)."""
    path = tmp_path / "la.json"
    path.write_text(
        '{"5.5.5.5": {"failures": 0, "locked_until": "!!!"}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        login_attempts_store,
        "_utcnow",
        lambda: datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(login_attempts_store, "_prune", lambda *_args, **_kwargs: None)
    login_attempts_store.record_failure(path, "5.5.5.5", max_attempts=99, lockout_minutes=10)
    data = login_attempts_store._load_raw(path)
    assert "locked_until" not in data["5.5.5.5"]
    assert int(data["5.5.5.5"].get("failures") or 0) >= 1


def test_selfvpn_admin_reset_success(authenticated_client, monkeypatch, tmp_path):
    admin_path = tmp_path / "admin.json"
    admin_path.write_text(
        '{"password_md5": "%s"}' % ("a" * 32),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", admin_path)
    monkeypatch.setattr(settings, "ADMIN_DEFAULT_PASSWORD", "reset-me-123")
    resp = authenticated_client.post(
        "/account/admin-password",
        data={"action": "reset"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    data = json.loads(admin_path.read_text(encoding="utf-8"))
    assert data["password_md5"] == hashlib.md5(b"reset-me-123").hexdigest()


def test_selfvpn_admin_save_empty_passwords(authenticated_client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", tmp_path / "admin.json")
    resp = authenticated_client.post(
        "/account/admin-password",
        data={"action": "save", "password": "", "password_confirm": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 302


def test_selfvpn_admin_password_unknown_action_redirects(authenticated_client):
    resp = authenticated_client.post(
        "/account/admin-password",
        data={"action": "other"},
        follow_redirects=False,
    )
    assert resp.status_code == 302


def test_selfvpn_clients_create_generic_exception(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(Path("/tmp/wg0.conf")))
    with patch.object(
        app_module.vpn_clients_service,
        "create_client",
        side_effect=TypeError("boom"),
    ):
        resp = authenticated_client.post("/clients", data={"name": "X"}, follow_redirects=False)
    assert resp.status_code == 302


def test_selfvpn_login_redirect_when_already_authenticated(authenticated_client):
    resp = authenticated_client.get("/login", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")


def test_selfvpn_clients_toggle_success(authenticated_client, monkeypatch, tmp_path):
    cid = "00000000-0000-4000-8000-000000000020"
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.40.0.1/24\n", encoding="utf-8")
    wireguard_conf.append_peer(conf, "wg_toggle", "PK", "10.40.0.2")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "wg_name": "wg_toggle", "enabled": True}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    with patch.object(app_module.vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None):
        resp = authenticated_client.post(
            f"/clients/{cid}/toggle",
            data={"enabled": "0"},
            follow_redirects=False,
        )
    assert resp.status_code == 302


def test_selfvpn_clients_qr_and_config_success(authenticated_client, monkeypatch, tmp_path):
    cid = "00000000-0000-4000-8000-000000000021"
    wgn = "wg_dl"
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.41.0.1/24\n", encoding="utf-8")
    wireguard_conf.append_peer(conf, wgn, "PK", "10.41.0.2")
    cc = tmp_path / "cc"
    cc.mkdir(parents=True)
    (cc / f"{wgn}.conf").write_text("[Interface]\nPrivateKey = z\n", encoding="utf-8")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "name": "DL", "wg_name": wgn}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(cc))
    r1 = authenticated_client.get(f"/clients/{cid}/qr.png")
    assert r1.status_code == 200
    r2 = authenticated_client.get(f"/clients/{cid}/config.conf")
    assert r2.status_code == 200
    assert b"PrivateKey" in r2.data


def test_vpn_delete_client_rest_branch(tmp_path, monkeypatch):
    """Ветка ``else: rest.append(c)`` при поиске жертвы (vpn_clients_service ~459)."""
    a = "00000000-0000-4000-8000-000000000030"
    b = "00000000-0000-4000-8000-000000000031"
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps(
            {
                "clients": [
                    {"id": a, "name": "keep"},
                    {"id": b, "name": "go", "wg_name": ""},
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(tmp_path / "w.conf"))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    (tmp_path / "w.conf").write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    vpn_clients_service.delete_client(b)
    rows = json.loads(vpn_json.read_text(encoding="utf-8"))["clients"]
    assert len(rows) == 1
    assert rows[0]["id"] == a


def test_vpn_client_config_text_raises_when_wireguard_off(tmp_path, monkeypatch):
    cid = "00000000-0000-4000-8000-000000000040"
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "wg_name": "w"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    with pytest.raises(KeyError):
        vpn_clients_service.client_config_text(cid)


def test_wg_syncconf_log_warning_calls_logger():
    with patch.object(wg_local_runtime._log, "warning") as m:
        wg_local_runtime._syncconf_log_warning("hello")
    m.assert_called_once()


def test_selfvpn_admin_reset_save_value_error(authenticated_client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "ADMIN_DEFAULT_PASSWORD", "default-pw")
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", tmp_path / "admin.json")

    def bad_save(_h: str) -> None:
        raise ValueError("no")

    with patch.object(app_module.admin_user_store, "save_password_md5_hex", bad_save):
        resp = authenticated_client.post(
            "/account/admin-password",
            data={"action": "reset"},
            follow_redirects=False,
        )
    assert resp.status_code == 302


def test_selfvpn_clients_delete_success(authenticated_client, monkeypatch, tmp_path):
    cid = "00000000-0000-4000-8000-000000000022"
    wgn = "wg_del"
    conf = tmp_path / "wg.conf"
    conf.write_text("[Interface]\nAddress = 10.42.0.1/24\n", encoding="utf-8")
    wireguard_conf.append_peer(conf, wgn, "PK", "10.42.0.2")
    vpn_json = tmp_path / "vpn.json"
    vpn_json.write_text(
        json.dumps({"clients": [{"id": cid, "wg_name": wgn}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(conf))
    monkeypatch.setattr(settings, "VPN_CLIENTS_JSON_PATH", vpn_json)
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(settings, "WIREGUARD_CLIENT_CONFIG_DIR", str(tmp_path / "cc"))
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "cc").mkdir(parents=True, exist_ok=True)
    with patch.object(app_module.vpn_clients_service.wg_local_runtime, "apply_wg_syncconf_if_configured", lambda: None):
        resp = authenticated_client.post(f"/clients/{cid}/delete", follow_redirects=False)
    assert resp.status_code == 302
