"""Маршруты Flask (selfvpn_app)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from manage_site import selfvpn_app as app_module
from manage_site import settings


def test_root_redirects_to_login_when_not_authenticated(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_get_ok(client):
    resp = client.get("/login")
    assert resp.status_code == 200


def test_login_post_success_redirects_home(client, monkeypatch, tmp_path):
    digest = hashlib.md5(b"secret-login").hexdigest()
    monkeypatch.setattr(app_module, "_ADMIN_PASSWORD_MD5", digest)
    monkeypatch.setattr(settings, "LOGIN_ATTEMPTS_JSON_PATH", tmp_path / "login_attempts.json")

    resp = client.post(
        "/login",
        data={"password": "secret-login"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")


def test_login_post_wrong_password_shows_error(client, monkeypatch):
    monkeypatch.setattr(app_module, "_ADMIN_PASSWORD_MD5", hashlib.md5(b"good").hexdigest())
    import tempfile

    att = Path(tempfile.mkdtemp()) / "login_attempts.json"
    monkeypatch.setattr(settings, "LOGIN_ATTEMPTS_JSON_PATH", att)
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILED_ATTEMPTS", 99)
    monkeypatch.setattr(settings, "LOGIN_LOCKOUT_MINUTES", 60)

    resp = client.post("/login", data={"password": "bad"})
    assert resp.status_code == 200


def test_login_post_empty_password(client, monkeypatch):
    monkeypatch.setattr(app_module, "_ADMIN_PASSWORD_MD5", hashlib.md5(b"x").hexdigest())
    resp = client.post("/login", data={"password": "  "})
    assert resp.status_code == 200


def test_login_post_config_error_503(client, monkeypatch):
    monkeypatch.setattr(app_module, "_ADMIN_PASSWORD_MD5", None)
    resp = client.post("/login", data={"password": "x"})
    assert resp.status_code == 503


def test_logout_clears_session(authenticated_client):
    resp = authenticated_client.post("/logout", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_home_authenticated_ok(authenticated_client):
    resp = authenticated_client.get("/")
    assert resp.status_code == 200


def test_fmt_lockout_utc_filter(app):
    filt = app.jinja_env.filters["fmt_lockout_utc"]
    dt = datetime(2025, 3, 4, 15, 30, tzinfo=timezone.utc)
    assert "03.2025" in filt(dt)
    assert filt(None) == ""


def test_telegram_proxy_qr_png_404_when_disabled(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", "")
    resp = authenticated_client.get("/telegram-proxy/qr.png")
    assert resp.status_code == 404


def test_telegram_proxy_qr_png_ok(authenticated_client, monkeypatch, tmp_path):
    link = tmp_path / "mt.link"
    link.write_text("tg://proxy?x=1\n", encoding="utf-8")
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(link))
    resp = authenticated_client.get("/telegram-proxy/qr.png")
    assert resp.status_code == 200
    assert resp.mimetype == "image/png"


def test_clients_routes_404_when_wireguard_off(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "")
    cid = "00000000-0000-4000-8000-000000000001"
    assert authenticated_client.post("/clients", data={"name": "x"}).status_code == 404
    assert authenticated_client.post(f"/clients/{cid}/toggle", data={"enabled": "1"}).status_code == 404
    assert authenticated_client.get(f"/clients/{cid}/qr.png").status_code == 404
    assert authenticated_client.get(f"/clients/{cid}/config.conf").status_code == 404
    assert authenticated_client.post(f"/clients/{cid}/delete").status_code == 404


def test_clients_invalid_uuid_returns_404(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(Path("/tmp/wg0.conf")))
    assert authenticated_client.get("/clients/not-a-uuid/qr.png").status_code == 404


def test_admin_password_save(authenticated_client, monkeypatch, tmp_path):
    admin_path = tmp_path / "admin_user.json"
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", admin_path)
    monkeypatch.setattr(app_module, "_ADMIN_PASSWORD_MD5", hashlib.md5(b"old").hexdigest())

    new_pw = "new-secure-password-xyz"
    resp = authenticated_client.post(
        "/account/admin-password",
        data={
            "action": "save",
            "password": new_pw,
            "password_confirm": new_pw,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    data = __import__("json").loads(admin_path.read_text(encoding="utf-8"))
    assert data["password_md5"] == hashlib.md5(new_pw.encode("utf-8")).hexdigest()


def test_admin_password_reset_requires_default(authenticated_client, monkeypatch, tmp_path):
    admin_path = tmp_path / "admin_user.json"
    admin_path.write_text('{"password_md5": "a" * 32}', encoding="utf-8")
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", admin_path)
    monkeypatch.setattr(settings, "ADMIN_DEFAULT_PASSWORD", "")
    resp = authenticated_client.post("/account/admin-password", data={"action": "reset"})
    assert resp.status_code == 302


def test_clients_create_posts(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", str(Path("/no/such/wg.conf")))
    resp = authenticated_client.post("/clients", data={"name": "Someone"}, follow_redirects=False)
    assert resp.status_code == 302


def test_clients_create_with_mock_service(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "/x.conf")
    with patch.object(app_module.vpn_clients_service, "create_client", MagicMock()):
        resp = authenticated_client.post("/clients", data={"name": "X"}, follow_redirects=False)
    assert resp.status_code == 302


def test_clients_toggle_delete_keyerror_404(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "/x.conf")
    cid = "00000000-0000-4000-8000-000000000099"
    with patch.object(
        app_module.vpn_clients_service,
        "set_client_enabled",
        side_effect=KeyError(cid),
    ):
        r = authenticated_client.post(f"/clients/{cid}/toggle", data={"enabled": "1"})
    assert r.status_code == 404


def test_login_post_when_locked(client, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "_ADMIN_PASSWORD_MD5", hashlib.md5(b"x").hexdigest())
    att = tmp_path / "login_attempts.json"
    future = "2099-01-01T00:00:00+00:00"
    att.write_text(
        '{"192.0.2.9": {"failures": 0, "locked_until": "%s"}}' % future,
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "LOGIN_ATTEMPTS_JSON_PATH", att)
    monkeypatch.setattr(app_module, "_client_ip", lambda: "192.0.2.9")
    resp = client.post("/login", data={"password": "x"})
    assert resp.status_code == 200


def test_admin_password_mismatch(authenticated_client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", tmp_path / "admin.json")
    resp = authenticated_client.post(
        "/account/admin-password",
        data={"action": "save", "password": "a", "password_confirm": "b"},
        follow_redirects=False,
    )
    assert resp.status_code == 302


def test_admin_password_save_invalid_md5_path(authenticated_client, monkeypatch, tmp_path):
    """save_password_md5_hex raises ValueError — flash error."""
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", tmp_path / "admin.json")

    def boom(_: str) -> None:
        raise ValueError("bad")

    with patch.object(app_module.admin_user_store, "save_password_md5_hex", boom):
        resp = authenticated_client.post(
            "/account/admin-password",
            data={"action": "save", "password": "ok", "password_confirm": "ok"},
            follow_redirects=False,
        )
    assert resp.status_code == 302


def test_clients_config_qr_keyerror_404(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "/x.conf")
    cid = "00000000-0000-4000-8000-000000000088"
    with patch.object(
        app_module.vpn_clients_service,
        "client_config_bytes",
        side_effect=KeyError(cid),
    ):
        r = authenticated_client.get(f"/clients/{cid}/config.conf")
    assert r.status_code == 404


def test_clients_qr_keyerror_404(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "/x.conf")
    cid = "00000000-0000-4000-8000-000000000077"
    with patch.object(
        app_module.vpn_clients_service,
        "qr_png_bytes",
        side_effect=KeyError(cid),
    ):
        r = authenticated_client.get(f"/clients/{cid}/qr.png")
    assert r.status_code == 404


def test_clients_delete_keyerror_404(authenticated_client, monkeypatch):
    monkeypatch.setattr(settings, "WIREGUARD_CONF_PATH", "/x.conf")
    cid = "00000000-0000-4000-8000-000000000066"
    with patch.object(
        app_module.vpn_clients_service,
        "delete_client",
        side_effect=KeyError(cid),
    ):
        r = authenticated_client.post(f"/clients/{cid}/delete")
    assert r.status_code == 404


def test_telegram_proxy_qr_png_abort_on_bad_qr(authenticated_client, monkeypatch, tmp_path):
    link = tmp_path / "mt.link"
    link.write_text("tg://x\n", encoding="utf-8")
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(link))
    with patch.object(
        app_module.telegram_proxy_qr,
        "build_mtproxy_qr_png",
        side_effect=ValueError("bad"),
    ):
        resp = authenticated_client.get("/telegram-proxy/qr.png")
    assert resp.status_code == 404


def test_telegram_proxy_qr_png_missing_link_file_404(authenticated_client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(tmp_path / "missing.link"))
    assert authenticated_client.get("/telegram-proxy/qr.png").status_code == 404
