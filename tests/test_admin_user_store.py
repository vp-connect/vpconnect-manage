"""admin_user.json (admin_user_store)."""

from __future__ import annotations

import hashlib
import json

import pytest

from manage_site import admin_user_store
from manage_site import settings


def test_save_password_md5_hex_invalid():
    with pytest.raises(ValueError):
        admin_user_store.save_password_md5_hex("not-md5")
    with pytest.raises(ValueError):
        admin_user_store.save_password_md5_hex("G" * 32)


def test_save_password_md5_hex_writes(tmp_path, monkeypatch):
    path = tmp_path / "admin_user.json"
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", path)
    digest = hashlib.md5(b"pw").hexdigest()
    admin_user_store.save_password_md5_hex(digest.upper())
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["password_md5"] == digest


def test_save_password_merges_existing(tmp_path, monkeypatch):
    path = tmp_path / "admin_user.json"
    path.write_text('{"other": 1}', encoding="utf-8")
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", path)
    digest = hashlib.md5(b"x").hexdigest()
    admin_user_store.save_password_md5_hex(digest)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["other"] == 1
    assert data["password_md5"] == digest


def test_ensure_admin_user_from_default_password(tmp_path, monkeypatch):
    path = tmp_path / "admin_user.json"
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", path)
    monkeypatch.setattr(settings, "ADMIN_DEFAULT_PASSWORD", "  secret  ")
    assert admin_user_store.ensure_admin_user_from_default_password() is True
    assert path.is_file()
    assert admin_user_store.ensure_admin_user_from_default_password() is False


def test_ensure_admin_skips_without_default(tmp_path, monkeypatch):
    path = tmp_path / "admin_user.json"
    monkeypatch.setattr(settings, "ADMIN_USER_JSON_PATH", path)
    monkeypatch.setattr(settings, "ADMIN_DEFAULT_PASSWORD", "")
    assert admin_user_store.ensure_admin_user_from_default_password() is False
