"""Чтение файла MTProxy (mtproxy_link)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from manage_site import mtproxy_link
from manage_site import settings


def test_read_mtproxy_link_empty_setting(monkeypatch):
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", "")
    assert mtproxy_link.read_mtproxy_link() is None


def test_read_mtproxy_link_whitespace_setting(monkeypatch):
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", "   ")
    assert mtproxy_link.read_mtproxy_link() is None


def test_read_mtproxy_link_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(tmp_path / "nope.link"))
    assert mtproxy_link.read_mtproxy_link() is None


def test_read_mtproxy_link_first_nonempty_line(tmp_path, monkeypatch):
    f = tmp_path / "mt.link"
    f.write_text("\n\ntg://proxy?secret=x\n", encoding="utf-8")
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(f))
    assert mtproxy_link.read_mtproxy_link() == "tg://proxy?secret=x"


def test_read_mtproxy_link_oserror(monkeypatch, tmp_path):
    f = tmp_path / "mt.link"
    f.write_text("x", encoding="utf-8")
    monkeypatch.setattr(settings, "MTPROXY_LINK_FILE", str(f))
    with patch.object(Path, "read_text", side_effect=OSError("denied")):
        assert mtproxy_link.read_mtproxy_link() is None
