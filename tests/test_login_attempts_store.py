"""Блокировки входа по IP (login_attempts_store)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from manage_site import login_attempts_store


def test_parse_iso_z_suffix():
    dt = login_attempts_store._parse_iso("2020-01-02T03:04:05Z")
    assert dt.tzinfo is not None


def test_purge_removes_empty_and_expired_lock(tmp_path: Path, monkeypatch):
    path = tmp_path / "login_attempts.json"
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    past = (now - timedelta(hours=1)).isoformat()
    path.write_text(
        '{"1.1.1.1": {"failures": 0, "locked_until": "%s"}, '
        '"2.2.2.2": {"failures": 0}}' % past,
        encoding="utf-8",
    )
    monkeypatch.setattr(login_attempts_store, "_utcnow", lambda: now)
    login_attempts_store.purge_expired(path)
    data = login_attempts_store._load_raw(path)
    assert "1.1.1.1" not in data
    assert "2.2.2.2" not in data


def test_is_locked_active(tmp_path: Path, monkeypatch):
    path = tmp_path / "la.json"
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    future = (now + timedelta(minutes=30)).isoformat()
    path.write_text(
        '{"9.9.9.9": {"failures": 0, "locked_until": "%s"}}' % future,
        encoding="utf-8",
    )
    monkeypatch.setattr(login_attempts_store, "_utcnow", lambda: now)
    locked, until = login_attempts_store.is_locked(path, "9.9.9.9")
    assert locked is True
    assert until is not None


def test_record_failure_then_lockout(tmp_path: Path, monkeypatch):
    path = tmp_path / "la.json"
    now = datetime(2030, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(login_attempts_store, "_utcnow", lambda: now)
    for _ in range(3):
        login_attempts_store.record_failure(path, "8.8.8.8", max_attempts=3, lockout_minutes=10)
    locked, _ = login_attempts_store.is_locked(path, "8.8.8.8")
    assert locked is True


def test_record_failure_noop_when_already_locked(tmp_path: Path, monkeypatch):
    path = tmp_path / "la.json"
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    future = (now + timedelta(hours=1)).isoformat()
    path.write_text(
        '{"8.8.8.8": {"failures": 0, "locked_until": "%s"}}' % future,
        encoding="utf-8",
    )
    monkeypatch.setattr(login_attempts_store, "_utcnow", lambda: now)
    login_attempts_store.record_failure(path, "8.8.8.8", max_attempts=1, lockout_minutes=10)
    data = login_attempts_store._load_raw(path)
    assert data["8.8.8.8"]["locked_until"] == future


def test_clear_ip(tmp_path: Path):
    path = tmp_path / "la.json"
    path.write_text('{"1.2.3.4": {"failures": 1}}', encoding="utf-8")
    login_attempts_store.clear_ip(path, "1.2.3.4")
    assert login_attempts_store._load_raw(path) == {}


def test_is_locked_bad_locked_until_prunes(tmp_path: Path):
    path = tmp_path / "la.json"
    path.write_text('{"1.1.1.1": {"failures": 1, "locked_until": "not-a-date"}}', encoding="utf-8")
    locked, _ = login_attempts_store.is_locked(path, "1.1.1.1")
    assert locked is False
