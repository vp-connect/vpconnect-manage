"""Учёт неудачных попыток входа по IP (JSON + lock для одного процесса)."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


def _load_raw(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open(encoding='utf-8') as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _prune(data: dict[str, Any], now: datetime) -> None:
    dead: list[str] = []
    for ip, entry in list(data.items()):
        if not isinstance(entry, dict):
            dead.append(ip)
            continue
        lu = entry.get('locked_until')
        failures = int(entry.get('failures') or 0)
        if lu:
            try:
                until = _parse_iso(str(lu))
            except (TypeError, ValueError):
                dead.append(ip)
                continue
            if until <= now and failures == 0:
                dead.append(ip)
        elif failures == 0:
            dead.append(ip)
    for ip in dead:
        data.pop(ip, None)


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write('\n')
    tmp.replace(path)


def purge_expired(path: Path) -> None:
    """Удалить из файла просроченные блокировки и пустые записи (удобно при старте приложения)."""
    with _lock:
        now = _utcnow()
        data = _load_raw(path)
        _prune(data, now)
        _save(path, data)


def is_locked(path: Path, client_ip: str) -> tuple[bool, datetime | None]:
    """Активна ли блокировка для IP; если да — время окончания (UTC)."""
    with _lock:
        now = _utcnow()
        data = _load_raw(path)
        _prune(data, now)
        entry = data.get(client_ip)
        if not isinstance(entry, dict):
            _save(path, data)
            return False, None
        lu = entry.get('locked_until')
        if not lu:
            _save(path, data)
            return False, None
        try:
            until = _parse_iso(str(lu))
        except (TypeError, ValueError):
            _save(path, data)
            return False, None
        if until > now:
            _save(path, data)
            return True, until
        entry.pop('locked_until', None)
        _save(path, data)
        return False, None


def record_failure(
    path: Path,
    client_ip: str,
    max_attempts: int,
    lockout_minutes: int,
) -> None:
    with _lock:
        now = _utcnow()
        data = _load_raw(path)
        _prune(data, now)
        entry = data.setdefault(client_ip, {})
        if not isinstance(entry, dict):
            entry = {}
            data[client_ip] = entry
        lu = entry.get('locked_until')
        if lu:
            try:
                if _parse_iso(str(lu)) > now:
                    _save(path, data)
                    return
            except (TypeError, ValueError):
                entry.pop('locked_until', None)
        failures = int(entry.get('failures') or 0) + 1
        entry['failures'] = failures
        if failures >= max_attempts:
            until = now + timedelta(minutes=lockout_minutes)
            entry['locked_until'] = until.isoformat()
            entry['failures'] = 0
        _save(path, data)


def clear_ip(path: Path, client_ip: str) -> None:
    with _lock:
        data = _load_raw(path)
        data.pop(client_ip, None)
        _save(path, data)
