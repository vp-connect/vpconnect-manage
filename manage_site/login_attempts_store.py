"""
Блокировка входа по **IP** в JSON (счётчик неудач и ``locked_until``).

Назначение
    Защита формы ``/login``: после ``LOGIN_MAX_FAILED_ATTEMPTS`` неверных попыток с
    одного IP выставляется блокировка на ``LOGIN_LOCKOUT_MINUTES`` минут.

Зависимости
    Только стандартная библиотека. Путь к файлу передаётся аргументом (обычно
    ``settings.LOGIN_ATTEMPTS_JSON_PATH``).

Кто вызывает
    ``selfvpn_app.login`` (проверка, запись неудачи, сброс при успехе),
    ``selfvpn_app`` при старте — ``purge_expired``.

Потокобезопасность
    Один процесс Flask: доступ к файлу сериализуется ``threading.Lock``.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()


def _utcnow() -> datetime:
    """Текущее время UTC с ``tzinfo`` (для сравнения с ``locked_until``)."""
    return datetime.now(timezone.utc)


def _parse_iso(s: str) -> datetime:
    """
    Разобрать ISO-время из JSON (в т.ч. с суффиксом ``Z``).

    Args:
        s: строка из поля ``locked_until``.

    Raises:
        ValueError: при неразборчивом формате (пробрасывается из ``fromisoformat``).
    """
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _load_raw(path: Path) -> dict[str, Any]:
    """
    Загрузить сырой словарь IP → запись или пустой dict.

    Args:
        path: ``login_attempts.json``.

    Returns:
        Словарь; если файл отсутствует или корень не dict — ``{}``.
    """
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _prune(data: dict[str, Any], now: datetime) -> None:
    """
    Удалить устаревшие и мусорные записи **in-place** перед чтением/записью.

    Args:
        data: содержимое файла попыток.
        now: момент сравнения (обычно ``_utcnow()``).
    """
    dead: list[str] = []
    for ip, entry in list(data.items()):
        if not isinstance(entry, dict):
            dead.append(ip)
            continue
        lu = entry.get("locked_until")
        failures = int(entry.get("failures") or 0)
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
    """Атомарно записать JSON (через ``.tmp`` + ``replace``)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def purge_expired(path: Path) -> None:
    """
    Очистить просроченные блокировки и пустые записи (удобно при старте приложения).

    Args:
        path: путь к ``login_attempts.json``.
    """
    with _lock:
        now = _utcnow()
        data = _load_raw(path)
        _prune(data, now)
        _save(path, data)


def is_locked(path: Path, client_ip: str) -> tuple[bool, datetime | None]:
    """
    Проверить, активна ли блокировка для данного IP.

    Прецедент: GET/POST ``/login`` — показать сообщение о блокировке.

    Args:
        path: файл попыток.
        client_ip: ключ записи (как возвращает ``request.remote_addr`` или ``"unknown"``).

    Returns:
        ``(True, until)`` если ``locked_until`` в будущем; иначе ``(False, None)``.
        При повреждённых данных запись может быть очищена и сохранена.
    """
    with _lock:
        now = _utcnow()
        data = _load_raw(path)
        _prune(data, now)
        entry = data.get(client_ip)
        if not isinstance(entry, dict):
            _save(path, data)
            return False, None
        lu = entry.get("locked_until")
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
        entry.pop("locked_until", None)
        _save(path, data)
        return False, None


def record_failure(
    path: Path,
    client_ip: str,
    max_attempts: int,
    lockout_minutes: int,
) -> None:
    """
    Учесть одну неверную попытку входа для IP.

    Прецедент: POST ``/login`` с неверным паролем (и непустым полем пароля).

    Args:
        path: файл попыток.
        client_ip: IP клиента.
        max_attempts: порог для блокировки (из ``LOGIN_MAX_FAILED_ATTEMPTS``).
        lockout_minutes: длительность блокировки (из ``LOGIN_LOCKOUT_MINUTES``).

    Поведение:
        Если IP уже в активной блокировке — выход без изменений. Иначе увеличить
        ``failures``; при достижении порога выставить ``locked_until`` (ISO) и обнулить счётчик.
    """
    with _lock:
        now = _utcnow()
        data = _load_raw(path)
        _prune(data, now)
        entry = data.setdefault(client_ip, {})
        if not isinstance(entry, dict):
            entry = {}
            data[client_ip] = entry
        lu = entry.get("locked_until")
        if lu:
            try:
                if _parse_iso(str(lu)) > now:
                    _save(path, data)
                    return
            except (TypeError, ValueError):
                entry.pop("locked_until", None)
        failures = int(entry.get("failures") or 0) + 1
        entry["failures"] = failures
        if failures >= max_attempts:
            until = now + timedelta(minutes=lockout_minutes)
            entry["locked_until"] = until.isoformat()
            entry["failures"] = 0
        _save(path, data)


def clear_ip(path: Path, client_ip: str) -> None:
    """
    Удалить запись об IP (после успешного входа).

    Args:
        path: файл попыток.
        client_ip: IP, для которого сбрасываем счётчик/блокировку.
    """
    with _lock:
        data = _load_raw(path)
        data.pop(client_ip, None)
        _save(path, data)
