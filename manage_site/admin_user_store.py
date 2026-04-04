"""
Запись учётных данных администратора в ``admin_user.json`` (MD5 пароля).

Потокобезопасная запись через ``threading.Lock``.
Функция ``ensure_admin_user_from_default_password`` создаёт файл при первом запуске,
если задан ``ADMIN_DEFAULT_PASSWORD``.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from . import settings

_lock = threading.Lock()


def ensure_admin_user_from_default_password() -> bool:
    """
    При отсутствии ``admin_user.json`` и непустом ``ADMIN_DEFAULT_PASSWORD`` создать файл с MD5.

    Returns:
        True, если файл был создан.
    """
    path: Path = settings.ADMIN_USER_JSON_PATH
    if path.is_file():
        return False
    default = (settings.ADMIN_DEFAULT_PASSWORD or "").strip()
    if not default:
        return False
    digest = hashlib.md5(default.encode("utf-8")).hexdigest()
    save_password_md5_hex(digest)
    return True


def _is_hex_md5(s: str) -> bool:
    """Проверка: строка — 32 символа hex в нижнем регистре."""
    if len(s) != 32:
        return False
    return all(c in "0123456789abcdef" for c in s)


def save_password_md5_hex(password_md5_hex: str) -> None:
    """
    Сохранить MD5 пароля администратора (32 символа hex, регистр нормализуется).

    Raises:
        ValueError: если формат не MD5 hex.
    """
    h = (password_md5_hex or "").strip().lower()
    if not _is_hex_md5(h):
        raise ValueError("Некорректный MD5")

    path: Path = settings.ADMIN_USER_JSON_PATH
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        doc: dict[str, Any] = {}
        if path.is_file():
            try:
                with path.open(encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    doc = loaded
            except (OSError, json.JSONDecodeError):
                doc = {}
        doc["password_md5"] = h
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
        tmp.replace(path)
