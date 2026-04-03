"""Запись данных администратора в admin_user.json."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from . import settings

_lock = threading.Lock()


def _is_hex_md5(s: str) -> bool:
    if len(s) != 32:
        return False
    return all(c in '0123456789abcdef' for c in s)


def save_password_md5_hex(password_md5_hex: str) -> None:
    """Сохранить MD5 пароля (32 символа hex, нижний регистр)."""
    h = (password_md5_hex or '').strip().lower()
    if not _is_hex_md5(h):
        raise ValueError('Некорректный MD5')

    path: Path = settings.ADMIN_USER_JSON_PATH
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        doc: dict[str, Any] = {}
        if path.is_file():
            try:
                with path.open(encoding='utf-8') as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    doc = loaded
            except (OSError, json.JSONDecodeError):
                doc = {}
        doc['password_md5'] = h
        tmp = path.with_suffix(path.suffix + '.tmp')
        with tmp.open('w', encoding='utf-8') as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write('\n')
        tmp.replace(path)
