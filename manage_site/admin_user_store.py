"""
Учётная запись администратора в ``admin_user.json`` (пароль как **MD5 hex**).

Назначение
    Создание файла при первом запуске из ``ADMIN_DEFAULT_PASSWORD`` и смена пароля
    из UI с атомарной записью JSON.

Зависимости
    ``settings`` — путь ``ADMIN_USER_JSON_PATH``. Стандартная библиотека: ``hashlib``,
    ``json``, ``threading``.

Кто вызывает
    ``selfvpn_app`` (старт и POST смены пароля), тесты.
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
    Создать ``admin_user.json`` с MD5 пароля по умолчанию, если файла ещё нет.

    Прецедент: один раз при импорте ``selfvpn_app`` до чтения кэша пароля.

    Returns:
        ``True``, если файл был создан; иначе ``False`` (файл уже есть или пароль
        по умолчанию пуст).
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
    """
    Проверить, что строка — 32 символа **lowercase** hex.

    Args:
        s: нормализованная строка (ожидается уже ``.lower()`` снаружи при необходимости).
    """
    if len(s) != 32:
        return False
    return all(c in "0123456789abcdef" for c in s)


def save_password_md5_hex(password_md5_hex: str) -> None:
    """
    Атомарно сохранить MD5 пароля администратора в ``admin_user.json``.

    Прецедент: смена пароля в UI, сброс на значение по умолчанию, первичное создание.

    Args:
        password_md5_hex: 32 символа hex (регистр входа не важен — нормализуется).

    Raises:
        ValueError: если после ``strip``/``lower`` строка не является валидным MD5 hex.

    Побочные эффекты:
        Читает существующий JSON (если есть), мержит поле ``password_md5``, пишет через ``.tmp``.
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
