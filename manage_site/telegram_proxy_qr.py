"""
Генерация PNG с QR-кодом для произвольной строки (ссылка MTProxy / tg://proxy).

Используется библиотека ``qrcode``; без дополнительной стилизации изображения.
"""

from __future__ import annotations

import io

import qrcode


def build_mtproxy_qr_png(url: str) -> bytes:
    """
    Построить PNG с QR-кодом, кодирующим переданную строку.

    Args:
        url: непустая строка (обычно URL или tg://…).

    Raises:
        ValueError: если строка пустая после strip.

    Returns:
        Сырые байты PNG.
    """
    text = (url or "").strip()
    if not text:
        raise ValueError("empty url")
    img = qrcode.make(text, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
