"""Обычный QR-код PNG для ссылки MTProxy / Telegram (только данные внутри, без стилизации)."""

from __future__ import annotations

import io

import qrcode


def build_mtproxy_qr_png(url: str) -> bytes:
    text = (url or '').strip()
    if not text:
        raise ValueError('empty url')
    img = qrcode.make(text, border=2)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()
