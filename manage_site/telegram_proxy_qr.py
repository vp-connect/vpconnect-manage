"""
PNG **QR-код** по произвольной строке (ссылка MTProxy / ``tg://proxy``).

Назначение
    Сериализация ссылки в растровое изображение для HTTP-ответа ``image/png``.

Зависимости
    Пакет ``qrcode`` (с PIL), стандартный ``io``.

Кто вызывает
    ``selfvpn_app.telegram_proxy_qr_png`` после ``mtproxy_link.read_mtproxy_link``.
"""

from __future__ import annotations

import io

import qrcode


def build_mtproxy_qr_png(url: str) -> bytes:
    """
    Построить PNG с QR-кодом для строки ``url``.

    Прецедент: GET ``/telegram-proxy/qr.png`` при включённом MTProxy.

    Args:
        url: полезная нагрузка QR (непустая после ``strip``).

    Returns:
        Сырые байты PNG.

    Raises:
        ValueError: если после ``strip`` строка пустая.
    """
    text = (url or "").strip()
    if not text:
        raise ValueError("empty url")
    img = qrcode.make(text, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
