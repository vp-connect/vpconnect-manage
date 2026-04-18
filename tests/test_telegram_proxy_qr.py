"""QR для MTProxy (telegram_proxy_qr)."""

from __future__ import annotations

import pytest

from manage_site import telegram_proxy_qr


def test_build_mtproxy_qr_png_returns_png_magic():
    png = telegram_proxy_qr.build_mtproxy_qr_png("tg://proxy?server=1&port=443&secret=abc")
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


def test_build_mtproxy_qr_png_empty_raises():
    with pytest.raises(ValueError, match="empty"):
        telegram_proxy_qr.build_mtproxy_qr_png("")
