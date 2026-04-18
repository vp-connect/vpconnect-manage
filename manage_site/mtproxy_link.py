"""
Чтение **строки MTProxy** из файла на диске (Telegram proxy link).

Назначение
    Отдать первую непустую строку из файла, путь к которому задаётся в настройках
    ``MTPROXY_LINK_FILE``, для дашборда и QR.

Зависимости
    ``settings.MTPROXY_LINK_FILE``. Путь к файлу: абсолютный после ``expanduser``,
    иначе **от корня репозитория** (родитель ``manage_site``), не от ``cwd``.

Кто вызывает
    ``selfvpn_app.home``, ``selfvpn_app.telegram_proxy_qr_png``.
"""

from __future__ import annotations

from pathlib import Path

from . import settings

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolved_path() -> Path:
    """
    Абсолютный путь к файлу ссылки.

    Returns:
        ``Path.resolve()`` для абсолютного ``MTPROXY_LINK_FILE`` или ``_REPO_ROOT / относительный``.
    """
    raw = (settings.MTPROXY_LINK_FILE or "").strip()
    p = Path(raw).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (_REPO_ROOT / p).resolve()


def read_mtproxy_link() -> str | None:
    """
    Прочитать первую непустую строку из файла MTProxy.

    Прецедент: главная страница (текст ссылки), генерация PNG QR.

    Returns:
        Строка (``tg://…`` или иной URL) или ``None``, если настройка пуста,
        файла нет, чтение не удалось или в файле только пустые строки.
    """
    if not (settings.MTPROXY_LINK_FILE or "").strip():
        return None
    path = _resolved_path()
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        s = line.strip()
        if s:
            return s
    return None
