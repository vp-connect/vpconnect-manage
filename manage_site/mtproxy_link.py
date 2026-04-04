"""
Чтение ссылки Telegram MTProxy из файла, путь задаётся ``MTPROXY_LINK_FILE`` в настройках.

Пустой параметр в настройках отключает функцию; относительные пути считаются от корня репозитория
(родитель каталога ``manage_site``), не от cwd процесса.
"""

from __future__ import annotations

from pathlib import Path

from . import settings

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolved_path() -> Path:
    """Абсолютный путь к файлу ссылки: expanduser, абсолютный или от корня репозитория."""
    raw = (settings.MTPROXY_LINK_FILE or "").strip()
    p = Path(raw).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (_REPO_ROOT / p).resolve()


def read_mtproxy_link() -> str | None:
    """
    Вернуть первую непустую строку из файла или None.

    Returns:
        URL/строка прокси или None, если параметр не задан, файла нет или файл пуст.
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
