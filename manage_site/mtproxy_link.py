"""Чтение ссылки MTProxy / Telegram proxy из файла, путь задаётся в настройках."""

from __future__ import annotations

from pathlib import Path

from . import settings

# корень репозитория: каталог выше пакета manage_site
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolved_path() -> Path:
    p = Path(settings.MTPROXY_LINK_FILE)
    if p.is_absolute():
        return p.resolve()
    # пути вида manage_site/data/... в .env считаются от корня репозитория, не от cwd
    return (_REPO_ROOT / p).resolve()


def read_mtproxy_link() -> str | None:
    """Первая непустая строка из файла или None, если файла нет / пусто."""
    path = _resolved_path()
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding='utf-8')
    except OSError:
        return None
    for line in text.splitlines():
        s = line.strip()
        if s:
            return s
    return None
