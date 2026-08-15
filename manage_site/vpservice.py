"""
Определение активного VPN-сервиса (WireGuard/AmneziaWG).

Назначение
    Единая точка выбора типа сервиса для backend-операций и UI:
    1) явный ``VP_SERVICE_TYPE`` из ``settings.env``,
    2) fallback-автодетект по серверному конфигу.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import settings
from . import wireguard_conf

WIREGUARD = "wireguard"
AMNEZIAWG = "amneziawg"

_AMNEZIA_CONF_KEYS = {
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "h1",
    "h2",
    "h3",
    "h4",
}
_CONF_KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)\s*=")


def configured_vpservice_type() -> str | None:
    """
    Тип сервиса, заданный явно в env.

    Returns:
        ``wireguard``/``amneziawg`` или ``None``, если параметр пуст.
    """
    raw = (settings.VP_SERVICE_TYPE or "").strip().lower()
    return raw or None


def detect_vpservice_type_from_conf(conf_path: Path) -> str:
    """
    Определить тип сервиса по preamble серверного конфига.

    Правило:
        Если в активных директивах обнаружены amnezia-поля (``Jc/Jmin/Jmax/S1/S2/H1..H4``),
        считаем сервис ``amneziawg``. Иначе ``wireguard``.
    """
    if not conf_path.is_file():
        return WIREGUARD

    preamble, _ = wireguard_conf.parse_wg_conf(conf_path)
    keys: set[str] = set()
    for line in preamble:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        m = _CONF_KEY_RE.match(raw)
        if not m:
            continue
        keys.add(m.group(1).strip().lower())
    if keys.intersection(_AMNEZIA_CONF_KEYS):
        return AMNEZIAWG
    return WIREGUARD


def active_vpservice_type(conf_path: Path | None = None) -> str:
    """
    Определить активный тип VPN-сервиса для текущего сервера.

    Args:
        conf_path: опциональный путь к серверному конфигу; если не передан,
            используется ``WIREGUARD_CONF_PATH``.
    """
    explicit = configured_vpservice_type()
    if explicit:
        return explicit
    if not settings.vpservice_enabled():
        return WIREGUARD
    base_path = conf_path or Path(settings.WIREGUARD_CONF_PATH).expanduser().resolve()
    return detect_vpservice_type_from_conf(base_path)


def vpservice_display_name(conf_path: Path | None = None) -> str:
    """
    Человекочитаемое имя для UI.

    Returns:
        ``Wireguard`` или ``Amnezia WG``.
    """
    service = active_vpservice_type(conf_path)
    if service == AMNEZIAWG:
        return "Amnezia WG"
    return "Wireguard"
