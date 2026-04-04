"""
Локальные операции WireGuard на машине с панелью: ключи, Endpoint, запись .conf, wg syncconf.

Используется при создании клиентов и после правок wg0.conf.
Требует утилит ``wg`` и (для автоматического ``wg syncconf``) ``bash`` на Linux.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

from . import settings
from . import wireguard_conf

_log = logging.getLogger(__name__)

_PRIVATE_KEY_RE = re.compile(r"^\s*PrivateKey\s*=\s*(\S+)\s*$")
_LISTEN_PORT_RE = re.compile(r"^\s*ListenPort\s*=\s*(\d+)\s*$")


def wg_conf_path_resolved() -> Path:
    """Абсолютный путь к wg0.conf из настроек."""
    return Path(settings.WIREGUARD_CONF_PATH).expanduser().resolve()


def listen_port_from_server_preamble(conf_path: Path) -> int | None:
    """Прочитать ``ListenPort`` из преамбулы wg0.conf (секция [Interface])."""
    preamble, _ = wireguard_conf.parse_wg_conf(conf_path)
    for line in preamble:
        m = _LISTEN_PORT_RE.match(wireguard_conf.logical_config_line(line))
        if m:
            return int(m.group(1))
    return None


def resolve_client_endpoint(conf_path: Path) -> str:
    """
    Собрать строку ``Endpoint`` для клиентского конфига (куда клиент подключается снаружи).

    Приоритет: ``WIREGUARD_ENDPOINT``; иначе ``WIREGUARD_PUBLIC_HOST`` + порт из
    ``WIREGUARD_LISTEN_PORT``, из ``ListenPort`` в конфиге или 51820.
    """
    direct = (settings.WIREGUARD_ENDPOINT or "").strip()
    if direct:
        return direct
    host = (settings.WIREGUARD_PUBLIC_HOST or "").strip()
    if not host:
        raise RuntimeError(
            "Укажите WIREGUARD_ENDPOINT (например vpn.example.com:51820) "
            "или WIREGUARD_PUBLIC_HOST (порт — из ListenPort в wg0.conf, "
            "из WIREGUARD_LISTEN_PORT при ненулевом значении или 51820)."
        )
    lp = settings.WIREGUARD_LISTEN_PORT or 0
    if lp > 0:
        port = lp
    else:
        parsed = listen_port_from_server_preamble(conf_path)
        port = parsed if parsed is not None else 51820
    return f"{host}:{port}"


def server_public_key_from_interface(conf_path: Path) -> str | None:
    """
    Публичный ключ сервера из ``PrivateKey`` в преамбуле wg0.conf (через ``wg pubkey``).
    """
    preamble, _ = wireguard_conf.parse_wg_conf(conf_path)
    priv: str | None = None
    for line in preamble:
        m = _PRIVATE_KEY_RE.match(wireguard_conf.logical_config_line(line))
        if m:
            priv = m.group(1).strip()
            break
    if not priv:
        return None
    try:
        pub = subprocess.run(
            ["wg", "pubkey"],
            input=priv,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return pub.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None


def wg_gen_keypair() -> tuple[str, str]:
    """Сгенерировать пару ключей WireGuard (приватный и публичный, base64)."""
    try:
        gen = subprocess.run(
            ["wg", "genkey"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        priv = gen.stdout.strip()
        pub = subprocess.run(
            ["wg", "pubkey"],
            input=priv,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return priv, pub.stdout.strip()
    except FileNotFoundError as e:
        raise RuntimeError("Команда wg не найдена. Установите wireguard-tools.") from e
    except subprocess.CalledProcessError as e:
        err = (e.stderr or e.stdout or "").strip() or str(e)
        raise RuntimeError(f"Ошибка генерации ключей wg: {err}") from e


def write_client_conf_file(
    client_config_dir: Path,
    wg_name: str,
    private_key: str,
    tunnel_ip: str,
    server_public_key: str,
    endpoint: str,
) -> Path:
    """
    Записать клиентский ``.conf`` в ``client_config_dir`` (права 0600 при возможности).

    Формат совместим с типичным выводом create_client.sh (Address /24, DNS, Peer, Keepalive).
    """
    client_config_dir.mkdir(parents=True, exist_ok=True)
    (client_config_dir / "qr").mkdir(parents=True, exist_ok=True)
    path = client_config_dir / f"{wg_name}.conf"
    dns = (settings.WIREGUARD_DNS or "8.8.8.8").strip()
    text = (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {tunnel_ip}/24\n"
        f"DNS = {dns}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _syncconf_log_warning(msg: str) -> None:
    _log.warning("%s", msg)


def apply_wg_syncconf_if_configured() -> None:
    """
    После правки wg0.conf вызвать ``wg syncconf``, если путь совпадает с ожиданием wg-quick.

    Иначе — предупреждение в лог (см. ``wireguard_conf.try_run_wg_syncconf``).
    """
    if not settings.wireguard_enabled():
        return
    wireguard_conf.try_run_wg_syncconf(
        settings.WIREGUARD_INTERFACE_NAME,
        wg_conf_path_resolved(),
        _syncconf_log_warning,
    )
