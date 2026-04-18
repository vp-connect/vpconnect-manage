"""
Локальные операции **WireGuard** на машине с панелью: ключи, Endpoint, клиентский ``.conf``, ``wg syncconf``.

Назначение
    Обёртки над утилитой ``wg`` и чтением ``wg0.conf`` для создания клиентов и
    обновления конфигов без ручного вмешательства.

Зависимости
    ``settings`` (пути, интерфейс, DNS, CIDR), ``wireguard_conf`` (разбор преамбулы,
    ``try_run_wg_syncconf``). Внешние команды: ``wg``, при стандартном пути конфига — ``bash``.

Кто вызывает
    ``vpn_clients_service`` (ключи, endpoint, публичный ключ сервера, запись ``.conf``,
    ``apply_wg_syncconf_if_configured``).
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
    """
    Абсолютный путь к серверному ``wg0.conf`` из ``WIREGUARD_CONF_PATH``.

    Returns:
        ``Path.expanduser().resolve()``.
    """
    return Path(settings.WIREGUARD_CONF_PATH).expanduser().resolve()


def listen_port_from_server_preamble(conf_path: Path) -> int | None:
    """
    Найти ``ListenPort`` в преамбуле ``wg0.conf`` (до первого ``# Client:``).

    Args:
        conf_path: путь к конфигу сервера.

    Returns:
        Порт или ``None``, если строка не найдена.
    """
    preamble, _ = wireguard_conf.parse_wg_conf(conf_path)
    for line in preamble:
        m = _LISTEN_PORT_RE.match(wireguard_conf.logical_config_line(line))
        if m:
            return int(m.group(1))
    return None


def resolve_client_endpoint(conf_path: Path) -> str:
    """
    Собрать строку ``Endpoint`` для клиентского конфига (куда клиент стучится снаружи).

    Прецедент: ``vpn_clients_service.create_client`` перед записью ``.conf``.

    Args:
        conf_path: ``wg0.conf`` (для чтения ``ListenPort``, если порт не задан в settings).

    Returns:
        ``host:port`` или полная строка из ``WIREGUARD_ENDPOINT``.

    Raises:
        RuntimeError: если нет ни ``WIREGUARD_ENDPOINT``, ни ``WIREGUARD_PUBLIC_HOST``.
    """
    direct = (settings.WIREGUARD_ENDPOINT or "").strip()
    if direct:
        return direct
    host = (settings.WIREGUARD_PUBLIC_HOST or "").strip()
    if not host:
        raise RuntimeError(
            "Не удалось определить Endpoint. Укажите WIREGUARD_ENDPOINT, "
            "или WIREGUARD_PUBLIC_HOST (порт — ListenPort/WIREGUARD_LISTEN_PORT/51820), "
            "или задайте полный host:port через WIREGUARD_ENDPOINT."
        )
    lp = settings.WIREGUARD_LISTEN_PORT or 0
    if lp > 0:
        port = lp
    else:
        parsed = listen_port_from_server_preamble(conf_path)
        port = parsed if parsed is not None else 51820
    return f"{host}:{port}"


def _wg_show_interface_public_key() -> str | None:
    """
    Публичный ключ интерфейса через ``wg show <iface> public-key``.

    Returns:
        Непустая строка ключа или ``None`` (интерфейс не поднят, ``wg`` недоступен, таймаут).
    """
    try:
        out = subprocess.run(
            ["wg", "show", settings.WIREGUARD_INTERFACE_NAME, "public-key"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        return out or None
    except Exception:
        return None


def _interface_private_key_from_conf(conf_path: Path) -> str | None:
    """
    Значение ``PrivateKey =`` из преамбулы ``wg0.conf`` (строка ключа или путь к файлу).

    Args:
        conf_path: путь к ``wg0.conf``.
    """
    preamble, _ = wireguard_conf.parse_wg_conf(conf_path)
    for line in preamble:
        m = _PRIVATE_KEY_RE.match(wireguard_conf.logical_config_line(line))
        if m:
            return m.group(1).strip()
    return None


def _expand_private_key_value(priv: str) -> str | None:
    """
    Если ``priv`` похож на путь — прочитать файл; иначе вернуть строку ключа.

    Args:
        priv: значение из ``PrivateKey =`` (inline или путь с ``/`` / ``~``).

    Returns:
        Содержимое приватного ключа или ``None`` при отсутствии файла / ошибке чтения.
    """
    if "/" not in priv and not priv.startswith("~"):
        return priv
    p = Path(priv).expanduser()
    try:
        if not p.is_file():
            return None
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _public_key_from_private(priv: str) -> str | None:
    """
    Вычислить публичный ключ из приватного через ``wg pubkey``.

    Args:
        priv: приватный ключ в формате WireGuard.

    Returns:
        Публичный ключ или ``None`` при ошибке процесса.
    """
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


def server_public_key_from_interface(conf_path: Path) -> str | None:
    """
    Публичный ключ сервера для секции ``[Peer]`` в клиентском конфиге.

    Порядок: (1) ``wg show``; (2) ``PrivateKey`` из ``wg0.conf`` (inline или файл) → ``wg pubkey``.

    Args:
        conf_path: путь к ``wg0.conf``.

    Returns:
        Base64 публичного ключа или ``None``, если источников нет.
    """
    from_show = _wg_show_interface_public_key()
    if from_show:
        return from_show

    priv_raw = _interface_private_key_from_conf(conf_path)
    if not priv_raw:
        return None

    priv = _expand_private_key_value(priv_raw)
    if not priv:
        return None
    return _public_key_from_private(priv)


def wg_gen_keypair() -> tuple[str, str]:
    """
    Сгенерировать пару ключей ``wg genkey`` / ``wg pubkey``.

    Прецедент: создание нового клиента.

    Returns:
        ``(private_b64, public_b64)``.

    Raises:
        RuntimeError: если ``wg`` не найдена или команда завершилась с ошибкой.
    """
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
    Записать клиентский ``{wg_name}.conf`` и подкаталог ``qr``.

    Прецедент: успешное создание клиента после получения публичного ключа сервера.

    Args:
        client_config_dir: корень каталога клиентских конфигов.
        wg_name: имя маркера клиента (база имени файла).
        private_key: приватный ключ клиента.
        tunnel_ip: IPv4 туннеля (без маски в аргументе; в файл пишется ``/24``).
        server_public_key: публичный ключ сервера.
        endpoint: строка ``Endpoint`` (``host:port``).

    Returns:
        Путь к записанному ``.conf``.

    Побочные эффекты:
        Если задан ``WIREGUARD_NETWORK_CIDR``, выполняется валидация через
        ``subnet_prefix_from_network_cidr`` (как при настройке из панели). Права ``0600`` на файл
        при возможности.
    """
    client_config_dir.mkdir(parents=True, exist_ok=True)
    (client_config_dir / "qr").mkdir(parents=True, exist_ok=True)
    path = client_config_dir / f"{wg_name}.conf"
    dns = (settings.WIREGUARD_DNS or "8.8.8.8").strip()
    address_cidr = (settings.WIREGUARD_NETWORK_CIDR or "").strip()
    if address_cidr:
        _ = wireguard_conf.subnet_prefix_from_network_cidr(address_cidr)
    client_address = f"{tunnel_ip}/24"
    text = (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {client_address}\n"
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
    """Передать предупреждение в лог панели (колбэк для ``try_run_wg_syncconf``)."""
    _log.warning("%s", msg)


def apply_wg_syncconf_if_configured() -> None:
    """
    После правки ``wg0.conf`` вызвать ``wg syncconf``, если путь совпадает с ожиданием wg-quick.

    Прецедент: после изменений пиров из ``vpn_clients_service``.

    Поведение:
        Ничего не делает при выключенном WireGuard. Иначе делегирует в ``wireguard_conf.try_run_wg_syncconf``.
    """
    if not settings.wireguard_enabled():
        return
    wireguard_conf.try_run_wg_syncconf(
        settings.WIREGUARD_INTERFACE_NAME,
        wg_conf_path_resolved(),
        _syncconf_log_warning,
    )
