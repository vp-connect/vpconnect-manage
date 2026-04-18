"""
Разбор и безопасная запись серверного **WireGuard** конфига ``wg0.conf``.

Назначение
    Представление файла как преамбула сервера + список блоков клиентов (маркер
    ``# Client: <имя>`` и тело до следующего маркера). Операции добавления/удаления/включения
    пиров совместимы со скриптами **vpconnect-configure** (list_users, create_client,
    delete_client, toggle_client).

Зависимости
    Стандартная библиотека; опционально ``subprocess`` + ``bash`` для ``wg syncconf``
    на стандартном пути ``/etc/wireguard/<iface>.conf``.

Кто вызывает
    ``vpn_clients_service``, ``wg_local_runtime`` (разбор преамбулы, ``try_run_wg_syncconf``).
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

CLIENT_MARKER_RE = re.compile(r"^#\s*Client:\s*(.+?)\s*$")
PUBLIC_KEY_RE = re.compile(r"^\s*PublicKey\s*=\s*(\S+)\s*$")
ADDRESS_RE = re.compile(r"^\s*Address\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})/(\d+)\s*$")
CIDR_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})/(\d+)\s*$")
ALLOWED_IPS_RE = re.compile(
    r"^\s*AllowedIPs\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)\s*$",
)


@dataclass
class WgPeerBlock:
    """
    Один клиентский блок в ``wg0.conf`` (без строки ``# Client:``).

    Attributes:
        name: имя из маркера ``# Client: …``.
        body_lines: строки тела (обычно ``[Peer]`` и поля).
    """

    name: str
    body_lines: list[str] = field(default_factory=list)

    def clone(self) -> WgPeerBlock:
        """Неглубокая копия для безопасного изменения списка строк."""
        return WgPeerBlock(name=self.name, body_lines=list(self.body_lines))


def _line_is_active(line: str) -> bool:
    """True, если строка не пустая и не начинается с ``#`` (как у активного пира в bash-скриптах)."""
    s = line.strip()
    return bool(s) and not s.startswith("#")


def peer_enabled(body_lines: list[str]) -> bool:
    """
    Признак «пир включён» по набору строк тела блока.

    Прецедент: синхронизация поля ``enabled`` в JSON с состоянием комментариев в ``wg0.conf``.
    """
    return any(_line_is_active(line) for line in body_lines)


def logical_config_line(line: str) -> str:
    """
    Нормализовать строку конфига для разбора полей (учёт закомментированных директив).

    Снимает ведущие пробелы и один ведущий ``#`` (как при раскомментировании в скриптах).
    """
    s = line.lstrip()
    while s.startswith("#"):
        s = s[1:].lstrip()
    return s.strip()


def parse_peer_public_key(body_lines: list[str]) -> str | None:
    """
    Извлечь первый ``PublicKey =`` из тела пира (после ``logical_config_line``).

    Args:
        body_lines: строки между ``# Client:`` и следующим маркером/пустым разделом.
    """
    for line in body_lines:
        m = PUBLIC_KEY_RE.match(logical_config_line(line))
        if m:
            return m.group(1).strip()
    return None


def parse_peer_tunnel_ip(body_lines: list[str]) -> str | None:
    """
    Извлечь IPv4 из первого ``AllowedIPs = a.b.c.d/…``.

    Args:
        body_lines: тело блока пира.
    """
    for line in body_lines:
        logical = logical_config_line(line)
        m = ALLOWED_IPS_RE.match(logical)
        if m:
            return m.group(1)
    return None


def iter_conf_lines(path: Path) -> Iterator[str]:
    """
    Итератор строк ``wg0.conf`` (UTF-8).

    Args:
        path: существующий файл конфига.
    """
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        yield line


def parse_wg_conf(path: Path) -> tuple[list[str], list[WgPeerBlock]]:
    """
    Разобрать ``wg0.conf`` на преамбулу сервера и список клиентских блоков.

    Args:
        path: путь к конфигу.

    Returns:
        ``(preamble_lines, peers)``. Если файла нет — ``([], [])``. Если маркеров клиентов
        нет — ``(все_строки, [])``.
    """
    if not path.is_file():
        return ([], [])

    lines = list(iter_conf_lines(path))
    preamble: list[str] = []
    peers: list[WgPeerBlock] = []
    first_marker_idx: int | None = None
    for i, line in enumerate(lines):
        if CLIENT_MARKER_RE.match(line):
            first_marker_idx = i
            break
    if first_marker_idx is None:
        return (lines, [])

    preamble = lines[:first_marker_idx]
    idx = first_marker_idx
    while idx < len(lines):
        m = CLIENT_MARKER_RE.match(lines[idx])
        if not m:
            idx += 1
            continue
        name = m.group(1).strip()
        body: list[str] = []
        idx += 1
        while idx < len(lines):
            line = lines[idx]
            if line.strip() == "" or CLIENT_MARKER_RE.match(line):
                break
            body.append(line)
            idx += 1
        peers.append(WgPeerBlock(name=name, body_lines=body))
        if idx < len(lines) and lines[idx].strip() == "":
            idx += 1
    return (preamble, peers)


def server_subnet_prefix_from_conf(conf_path: Path) -> str:
    """
    Префикс ``A.B.C.`` для выдачи клиентских IP из первого ``Address =`` в преамбуле.

    Прецедент: ``vpn_clients_service`` при пустом ``WIREGUARD_NETWORK_CIDR``.

    Args:
        conf_path: ``wg0.conf`` сервера.

    Returns:
        Строка вида ``\"10.8.0.\"``.

    Raises:
        RuntimeError: если подходящей строки ``Address`` нет.
    """
    preamble, _ = parse_wg_conf(conf_path)
    for line in preamble:
        m = ADDRESS_RE.match(logical_config_line(line))
        if not m:
            continue
        ip = m.group(1)
        parts = ip.split(".")
        if len(parts) != 4:
            break
        return ".".join(parts[:3]) + "."
    raise RuntimeError(
        f"Не удалось определить Address из {conf_path} (ожидается IPv4 Address = A.B.C.D/24)"
    )


def subnet_prefix_from_network_cidr(network_cidr: str) -> str:
    """
    Префикс ``A.B.C.`` из CIDR сети панели (только **/24**).

    Прецедент: задан ``WIREGUARD_NETWORK_CIDR``; также валидация в ``write_client_conf_file``.

    Args:
        network_cidr: строка вида ``10.8.0.1/24``.

    Raises:
        ValueError: при неверном формате или маске не ``/24``.
    """
    s = (network_cidr or "").strip()
    m = CIDR_RE.match(s)
    if not m:
        raise ValueError("Ожидается IPv4 CIDR формата A.B.C.D/24")
    ip = m.group(1)
    prefix = int(m.group(2))
    if prefix != 24:
        raise ValueError("Сейчас поддерживается только /24 (как в установочных скриптах)")
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError("Ожидается IPv4 адрес")
    return ".".join(parts[:3]) + "."


def format_wg_conf(preamble: list[str], peers: list[WgPeerBlock]) -> str:
    """
    Собрать текст ``wg0.conf`` из преамбулы и блоков клиентов.

    Args:
        preamble: строки до первого ``# Client:``.
        peers: список пиров с именами и телами.

    Returns:
        Полный текст файла (с переводами строк между блоками).
    """
    parts: list[str] = []
    if preamble:
        parts.append("\n".join(preamble).rstrip("\n"))
    for p in peers:
        if parts and not parts[-1].endswith("\n"):
            parts.append("")
        block = [f"# Client: {p.name}"] + p.body_lines
        parts.append("\n".join(block).rstrip("\n"))
    out = "\n\n".join(parts)
    if out and not out.endswith("\n"):
        out += "\n"
    return out


def _normalize_blank_lines(text: str) -> str:
    """Схлопнуть множественные пустые строки до одной между непустыми блоками."""
    raw_lines = text.splitlines()
    out_lines: list[str] = []
    pending_blank = False
    first = True
    for line in raw_lines:
        if line.strip() == "":
            pending_blank = True
            continue
        if not first and pending_blank:
            out_lines.append("")
        out_lines.append(line)
        pending_blank = False
        first = False
    return "\n".join(out_lines) + ("\n" if out_lines else "")


def set_peer_enabled(body_lines: list[str], enabled: bool) -> list[str]:
    """
    Включить или выключить пир комментированием каждой строки тела (как ``toggle_client.sh``).

    Args:
        body_lines: строки блока ``[Peer]`` и ниже до следующего маркера.
        enabled: ``True`` — убрать один ведущий ``#``; ``False`` — добавить ``#``.
    """
    if enabled:
        return [line[1:] if line.startswith("#") else line for line in body_lines]
    return ["#" + line for line in body_lines]


def append_peer(
    conf_path: Path,
    wg_name: str,
    public_key_b64: str,
    tunnel_ip: str,
) -> None:
    """
    Добавить нового клиента в конец ``wg0.conf`` (маркер + минимальный ``[Peer]``).

    Args:
        conf_path: путь к конфигу.
        wg_name: имя в строке ``# Client:``.
        public_key_b64: публичный ключ клиента.
        tunnel_ip: IPv4 для ``AllowedIPs = …/32``.
    """
    preamble, peers = parse_wg_conf(conf_path)
    body = [
        "[Peer]",
        f"PublicKey = {public_key_b64}",
        f"AllowedIPs = {tunnel_ip}/32",
    ]
    peers.append(WgPeerBlock(name=wg_name, body_lines=body))
    text = _normalize_blank_lines(format_wg_conf(preamble, peers))
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(conf_path, text)


def remove_peer(conf_path: Path, wg_name: str) -> bool:
    """
    Удалить блок клиента по имени маркера.

    Returns:
        ``True``, если блок был найден и удалён.
    """
    preamble, peers = parse_wg_conf(conf_path)
    new_peers = [p for p in peers if p.name != wg_name]
    if len(new_peers) == len(peers):
        return False
    text = _normalize_blank_lines(format_wg_conf(preamble, new_peers))
    _atomic_write(conf_path, text)
    return True


def set_peer_block_enabled(conf_path: Path, wg_name: str, enabled: bool) -> bool:
    """
    Включить или выключить существующего клиента в ``wg0.conf``.

    Returns:
        ``True``, если пир с именем ``wg_name`` найден.
    """
    preamble, peers = parse_wg_conf(conf_path)
    found = False
    new_peers: list[WgPeerBlock] = []
    for p in peers:
        if p.name != wg_name:
            new_peers.append(p)
            continue
        found = True
        new_body = set_peer_enabled(p.body_lines, enabled)
        new_peers.append(WgPeerBlock(name=p.name, body_lines=new_body))
    if not found:
        return False
    text = _normalize_blank_lines(format_wg_conf(preamble, new_peers))
    _atomic_write(conf_path, text)
    return True


def _atomic_write(path: Path, text: str) -> None:
    """Атомарная запись текста в ``path`` (``.tmp`` + ``replace``)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def list_peers_from_conf(conf_path: Path) -> list[WgPeerBlock]:
    """
    Список пиров из ``wg0.conf`` (копии блоков, безопасно для мутаций).

    Args:
        conf_path: путь к конфигу.
    """
    _, peers = parse_wg_conf(conf_path)
    return [p.clone() for p in peers]


def collect_used_tunnel_ips(peers: list[WgPeerBlock]) -> set[str]:
    """
    Множество IPv4 туннелей, уже занятых в ``AllowedIPs`` переданных пиров.

    Args:
        peers: список блоков из ``list_peers_from_conf``.
    """
    used: set[str] = set()
    for p in peers:
        ip = parse_peer_tunnel_ip(p.body_lines)
        if ip:
            used.add(ip)
    return used


def pick_free_tunnel_ip(
    peers: list[WgPeerBlock],
    subnet_prefix: str,
) -> str:
    """
    Найти свободный адрес в сети WireGuard.

    Диапазон поиска: ``<prefix>2``–``<prefix>254`` (как в установочных скриптах для /24).
    Параметр ``subnet_prefix`` должен быть вычислен уровнем выше из:

    - ``WIREGUARD_NETWORK_CIDR`` (настройка панели), либо
    - ``Address = ...`` в серверном ``wg0.conf`` (fallback).
    """
    used = collect_used_tunnel_ips(peers)
    for n in range(2, 255):
        candidate = f"{subnet_prefix}{n}"
        if candidate not in used:
            return candidate
    raise RuntimeError(f"Не осталось свободных адресов {subnet_prefix}2–{subnet_prefix}254")


def try_run_wg_syncconf(
    interface: str,
    conf_path: Path,
    log_warning: Callable[[str], None] | None = None,
) -> None:
    """
    Применить изменения ``wg0.conf`` через ``wg syncconf`` (только «стандартный» путь в ``/etc``).

    Прецедент: ``wg_local_runtime.apply_wg_syncconf_if_configured`` после правок панелью.

    Args:
        interface: имя интерфейса (например ``wg0``).
        conf_path: фактический путь к конфигу на машине.
        log_warning: опциональный колбэк для предупреждений (пропуск sync, ошибки bash/wg).

    Поведение:
        Если ``conf_path.resolve()`` не совпадает с ``/etc/wireguard/<interface>.conf``,
        sync не выполняется — только предупреждение.
    """
    try:
        expected = (Path("/etc/wireguard") / f"{interface}.conf").resolve()
        if conf_path.resolve() != expected:
            if log_warning:
                log_warning(
                    f"WIREGUARD_CONF_PATH не совпадает с {expected}; wg syncconf пропущен "
                    "(ожидается стандартный путь для wg-quick strip)."
                )
            return
        cmd = f"wg syncconf {shlex.quote(interface)} <(wg-quick strip {shlex.quote(interface)})"
        subprocess.run(
            ["bash", "-lc", cmd],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        if log_warning:
            log_warning("bash/wg не найдены; wg syncconf пропущен.")
    except subprocess.CalledProcessError as e:
        if log_warning:
            log_warning(f"wg syncconf завершился с ошибкой: {e.stderr or e.stdout or e}")
    except OSError as e:
        if log_warning:
            log_warning(f"wg syncconf: {e}")
