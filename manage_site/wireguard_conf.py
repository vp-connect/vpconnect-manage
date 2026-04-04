"""
Разбор и безопасная запись серверного конфига WireGuard (wg0.conf).

Формат блоков клиентов совместим со скриптами vpconnect-configure/wg:
маркер «# Client: <имя>», затем секция [Peer]; вкл/выкл — комментирование строк
(list_users.sh, create_client.sh, delete_client.sh, toggle_client.sh).
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
ALLOWED_IPS_RE = re.compile(
    r"^\s*AllowedIPs\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)\s*$",
)


@dataclass
class WgPeerBlock:
    """Блок клиента без строки-маркера «# Client: …»."""

    name: str
    body_lines: list[str] = field(default_factory=list)

    def clone(self) -> WgPeerBlock:
        return WgPeerBlock(name=self.name, body_lines=list(self.body_lines))


def _line_is_active(line: str) -> bool:
    """Не пустая строка и не закомментированная (для определения enabled у пира)."""
    s = line.strip()
    return bool(s) and not s.startswith("#")


def peer_enabled(body_lines: list[str]) -> bool:
    """Активен, если есть непустая строка, не начинающаяся с # (как list_users.sh)."""
    return any(_line_is_active(line) for line in body_lines)


def logical_config_line(line: str) -> str:
    """Убрать ведущие пробелы и один уровень префиксных «#» для разбора полей конфига."""
    s = line.lstrip()
    while s.startswith("#"):
        s = s[1:].lstrip()
    return s.strip()


def parse_peer_public_key(body_lines: list[str]) -> str | None:
    """Извлечь ``PublicKey`` из тела блока [Peer] (с учётом закомментированных строк)."""
    for line in body_lines:
        m = PUBLIC_KEY_RE.match(logical_config_line(line))
        if m:
            return m.group(1).strip()
    return None


def parse_peer_tunnel_ip(body_lines: list[str]) -> str | None:
    """Извлечь IPv4 из ``AllowedIPs`` (первое совпадение)."""
    for line in body_lines:
        logical = logical_config_line(line)
        m = ALLOWED_IPS_RE.match(logical)
        if m:
            return m.group(1)
    return None


def iter_conf_lines(path: Path) -> Iterator[str]:
    """Построчное чтение текстового конфига UTF-8."""
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        yield line


def parse_wg_conf(path: Path) -> tuple[list[str], list[WgPeerBlock]]:
    """Разобрать файл: преамбула до первого «# Client:» и список пиров."""
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


def format_wg_conf(preamble: list[str], peers: list[WgPeerBlock]) -> str:
    """Собрать текст wg0.conf из преамбулы и списка блоков клиентов."""
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
    """Убрать лишние пустые строки (аналог awk из delete_client.sh, упрощённо)."""
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
    Комментировать или раскомментировать строки блока (как toggle_client.sh).
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
    """Добавить блок [Peer] в конец (после преамбулы и существующих пиров)."""
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
    """Удалить блок клиента по имени маркера. Возвращает True, если удалён."""
    preamble, peers = parse_wg_conf(conf_path)
    new_peers = [p for p in peers if p.name != wg_name]
    if len(new_peers) == len(peers):
        return False
    text = _normalize_blank_lines(format_wg_conf(preamble, new_peers))
    _atomic_write(conf_path, text)
    return True


def set_peer_block_enabled(conf_path: Path, wg_name: str, enabled: bool) -> bool:
    """Включить/выключить пир (toggle_client.sh)."""
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
    """Записать файл через временный и ``replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def list_peers_from_conf(conf_path: Path) -> list[WgPeerBlock]:
    _, peers = parse_wg_conf(conf_path)
    return [p.clone() for p in peers]


def collect_used_tunnel_ips(peers: list[WgPeerBlock]) -> set[str]:
    """Множество IPv4 из ``AllowedIPs`` всех переданных пиров."""
    used: set[str] = set()
    for p in peers:
        ip = parse_peer_tunnel_ip(p.body_lines)
        if ip:
            used.add(ip)
    return used


def pick_free_tunnel_ip(
    peers: list[WgPeerBlock],
    subnet_prefix: str = "10.0.0.",
) -> str:
    """Свободный адрес ``10.0.0.2``–``10.0.0.254`` не занятый в ``AllowedIPs`` пиров."""
    used = collect_used_tunnel_ips(peers)
    for n in range(2, 255):
        candidate = f"{subnet_prefix}{n}"
        if candidate not in used:
            return candidate
    raise RuntimeError("Не осталось свободных адресов 10.0.0.2–10.0.0.254")


def try_run_wg_syncconf(
    interface: str,
    conf_path: Path,
    log_warning: Callable[[str], None] | None = None,
) -> None:
    """
    Вызвать ``wg syncconf`` через bash (как в скриптах установки).

    Срабатывает только если ``conf_path`` совпадает с ``/etc/wireguard/<iface>.conf``.
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
