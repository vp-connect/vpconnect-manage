"""
Учёт VPN-клиентов в JSON и синхронизация с серверным wg0.conf.

При включённом ``WIREGUARD_CONF_PATH`` список и статусы пиров подтягиваются из конфига;
создание, переключение и удаление обновляют wg0.conf, ключи на диске и клиентские .conf.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any

import qrcode

from . import settings
from . import wg_local_runtime
from . import wireguard_conf

_lock = threading.RLock()
_log = logging.getLogger(__name__)


def ascii_slug(name: str) -> str:
    """Латинский slug для имён файлов (кириллица транслитерируется упрощённо)."""
    t = (name or "").strip().lower()
    for a, b in (
        ("щ", "sch"),
        ("ш", "sh"),
        ("ч", "ch"),
        ("ж", "zh"),
        ("ю", "yu"),
        ("я", "ya"),
        ("ё", "e"),
        ("э", "e"),
        ("ы", "y"),
        ("й", "j"),
        ("ъ", ""),
        ("ь", ""),
    ):
        t = t.replace(a, b)
    t = t.translate(
        str.maketrans(
            "абвгдезиклмнопрстуфхц",
            "abvgdeziklmnoprstufhc",
        )
    )
    s = re.sub(r"[^a-z0-9]+", "_", t)
    s = s.strip("_")
    return s or "user"


def _keys_base_path() -> Path:
    """Каталог ключей клиентов (абсолютный путь)."""
    p = Path(settings.WIREGUARD_CLIENT_KEYS_DIR)
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


def _client_config_dir() -> Path:
    """Каталог клиентских .conf: из настроек или рядом с каталогом ключей."""
    raw = (settings.WIREGUARD_CLIENT_CONFIG_DIR or "").strip()
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        return p.resolve()
    return (_keys_base_path().parent / "client_config").resolve()


def _ensure_keys_dir() -> Path:
    """Создать каталог ключей при отсутствии."""
    base = _keys_base_path()
    base.mkdir(parents=True, exist_ok=True)
    return base


def _ensure_client_config_dir() -> Path:
    """Создать каталог клиентских конфигов и подкаталог ``qr``."""
    d = _client_config_dir()
    qr = d / "qr"
    d.mkdir(parents=True, exist_ok=True)
    qr.mkdir(parents=True, exist_ok=True)
    return d


def _load_document(path: Path) -> dict[str, Any]:
    """Загрузить JSON-документ со списком клиентов или пустой шаблон."""
    if not path.is_file():
        return {"clients": []}
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {"clients": []}
    clients = data.get("clients")
    if not isinstance(clients, list):
        data["clients"] = []
    return data


def _save_document(path: Path, data: dict[str, Any]) -> None:
    """Атомарно сохранить JSON на диск."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def _unique_wg_name(display_name: str, taken: set[str]) -> str:
    """Уникальное имя маркера ``# Client: …`` в wg0.conf."""
    base = ascii_slug(display_name) or "user"
    short = uuid.uuid4().hex[:8]
    candidate = f"{base}_{short}"
    n = 0
    while candidate in taken:
        n += 1
        candidate = f"{base}_{short}_{n}"
    return candidate


def _merge_wg_into_document(doc: dict[str, Any], conf_path: Path) -> bool:
    """
    Слить состояние пиров из wg0.conf в ``doc['clients']``.

    Записи без ``wg_name`` отбрасываются; пиры только в конфиге добавляются в JSON.
    Возвращает True, если документ изменился и его нужно сохранить.
    """
    peers = wireguard_conf.list_peers_from_conf(conf_path)
    by_wg: dict[str, wireguard_conf.WgPeerBlock] = {p.name: p for p in peers}

    raw = doc.get("clients")
    if not isinstance(raw, list):
        raw = []
    clients = [c for c in raw if isinstance(c, dict)]

    changed = False
    kept: list[dict[str, Any]] = []
    seen_wg: set[str] = set()

    for row in clients:
        wgn = row.get("wg_name")
        if not isinstance(wgn, str) or not wgn.strip():
            continue
        wgn = wgn.strip()
        if wgn not in by_wg:
            changed = True
            continue
        peer = by_wg[wgn]
        seen_wg.add(wgn)
        ip = wireguard_conf.parse_peer_tunnel_ip(peer.body_lines)
        pub = wireguard_conf.parse_peer_public_key(peer.body_lines)
        en = wireguard_conf.peer_enabled(peer.body_lines)
        if ip and row.get("tunnel_ip") != ip:
            row["tunnel_ip"] = ip
            changed = True
        if pub and row.get("public_key") != pub:
            row["public_key"] = pub
            changed = True
        if bool(row.get("enabled")) != en:
            row["enabled"] = en
            changed = True
        kept.append(row)

    for wgn, peer in by_wg.items():
        if wgn in seen_wg:
            continue
        ip = wireguard_conf.parse_peer_tunnel_ip(peer.body_lines)
        pub = wireguard_conf.parse_peer_public_key(peer.body_lines)
        en = wireguard_conf.peer_enabled(peer.body_lines)
        if not ip:
            continue
        new_row: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "name": wgn,
            "wg_name": wgn,
            "tunnel_ip": ip,
            "private_key_rel": f"{wgn}_private.key",
            "enabled": en,
        }
        if pub:
            new_row["public_key"] = pub
        kept.append(new_row)
        changed = True

    if changed or len(kept) != len(clients):
        doc["clients"] = kept
        return True
    return False


def list_clients() -> list[dict[str, Any]]:
    """Список записей клиентов из JSON (без синхронизации с wg0.conf)."""
    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        raw = doc.get("clients") or []
        return [c for c in raw if isinstance(c, dict)]


def sync_clients_json_with_runtime_state() -> list[dict[str, Any]]:
    """
    При включённом WireGuard перечитать wg0.conf и обновить ``vpn_clients.json``.

    Если интеграция выключена или файла конфига нет — вернуть пустой список
    (дашборд без секции клиентов).
    """
    with _lock:
        if not settings.wireguard_enabled():
            return []
        conf_path = wg_local_runtime.wg_conf_path_resolved()
        if not conf_path.is_file():
            _log.warning("WireGuard: файл конфигурации не найден: %s", conf_path)
            return []
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        if _merge_wg_into_document(doc, conf_path):
            _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)
        raw = doc.get("clients") or []
        return [c for c in raw if isinstance(c, dict)]


def get_client(client_id: str) -> dict[str, Any] | None:
    """Найти клиента по UUID в текущем JSON."""
    for c in list_clients():
        if c.get("id") == client_id:
            return c
    return None


def create_client(name: str) -> dict[str, Any]:
    """
    Создать клиента: ключи, блок [Peer] в wg0.conf, запись в JSON, клиентский .conf.

    Требуются ``WIREGUARD_CONF_PATH``, файл конфига и настройки Endpoint
    (см. ``wg_local_runtime.resolve_client_endpoint``).
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("Имя пользователя не может быть пустым")
    if not settings.wireguard_enabled():
        raise RuntimeError("WireGuard не настроен (WIREGUARD_CONF_PATH)")

    conf_path = wg_local_runtime.wg_conf_path_resolved()
    if not conf_path.is_file():
        raise RuntimeError(f"Нет файла конфигурации WireGuard: {conf_path}")

    endpoint = wg_local_runtime.resolve_client_endpoint(conf_path)
    try:
        if (settings.WIREGUARD_NETWORK_CIDR or "").strip():
            subnet_prefix = wireguard_conf.subnet_prefix_from_network_cidr(
                settings.WIREGUARD_NETWORK_CIDR
            )
        else:
            subnet_prefix = wireguard_conf.server_subnet_prefix_from_conf(conf_path)
    except ValueError as e:
        raise RuntimeError(
            "Некорректная настройка WIREGUARD_NETWORK_CIDR. "
            "Ожидается IPv4 CIDR формата A.B.C.D/24 (например 10.8.0.1/24)."
        ) from e

    with _lock:
        peers = wireguard_conf.list_peers_from_conf(conf_path)
        taken = {p.name for p in peers}
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        raw_clients = [c for c in (doc.get("clients") or []) if isinstance(c, dict)]
        for c in raw_clients:
            w = c.get("wg_name")
            if isinstance(w, str) and w.strip():
                taken.add(w.strip())

        wg_name = _unique_wg_name(name, taken)
        tunnel_ip = wireguard_conf.pick_free_tunnel_ip(peers, subnet_prefix=subnet_prefix)

        priv, pub = wg_local_runtime.wg_gen_keypair()
        keys_dir = _ensure_keys_dir()
        priv_file = keys_dir / f"{wg_name}_private.key"
        pub_file = keys_dir / f"{wg_name}_public.key"
        priv_file.write_text(priv + "\n", encoding="utf-8")
        pub_file.write_text(pub + "\n", encoding="utf-8")
        try:
            os.chmod(priv_file, 0o600)
            os.chmod(pub_file, 0o644)
        except OSError:
            pass

        wireguard_conf.append_peer(conf_path, wg_name, pub, tunnel_ip)

        try:
            srv_pub = wg_local_runtime.server_public_key_from_interface(conf_path)
            if not srv_pub:
                raise RuntimeError(
                    "Не удалось получить публичный ключ сервера из конфига "
                    "(PrivateKey в [Interface])"
                )
            wg_local_runtime.write_client_conf_file(
                _ensure_client_config_dir(),
                wg_name,
                priv,
                tunnel_ip,
                srv_pub,
                endpoint,
            )
        except Exception:
            wireguard_conf.remove_peer(conf_path, wg_name)
            for f in (priv_file, pub_file):
                try:
                    f.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

        wg_local_runtime.apply_wg_syncconf_if_configured()

        cid = str(uuid.uuid4())
        row: dict[str, Any] = {
            "id": cid,
            "name": name,
            "wg_name": wg_name,
            "tunnel_ip": tunnel_ip,
            "private_key_rel": f"{wg_name}_private.key",
            "public_key": pub,
            "enabled": True,
        }
        raw_clients.append(row)
        doc["clients"] = raw_clients
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)
        return row


def set_client_enabled(client_id: str, enabled: bool) -> None:
    """Включить или отключить пир в wg0.conf и обновить поле ``enabled`` в JSON."""
    if not settings.wireguard_enabled():
        raise KeyError(client_id)

    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        clients = [c for c in (doc.get("clients") or []) if isinstance(c, dict)]
        target: dict[str, Any] | None = None
        for c in clients:
            if c.get("id") == client_id:
                target = c
                break
        if target is None:
            raise KeyError(client_id)
        wgn = target.get("wg_name")
        if not isinstance(wgn, str) or not wgn.strip():
            raise KeyError(client_id)
        wgn = wgn.strip()
        conf_path = wg_local_runtime.wg_conf_path_resolved()
        if not wireguard_conf.set_peer_block_enabled(conf_path, wgn, bool(enabled)):
            raise KeyError(client_id)
        target["enabled"] = bool(enabled)
        doc["clients"] = clients
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)
        wg_local_runtime.apply_wg_syncconf_if_configured()


def delete_client(client_id: str) -> None:
    """Удалить клиента из JSON, убрать пир из wg0.conf и файлы ключей/конфига."""
    if not settings.wireguard_enabled():
        raise KeyError(client_id)

    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        clients = [c for c in (doc.get("clients") or []) if isinstance(c, dict)]
        victim: dict[str, Any] | None = None
        rest: list[dict[str, Any]] = []
        for c in clients:
            if c.get("id") == client_id:
                victim = c
            else:
                rest.append(c)
        if victim is None:
            raise KeyError(client_id)
        wgn = victim.get("wg_name")
        if isinstance(wgn, str) and wgn.strip():
            conf_path = wg_local_runtime.wg_conf_path_resolved()
            wireguard_conf.remove_peer(conf_path, wgn.strip())
            keys_dir = _keys_base_path()
            w = wgn.strip()
            for p in (
                keys_dir / f"{w}_private.key",
                keys_dir / f"{w}_public.key",
            ):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
            cfg_dir = _client_config_dir()
            for p in (
                cfg_dir / f"{w}.conf",
                cfg_dir / "qr" / f"{w}.txt",
            ):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
            wg_local_runtime.apply_wg_syncconf_if_configured()

        doc["clients"] = rest
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)


def client_config_text(client_id: str) -> str:
    """Текст клиентского WireGuard-конфига с диска или заглушка с подсказкой."""
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    if not settings.wireguard_enabled():
        raise KeyError(client_id)
    wgn = c.get("wg_name")
    if isinstance(wgn, str) and wgn.strip():
        p = _client_config_dir() / f"{wgn.strip()}.conf"
        if p.is_file():
            return p.read_text(encoding="utf-8")
    name = c.get("name", "")
    tid = c.get("id", "")
    ip = c.get("tunnel_ip", "")
    key_rel = c.get("private_key_rel", "")
    return (
        f"# SelfVPN (конфиг клиента не найден на диске)\n"
        f"# client_id={tid}\n"
        f"# name={name}\n"
        f"[Interface]\n"
        f"# PrivateKey = (файл: {key_rel})\n"
        f"Address = {ip}/32\n"
        f"\n"
        f"[Peer]\n"
        f"# задайте WIREGUARD_ENDPOINT или WIREGUARD_PUBLIC_HOST и пересоздайте клиента\n"
    )


def client_config_bytes(client_id: str) -> bytes:
    """Содержимое .conf в байтах для отдачи в HTTP."""
    return client_config_text(client_id).encode("utf-8")


def config_download_basename(client_id: str) -> str:
    """Имя файла для заголовка Content-Disposition при скачивании конфига."""
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    slug = ascii_slug(str(c.get("name", "client")))
    short = str(c.get("id", ""))[:8]
    return f"{slug}_{short}.conf"


def qr_png_bytes(client_id: str) -> bytes:
    """PNG с QR-кодом, кодирующим текст клиентского конфига."""
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    payload = client_config_text(client_id)
    img = qrcode.make(payload, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
