"""Хранение клиентов VPN и заглушки процедур (ключи, QR, конфиг) для последующей реализации."""

from __future__ import annotations

import io
import json
import random
import re
import threading
import uuid
from pathlib import Path
from typing import Any

import qrcode

from . import settings

_lock = threading.RLock()


def ascii_slug(name: str) -> str:
    t = (name or '').strip().lower()
    for a, b in (
        ('щ', 'sch'),
        ('ш', 'sh'),
        ('ч', 'ch'),
        ('ж', 'zh'),
        ('ю', 'yu'),
        ('я', 'ya'),
        ('ё', 'e'),
        ('э', 'e'),
        ('ы', 'y'),
        ('й', 'j'),
        ('ъ', ''),
        ('ь', ''),
    ):
        t = t.replace(a, b)
    t = t.translate(
        str.maketrans(
            'абвгдезиклмнопрстуфхц',
            'abvgdeziklmnoprstufhc',
        )
    )
    s = re.sub(r'[^a-z0-9]+', '_', t)
    s = s.strip('_')
    return s or 'user'


def _keys_base_path() -> Path:
    p = Path(settings.VPN_CLIENT_KEYS_BASE_DIR)
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


def _ensure_keys_dir() -> Path:
    base = _keys_base_path()
    base.mkdir(parents=True, exist_ok=True)
    return base


def _load_document(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {'clients': []}
    with path.open(encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {'clients': []}
    clients = data.get('clients')
    if not isinstance(clients, list):
        data['clients'] = []
    return data


def _save_document(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write('\n')
    tmp.replace(path)


def _used_tunnel_ips(clients: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for c in clients:
        if isinstance(c, dict) and isinstance(c.get('tunnel_ip'), str):
            out.add(c['tunnel_ip'])
    return out


def _pick_tunnel_ip(clients: list[dict[str, Any]]) -> str:
    used = _used_tunnel_ips(clients)
    candidates = [f'10.0.0.{n}' for n in range(1, 255) if f'10.0.0.{n}' not in used]
    if not candidates:
        raise RuntimeError('Не осталось свободных адресов 10.0.0.x')
    return random.choice(candidates)


def list_clients() -> list[dict[str, Any]]:
    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        raw = doc.get('clients') or []
        return [c for c in raw if isinstance(c, dict)]


def _fetch_clients_runtime_state() -> dict[str, Any]:
    """Фактическое состояние клиентов вне JSON (WireGuard, ОС и т.д.).

    Заглушка: источник и формат будут заданы позже.
    """
    return {}


def _apply_runtime_state_to_document(
    doc: dict[str, Any],
    runtime_state: dict[str, Any],
) -> bool:
    """Слить состояние из runtime_state в doc (поле clients).

    Возвращает True, если документ изменился и его нужно сохранить на диск.

    Заглушка: пока не изменяет doc.
    """
    _ = runtime_state
    return False


def sync_clients_json_with_runtime_state() -> list[dict[str, Any]]:
    """Получить текущее состояние клиентов из внешних источников и актуализировать JSON.

    После реализации: опрос фактического состояния, при необходимости правка списка
    в ``vpn_clients.json`` и запись файла.

    Сейчас: перечитывает файл с диска, вызывает заглушки опроса/слияния без изменений.
    """
    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        runtime = _fetch_clients_runtime_state()
        if _apply_runtime_state_to_document(doc, runtime):
            _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)
        raw = doc.get('clients') or []
        return [c for c in raw if isinstance(c, dict)]


def get_client(client_id: str) -> dict[str, Any] | None:
    for c in list_clients():
        if c.get('id') == client_id:
            return c
    return None


def create_client(name: str) -> dict[str, Any]:
    name = (name or '').strip()
    if not name:
        raise ValueError('Имя пользователя не может быть пустым')

    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        clients = [c for c in (doc.get('clients') or []) if isinstance(c, dict)]

        cid = str(uuid.uuid4())
        slug = ascii_slug(name)
        tunnel_ip = _pick_tunnel_ip(clients)
        private_key_rel = f'{cid}_{slug}.key'

        _ensure_keys_dir()

        row: dict[str, Any] = {
            'id': cid,
            'name': name,
            'tunnel_ip': tunnel_ip,
            'private_key_rel': private_key_rel,
            'enabled': True,
        }
        clients.append(row)
        doc['clients'] = clients
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)
        return row


def set_client_enabled(client_id: str, enabled: bool) -> None:
    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        clients = [c for c in (doc.get('clients') or []) if isinstance(c, dict)]
        found = False
        for c in clients:
            if c.get('id') == client_id:
                c['enabled'] = bool(enabled)
                found = True
                break
        if not found:
            raise KeyError(client_id)
        doc['clients'] = clients
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)


def delete_client(client_id: str) -> None:
    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        clients = [c for c in (doc.get('clients') or []) if isinstance(c, dict)]
        new_list = [c for c in clients if c.get('id') != client_id]
        if len(new_list) == len(clients):
            raise KeyError(client_id)
        doc['clients'] = new_list
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)


def client_config_text(client_id: str) -> str:
    """Заглушка: текст .conf для скачивания (позже заменить на реальную сборку)."""
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    name = c.get('name', '')
    tid = c.get('id', '')
    ip = c.get('tunnel_ip', '')
    key_rel = c.get('private_key_rel', '')
    return (
        f'# SelfVPN stub config\n'
        f'# client_id={tid}\n'
        f'# name={name}\n'
        f'[Interface]\n'
        f'# PrivateKey = (файл: {key_rel})\n'
        f'Address = {ip}/32\n'
        f'\n'
        f'[Peer]\n'
        f'# PublicKey = <server>\n'
        f'Endpoint = <server>:51820\n'
        f'AllowedIPs = 0.0.0.0/0\n'
    )


def client_config_bytes(client_id: str) -> bytes:
    return client_config_text(client_id).encode('utf-8')


def config_download_basename(client_id: str) -> str:
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    slug = ascii_slug(str(c.get('name', 'client')))
    short = str(c.get('id', ''))[:8]
    return f'{slug}_{short}.conf'


def qr_png_bytes(client_id: str) -> bytes:
    """Заглушка: PNG с QR, содержащим плейсхолдер (позже — реальный конфиг)."""
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    payload = (
        f'selfvpn://stub?id={c.get("id")}&name={c.get("name")}&ip={c.get("tunnel_ip")}'
    )
    img = qrcode.make(payload, border=2)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()
