"""Клиенты VPN: JSON, синхронизация с wg0.conf и выдача конфигов/QR."""

from __future__ import annotations

import io
import json
import logging
import os
import re
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

import qrcode

from . import settings
from . import wireguard_conf

_lock = threading.RLock()
_log = logging.getLogger(__name__)

_PRIVATE_KEY_RE = re.compile(r'^\s*PrivateKey\s*=\s*(\S+)\s*$')
_LISTEN_PORT_RE = re.compile(r'^\s*ListenPort\s*=\s*(\d+)\s*$')


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
    p = Path(settings.WIREGUARD_CLIENT_KEYS_DIR)
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


def _client_config_dir() -> Path:
    raw = (settings.WIREGUARD_CLIENT_CONFIG_DIR or '').strip()
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        return p.resolve()
    return (_keys_base_path().parent / 'client_config').resolve()


def _ensure_keys_dir() -> Path:
    base = _keys_base_path()
    base.mkdir(parents=True, exist_ok=True)
    return base


def _ensure_client_config_dir() -> Path:
    d = _client_config_dir()
    qr = d / 'qr'
    d.mkdir(parents=True, exist_ok=True)
    qr.mkdir(parents=True, exist_ok=True)
    return d


def _wg_conf_path() -> Path:
    return Path(settings.WIREGUARD_CONF_PATH).expanduser().resolve()


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


def _wg_gen_keypair() -> tuple[str, str]:
    try:
        gen = subprocess.run(
            ['wg', 'genkey'],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        priv = gen.stdout.strip()
        pub = subprocess.run(
            ['wg', 'pubkey'],
            input=priv,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return priv, pub.stdout.strip()
    except FileNotFoundError as e:
        raise RuntimeError('Команда wg не найдена. Установите wireguard-tools.') from e
    except subprocess.CalledProcessError as e:
        err = (e.stderr or e.stdout or '').strip() or str(e)
        raise RuntimeError(f'Ошибка генерации ключей wg: {err}') from e


def _logical_config_line(line: str) -> str:
    logical = line.lstrip()
    while logical.startswith('#'):
        logical = logical[1:].lstrip()
    return logical.strip()


def _listen_port_from_preamble(conf_path: Path) -> int | None:
    preamble, _ = wireguard_conf.parse_wg_conf(conf_path)
    for line in preamble:
        m = _LISTEN_PORT_RE.match(_logical_config_line(line))
        if m:
            return int(m.group(1))
    return None


def _resolve_client_endpoint(conf_path: Path) -> str:
    """Endpoint в клиентском .conf: внешний адрес, с которого клиент достучится до сервера."""
    direct = (settings.WIREGUARD_ENDPOINT or '').strip()
    if direct:
        return direct
    host = (settings.WIREGUARD_PUBLIC_HOST or '').strip()
    if not host:
        raise RuntimeError(
            'Укажите WIREGUARD_ENDPOINT (например vpn.example.com:51820) '
            'или WIREGUARD_PUBLIC_HOST (порт возьмётся из ListenPort в wg0.conf, '
            'из WIREGUARD_LISTEN_PORT при ненулевом значении или 51820).'
        )
    lp = settings.WIREGUARD_LISTEN_PORT or 0
    if lp > 0:
        port = lp
    else:
        parsed = _listen_port_from_preamble(conf_path)
        port = parsed if parsed is not None else 51820
    return f'{host}:{port}'


def _server_public_key_from_conf(conf_path: Path) -> str | None:
    preamble, _ = wireguard_conf.parse_wg_conf(conf_path)
    priv: str | None = None
    for line in preamble:
        m = _PRIVATE_KEY_RE.match(_logical_config_line(line))
        if m:
            priv = m.group(1).strip()
            break
    if not priv:
        return None
    try:
        pub = subprocess.run(
            ['wg', 'pubkey'],
            input=priv,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return pub.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None


def _write_client_conf_file(
    wg_name: str,
    private_key: str,
    tunnel_ip: str,
    server_public_key: str,
    endpoint: str,
) -> Path:
    cfg_dir = _ensure_client_config_dir()
    path = cfg_dir / f'{wg_name}.conf'
    dns = (settings.WIREGUARD_DNS or '8.8.8.8').strip()
    text = (
        '[Interface]\n'
        f'PrivateKey = {private_key}\n'
        f'Address = {tunnel_ip}/24\n'
        f'DNS = {dns}\n'
        '\n'
        '[Peer]\n'
        f'PublicKey = {server_public_key}\n'
        f'Endpoint = {endpoint}\n'
        'AllowedIPs = 0.0.0.0/0\n'
        'PersistentKeepalive = 25\n'
    )
    path.write_text(text, encoding='utf-8')
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _syncconf_warning(msg: str) -> None:
    _log.warning('%s', msg)


def _after_wg_conf_mutation() -> None:
    if not settings.wireguard_enabled():
        return
    wireguard_conf.try_run_wg_syncconf(
        settings.WIREGUARD_INTERFACE_NAME,
        _wg_conf_path(),
        _syncconf_warning,
    )


def _unique_wg_name(display_name: str, taken: set[str]) -> str:
    base = ascii_slug(display_name) or 'user'
    short = uuid.uuid4().hex[:8]
    candidate = f'{base}_{short}'
    n = 0
    while candidate in taken:
        n += 1
        candidate = f'{base}_{short}_{n}'
    return candidate


def _merge_wg_into_document(doc: dict[str, Any], conf_path: Path) -> bool:
    """Актуализировать clients по wg0.conf. WG — источник истины по составу и статусу пиров."""
    peers = wireguard_conf.list_peers_from_conf(conf_path)
    by_wg: dict[str, wireguard_conf.WgPeerBlock] = {p.name: p for p in peers}

    raw = doc.get('clients')
    if not isinstance(raw, list):
        raw = []
    clients = [c for c in raw if isinstance(c, dict)]

    changed = False
    kept: list[dict[str, Any]] = []
    seen_wg: set[str] = set()

    for row in clients:
        wgn = row.get('wg_name')
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
        if ip and row.get('tunnel_ip') != ip:
            row['tunnel_ip'] = ip
            changed = True
        if pub and row.get('public_key') != pub:
            row['public_key'] = pub
            changed = True
        if bool(row.get('enabled')) != en:
            row['enabled'] = en
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
            'id': str(uuid.uuid4()),
            'name': wgn,
            'wg_name': wgn,
            'tunnel_ip': ip,
            'private_key_rel': f'{wgn}_private.key',
            'enabled': en,
        }
        if pub:
            new_row['public_key'] = pub
        kept.append(new_row)
        changed = True

    if changed or len(kept) != len(clients):
        doc['clients'] = kept
        return True
    return False


def list_clients() -> list[dict[str, Any]]:
    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        raw = doc.get('clients') or []
        return [c for c in raw if isinstance(c, dict)]


def sync_clients_json_with_runtime_state() -> list[dict[str, Any]]:
    """Синхронизация с WireGuard при включённой интеграции; иначе без обработки WG."""
    with _lock:
        if not settings.wireguard_enabled():
            return []
        conf_path = _wg_conf_path()
        if not conf_path.is_file():
            _log.warning('WireGuard: файл конфигурации не найден: %s', conf_path)
            return []
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        if _merge_wg_into_document(doc, conf_path):
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
    if not settings.wireguard_enabled():
        raise RuntimeError('WireGuard не настроен (WIREGUARD_CONF_PATH)')

    conf_path = _wg_conf_path()
    if not conf_path.is_file():
        raise RuntimeError(f'Нет файла конфигурации WireGuard: {conf_path}')

    endpoint = _resolve_client_endpoint(conf_path)

    with _lock:
        peers = wireguard_conf.list_peers_from_conf(conf_path)
        taken = {p.name for p in peers}
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        raw_clients = [c for c in (doc.get('clients') or []) if isinstance(c, dict)]
        for c in raw_clients:
            w = c.get('wg_name')
            if isinstance(w, str) and w.strip():
                taken.add(w.strip())

        wg_name = _unique_wg_name(name, taken)
        tunnel_ip = wireguard_conf.pick_free_tunnel_ip(peers)

        priv, pub = _wg_gen_keypair()
        keys_dir = _ensure_keys_dir()
        priv_file = keys_dir / f'{wg_name}_private.key'
        pub_file = keys_dir / f'{wg_name}_public.key'
        priv_file.write_text(priv + '\n', encoding='utf-8')
        pub_file.write_text(pub + '\n', encoding='utf-8')
        try:
            os.chmod(priv_file, 0o600)
            os.chmod(pub_file, 0o644)
        except OSError:
            pass

        wireguard_conf.append_peer(conf_path, wg_name, pub, tunnel_ip)

        try:
            srv_pub = _server_public_key_from_conf(conf_path)
            if not srv_pub:
                raise RuntimeError(
                    'Не удалось получить публичный ключ сервера из конфига (PrivateKey в [Interface])'
                )
            _write_client_conf_file(wg_name, priv, tunnel_ip, srv_pub, endpoint)
        except Exception:
            wireguard_conf.remove_peer(conf_path, wg_name)
            for f in (priv_file, pub_file):
                try:
                    f.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

        _after_wg_conf_mutation()

        cid = str(uuid.uuid4())
        row: dict[str, Any] = {
            'id': cid,
            'name': name,
            'wg_name': wg_name,
            'tunnel_ip': tunnel_ip,
            'private_key_rel': f'{wg_name}_private.key',
            'public_key': pub,
            'enabled': True,
        }
        raw_clients.append(row)
        doc['clients'] = raw_clients
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)
        return row


def set_client_enabled(client_id: str, enabled: bool) -> None:
    if not settings.wireguard_enabled():
        raise KeyError(client_id)

    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        clients = [c for c in (doc.get('clients') or []) if isinstance(c, dict)]
        target: dict[str, Any] | None = None
        for c in clients:
            if c.get('id') == client_id:
                target = c
                break
        if target is None:
            raise KeyError(client_id)
        wgn = target.get('wg_name')
        if not isinstance(wgn, str) or not wgn.strip():
            raise KeyError(client_id)
        wgn = wgn.strip()
        conf_path = _wg_conf_path()
        if not wireguard_conf.set_peer_block_enabled(conf_path, wgn, bool(enabled)):
            raise KeyError(client_id)
        target['enabled'] = bool(enabled)
        doc['clients'] = clients
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)
        _after_wg_conf_mutation()


def delete_client(client_id: str) -> None:
    if not settings.wireguard_enabled():
        raise KeyError(client_id)

    with _lock:
        doc = _load_document(settings.VPN_CLIENTS_JSON_PATH)
        clients = [c for c in (doc.get('clients') or []) if isinstance(c, dict)]
        victim: dict[str, Any] | None = None
        rest: list[dict[str, Any]] = []
        for c in clients:
            if c.get('id') == client_id:
                victim = c
            else:
                rest.append(c)
        if victim is None:
            raise KeyError(client_id)
        wgn = victim.get('wg_name')
        if isinstance(wgn, str) and wgn.strip():
            conf_path = _wg_conf_path()
            wireguard_conf.remove_peer(conf_path, wgn.strip())
            keys_dir = _keys_base_path()
            w = wgn.strip()
            for p in (
                keys_dir / f'{w}_private.key',
                keys_dir / f'{w}_public.key',
            ):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
            cfg_dir = _client_config_dir()
            for p in (
                cfg_dir / f'{w}.conf',
                cfg_dir / 'qr' / f'{w}.txt',
            ):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
            _after_wg_conf_mutation()

        doc['clients'] = rest
        _save_document(settings.VPN_CLIENTS_JSON_PATH, doc)


def client_config_text(client_id: str) -> str:
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    if not settings.wireguard_enabled():
        raise KeyError(client_id)
    wgn = c.get('wg_name')
    if isinstance(wgn, str) and wgn.strip():
        p = _client_config_dir() / f'{wgn.strip()}.conf'
        if p.is_file():
            return p.read_text(encoding='utf-8')
    name = c.get('name', '')
    tid = c.get('id', '')
    ip = c.get('tunnel_ip', '')
    key_rel = c.get('private_key_rel', '')
    return (
        f'# SelfVPN (конфиг клиента не найден на диске)\n'
        f'# client_id={tid}\n'
        f'# name={name}\n'
        f'[Interface]\n'
        f'# PrivateKey = (файл: {key_rel})\n'
        f'Address = {ip}/32\n'
        f'\n'
        f'[Peer]\n'
        f'# задайте WIREGUARD_ENDPOINT или WIREGUARD_PUBLIC_HOST и пересоздайте клиента\n'
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
    c = get_client(client_id)
    if not c:
        raise KeyError(client_id)
    payload = client_config_text(client_id)
    img = qrcode.make(payload, border=2)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()
