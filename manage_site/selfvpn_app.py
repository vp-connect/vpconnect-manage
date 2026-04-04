from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid as uuid_mod
from datetime import timezone

from flask import Flask, abort, flash, redirect, render_template, request, Response, session, url_for

from . import admin_user_store
from . import login_attempts_store
from . import mtproxy_link
from . import settings
from . import telegram_proxy_qr
from . import vpn_clients_service

selfvpn_app = Flask(__name__)
selfvpn_app.secret_key = settings.FLASK_SECRET_KEY
_app_log = logging.getLogger(__name__)

# Сброс просроченных блокировок при импорте приложения (файл мог остаться от прошлых запусков).
login_attempts_store.purge_expired(settings.LOGIN_ATTEMPTS_JSON_PATH)


def _load_admin_password_md5() -> str | None:
    path = settings.ADMIN_USER_JSON_PATH
    if not path.is_file():
        return None
    try:
        with path.open(encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    raw = data.get('password_md5')
    if not isinstance(raw, str):
        return None
    return raw.strip().lower()


admin_user_store.ensure_admin_user_from_default_password()
_ADMIN_PASSWORD_MD5 = _load_admin_password_md5()


def _reload_admin_password_md5() -> None:
    global _ADMIN_PASSWORD_MD5
    _ADMIN_PASSWORD_MD5 = _load_admin_password_md5()


def _client_ip() -> str:
    # За обратным прокси при необходимости добавить разбор X-Forwarded-For с доверенным списком.
    return request.remote_addr or 'unknown'


def _password_ok(plain: str) -> bool:
    stored = _ADMIN_PASSWORD_MD5
    if stored is None or len(stored) != 32:
        return False
    digest = hashlib.md5(plain.encode('utf-8')).hexdigest()
    return hmac.compare_digest(stored, digest)


@selfvpn_app.before_request
def require_login():
    if request.endpoint in ('login', 'logout', 'static'):
        return
    if session.get('admin_authenticated'):
        return
    return redirect(url_for('login'))


def _require_client_uuid(client_id: str) -> str:
    try:
        uuid_mod.UUID(client_id)
    except ValueError:
        abort(404)
    return client_id


def _require_wireguard() -> None:
    if not settings.wireguard_enabled():
        abort(404)


@selfvpn_app.route('/')
def home():
    wireguard_enabled = settings.wireguard_enabled()
    mtproxy_enabled = settings.mtproxy_enabled()
    clients = (
        vpn_clients_service.sync_clients_json_with_runtime_state()
        if wireguard_enabled
        else []
    )
    telegram_proxy_url = mtproxy_link.read_mtproxy_link() if mtproxy_enabled else None
    return render_template(
        'clients.html',
        wireguard_enabled=wireguard_enabled,
        mtproxy_enabled=mtproxy_enabled,
        clients=clients,
        telegram_proxy_url=telegram_proxy_url,
    )


@selfvpn_app.get('/telegram-proxy/qr.png')
def telegram_proxy_qr_png():
    if not settings.mtproxy_enabled():
        abort(404)
    url = mtproxy_link.read_mtproxy_link()
    if not url:
        abort(404)
    try:
        data = telegram_proxy_qr.build_mtproxy_qr_png(url)
    except ValueError:
        abort(404)
    return Response(data, mimetype='image/png')


@selfvpn_app.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@selfvpn_app.post('/account/admin-password')
def admin_password():
    action = (request.form.get('action') or '').strip()
    if action == 'reset':
        default = (settings.ADMIN_DEFAULT_PASSWORD or '').strip()
        if not default:
            flash('В настройках не задан пароль по умолчанию (ADMIN_DEFAULT_PASSWORD).', 'error')
            return redirect(url_for('home'))
        try:
            admin_user_store.save_password_md5_hex(
                hashlib.md5(default.encode('utf-8')).hexdigest()
            )
        except ValueError:
            flash('Не удалось сохранить пароль.', 'error')
            return redirect(url_for('home'))
        _reload_admin_password_md5()
        flash('Пароль сброшен на значение по умолчанию из настроек.', 'message')
        return redirect(url_for('home'))

    if action == 'save':
        p1 = request.form.get('password') or ''
        p2 = request.form.get('password_confirm') or ''
        if not p1 or not p2:
            flash('Заполните оба поля пароля.', 'error')
            return redirect(url_for('home'))
        if p1 != p2:
            flash('Пароли не совпадают.', 'error')
            return redirect(url_for('home'))
        try:
            admin_user_store.save_password_md5_hex(
                hashlib.md5(p1.encode('utf-8')).hexdigest()
            )
        except ValueError:
            flash('Не удалось сохранить пароль.', 'error')
            return redirect(url_for('home'))
        _reload_admin_password_md5()
        flash('Пароль администратора сохранён.', 'message')
        return redirect(url_for('home'))

    return redirect(url_for('home'))


@selfvpn_app.post('/clients')
def clients_create():
    _require_wireguard()
    name = (request.form.get('name') or '').strip()
    if name:
        try:
            vpn_clients_service.create_client(name)
        except ValueError:
            pass
        except RuntimeError as e:
            flash(str(e), 'error')
    return redirect(url_for('home'))


@selfvpn_app.post('/clients/<client_id>/toggle')
def clients_toggle(client_id):
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    enabled = request.form.get('enabled') == '1'
    try:
        vpn_clients_service.set_client_enabled(client_id, enabled)
    except KeyError:
        abort(404)
    return redirect(url_for('home'))


@selfvpn_app.get('/clients/<client_id>/qr.png')
def clients_qr_png(client_id):
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    try:
        data = vpn_clients_service.qr_png_bytes(client_id)
    except KeyError:
        abort(404)
    return Response(data, mimetype='image/png')


@selfvpn_app.get('/clients/<client_id>/config.conf')
def clients_config_download(client_id):
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    try:
        body = vpn_clients_service.client_config_bytes(client_id)
        fname = vpn_clients_service.config_download_basename(client_id)
    except KeyError:
        abort(404)
    return Response(
        body,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename="{fname}"'},
    )


@selfvpn_app.post('/clients/<client_id>/delete')
def clients_delete(client_id):
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    try:
        vpn_clients_service.delete_client(client_id)
    except KeyError:
        abort(404)
    return redirect(url_for('home'))


@selfvpn_app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('admin_authenticated'):
        return redirect(url_for('home'))

    config_ok = _ADMIN_PASSWORD_MD5 is not None and len(_ADMIN_PASSWORD_MD5) == 32
    attempts_path = settings.LOGIN_ATTEMPTS_JSON_PATH
    ip = _client_ip()
    locked, locked_until = login_attempts_store.is_locked(attempts_path, ip)

    if request.method == 'POST' and not config_ok:
        return (
            render_template(
                'login.html',
                config_error=True,
                locked=False,
                locked_until=None,
                wrong_password=False,
            ),
            503,
        )

    if request.method == 'POST' and locked:
        return render_template(
            'login.html',
            config_error=False,
            locked=True,
            locked_until=locked_until,
            wrong_password=False,
        )

    if request.method == 'POST':
        password = (request.form.get('password') or '')
        if _password_ok(password):
            session['admin_authenticated'] = True
            login_attempts_store.clear_ip(attempts_path, ip)
            return redirect(url_for('home'))
        # Пустой пароль не считаем попыткой взлома (ложные POST без ввода не должны блокировать IP).
        if not password.strip():
            return render_template(
                'login.html',
                config_error=False,
                locked=False,
                locked_until=None,
                wrong_password=False,
            )
        max_attempts = max(1, settings.LOGIN_MAX_FAILED_ATTEMPTS)
        lockout_minutes = max(1, settings.LOGIN_LOCKOUT_MINUTES)
        login_attempts_store.record_failure(
            attempts_path,
            ip,
            max_attempts,
            lockout_minutes,
        )
        locked, locked_until = login_attempts_store.is_locked(attempts_path, ip)
        return render_template(
            'login.html',
            config_error=False,
            locked=locked,
            locked_until=locked_until,
            wrong_password=not locked,
        )

    return render_template(
        'login.html',
        config_error=not config_ok,
        locked=locked,
        locked_until=locked_until,
        wrong_password=False,
    )


@selfvpn_app.template_filter('fmt_lockout_utc')
def fmt_lockout_utc(dt):
    if dt is None:
        return ''
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime('%d.%m.%Y %H:%M UTC')


def _wireguard_background_sync_loop() -> None:
    while True:
        interval = max(0, settings.WIREGUARD_SYNC_INTERVAL_MINUTES)
        if interval <= 0:
            return
        time.sleep(interval * 60)
        try:
            with selfvpn_app.app_context():
                vpn_clients_service.sync_clients_json_with_runtime_state()
        except Exception:
            _app_log.exception('WireGuard: фоновая синхронизация')


if settings.wireguard_enabled():
    try:
        with selfvpn_app.app_context():
            vpn_clients_service.sync_clients_json_with_runtime_state()
    except Exception:
        _app_log.exception('WireGuard: синхронизация при старте')
    if settings.WIREGUARD_SYNC_INTERVAL_MINUTES > 0:
        threading.Thread(target=_wireguard_background_sync_loop, daemon=True).start()


if __name__ == '__main__':
    selfvpn_app.run()
