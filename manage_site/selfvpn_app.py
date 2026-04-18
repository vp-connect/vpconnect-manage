"""
Flask-приложение **vpconnect-manage**: вход администратора, дашборд, WireGuard, MTProxy.

Назначение
    HTTP-слой над сервисами: сессия, формы, отдача шаблонов и бинарных ответов (QR, ``.conf``).

Зависимости (внутренние модули)
    ``settings``, ``admin_user_store``, ``login_attempts_store``, ``mtproxy_link``,
    ``telegram_proxy_qr``, ``vpn_clients_service``, ``wg_background_sync``.

Побочные эффекты при импорте
    Загрузка ``settings``, ``purge_expired`` для файла попыток входа, возможное создание
    ``admin_user.json`` из ``ADMIN_DEFAULT_PASSWORD``, кэш MD5 пароля, регистрация
    фоновой синхронизации WireGuard.

Точка входа WSGI
    Объект ``selfvpn_app`` (экземпляр ``Flask``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid as uuid_mod
from datetime import timezone

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    Response,
    session,
    url_for,
)

from . import admin_user_store
from . import login_attempts_store
from . import mtproxy_link
from . import settings
from . import telegram_proxy_qr
from . import vpn_clients_service
from . import wg_background_sync

selfvpn_app = Flask(__name__)
selfvpn_app.secret_key = settings.FLASK_SECRET_KEY

login_attempts_store.purge_expired(settings.LOGIN_ATTEMPTS_JSON_PATH)


def _load_admin_password_md5() -> str | None:
    """
    Прочитать MD5 пароля администратора из ``admin_user.json``.

    Прецедент: при импорте модуля и после смены пароля через ``_reload_admin_password_md5``.

    Returns:
        32 символа hex в нижнем регистре или ``None`` (нет файла, битый JSON, нет поля).
    """
    path = settings.ADMIN_USER_JSON_PATH
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    raw = data.get("password_md5")
    if not isinstance(raw, str):
        return None
    return raw.strip().lower()


admin_user_store.ensure_admin_user_from_default_password()
_ADMIN_PASSWORD_MD5 = _load_admin_password_md5()


def _reload_admin_password_md5() -> None:
    """Обновить модульный кэш ``_ADMIN_PASSWORD_MD5`` после успешной записи пароля на диск."""
    global _ADMIN_PASSWORD_MD5
    _ADMIN_PASSWORD_MD5 = _load_admin_password_md5()


def _try_save_admin_password_plain(plain: str) -> bool:
    """
    Сохранить MD5 от пароля в открытом виде.

    Args:
        plain: пароль до хэширования.

    Returns:
        ``True`` при успехе; ``False`` при ``ValueError`` из хранилища.
    """
    try:
        admin_user_store.save_password_md5_hex(hashlib.md5(plain.encode("utf-8")).hexdigest())
    except ValueError:
        return False
    return True


def _client_ip() -> str:
    """
    IP клиента текущего запроса.

    Returns:
        ``request.remote_addr`` или ``\"unknown\"``, если адрес не задан.
    """
    return request.remote_addr or "unknown"


def _password_ok(plain: str) -> bool:
    """
    Сравнить введённый пароль с кэшированным MD5 (без утечки по времени).

    Args:
        plain: пароль из формы входа.

    Returns:
        ``True``, если MD5 совпадает с ``_ADMIN_PASSWORD_MD5`` (длина кэша 32).
    """
    stored = _ADMIN_PASSWORD_MD5
    if stored is None or len(stored) != 32:
        return False
    digest = hashlib.md5(plain.encode("utf-8")).hexdigest()
    return hmac.compare_digest(stored, digest)


@selfvpn_app.before_request
def require_login():
    """
    Требовать сессию администратора для всех маршрутов, кроме исключений.

    Исключения: ``login``, ``logout``, ``static``.
    """
    if request.endpoint in ("login", "logout", "static"):
        return
    if session.get("admin_authenticated"):
        return
    return redirect(url_for("login"))


def _require_client_uuid(client_id: str) -> str:
    """
    Убедиться, что ``client_id`` — UUID.

    Args:
        client_id: сегмент URL.

    Returns:
        Тот же ``client_id`` при успехе.

    Raises:
        HTTP 404: при невалидном UUID (через ``abort``).
    """
    try:
        uuid_mod.UUID(client_id)
    except ValueError:
        abort(404)
    return client_id


def _require_wireguard() -> None:
    """
    Завершить запрос 404, если интеграция WireGuard выключена.

    Прецедент: маршруты под ``/clients/...``.
    """
    if not settings.wireguard_enabled():
        abort(404)


@selfvpn_app.route("/")
def home():
    """
    Главная страница дашборда: список клиентов WG и/или блок MTProxy.

    Данные клиентов при включённом WG синхронизируются с ``wg0.conf`` перед рендером.
    """
    wireguard_enabled = settings.wireguard_enabled()
    mtproxy_enabled = settings.mtproxy_enabled()
    clients = (
        vpn_clients_service.sync_clients_json_with_runtime_state() if wireguard_enabled else []
    )
    telegram_proxy_url = mtproxy_link.read_mtproxy_link() if mtproxy_enabled else None
    return render_template(
        "clients.html",
        wireguard_enabled=wireguard_enabled,
        mtproxy_enabled=mtproxy_enabled,
        clients=clients,
        telegram_proxy_url=telegram_proxy_url,
    )


@selfvpn_app.get("/telegram-proxy/qr.png")
def telegram_proxy_qr_png():
    """
    PNG с QR-кодом ссылки MTProxy.

    Returns:
        ``Response`` с ``image/png`` или 404, если MTProxy выключен, ссылки нет или QR не собрать.
    """
    if not settings.mtproxy_enabled():
        abort(404)
    url = mtproxy_link.read_mtproxy_link()
    if not url:
        abort(404)
    try:
        data = telegram_proxy_qr.build_mtproxy_qr_png(url)
    except ValueError:
        abort(404)
    return Response(data, mimetype="image/png")


@selfvpn_app.post("/logout")
def logout():
    """Очистить сессию и отправить на форму входа."""
    session.clear()
    return redirect(url_for("login"))


@selfvpn_app.post("/account/admin-password")
def admin_password():
    """
    Смена или сброс пароля администратора (POST form).

    Поля формы:
        ``action`` — ``reset`` (на ``ADMIN_DEFAULT_PASSWORD``) или ``save`` (новый пароль).
        При ``save``: ``password``, ``password_confirm`` должны совпадать и быть непустыми.
    """
    action = (request.form.get("action") or "").strip()
    if action == "reset":
        default = (settings.ADMIN_DEFAULT_PASSWORD or "").strip()
        if not default:
            flash(
                "В настройках не задан пароль по умолчанию (ADMIN_DEFAULT_PASSWORD).",
                "error",
            )
            return redirect(url_for("home"))
        if not _try_save_admin_password_plain(default):
            flash("Не удалось сохранить пароль.", "error")
            return redirect(url_for("home"))
        _reload_admin_password_md5()
        flash("Пароль сброшен на значение по умолчанию из настроек.", "message")
        return redirect(url_for("home"))

    if action == "save":
        p1 = request.form.get("password") or ""
        p2 = request.form.get("password_confirm") or ""
        if not p1 or not p2:
            flash("Заполните оба поля пароля.", "error")
            return redirect(url_for("home"))
        if p1 != p2:
            flash("Пароли не совпадают.", "error")
            return redirect(url_for("home"))
        if not _try_save_admin_password_plain(p1):
            flash("Не удалось сохранить пароль.", "error")
            return redirect(url_for("home"))
        _reload_admin_password_md5()
        flash("Пароль администратора сохранён.", "message")
        return redirect(url_for("home"))

    return redirect(url_for("home"))


@selfvpn_app.post("/clients")
def clients_create():
    """
    Создать клиента WireGuard по имени из формы (поле ``name``).

    Ошибки ``RuntimeError`` показываются через ``flash``; прочие — общее сообщение.
    """
    _require_wireguard()
    name = (request.form.get("name") or "").strip()
    if name:
        try:
            vpn_clients_service.create_client(name)
        except RuntimeError as e:
            flash(str(e), "error")
        except Exception:
            flash("Не удалось создать клиента (внутренняя ошибка).", "error")
    return redirect(url_for("home"))


@selfvpn_app.post("/clients/<client_id>/toggle")
def clients_toggle(client_id):
    """
    Включить/выключить пира в ``wg0.conf`` (форма: ``enabled`` == ``\"1\"`` для включения).

    Args:
        client_id: UUID клиента из JSON.
    """
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    enabled = request.form.get("enabled") == "1"
    try:
        vpn_clients_service.set_client_enabled(client_id, enabled)
    except KeyError:
        abort(404)
    return redirect(url_for("home"))


@selfvpn_app.get("/clients/<client_id>/qr.png")
def clients_qr_png(client_id):
    """PNG QR с текстом клиентского ``.conf`` (или 404)."""
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    try:
        data = vpn_clients_service.qr_png_bytes(client_id)
    except KeyError:
        abort(404)
    return Response(data, mimetype="image/png")


@selfvpn_app.get("/clients/<client_id>/config.conf")
def clients_config_download(client_id):
    """Скачивание клиентского ``.conf`` (или 404)."""
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    try:
        body = vpn_clients_service.client_config_bytes(client_id)
        fname = vpn_clients_service.config_download_basename(client_id)
    except KeyError:
        abort(404)
    return Response(
        body,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@selfvpn_app.post("/clients/<client_id>/delete")
def clients_delete(client_id):
    """Удалить клиента из JSON и артефакты WG (или 404)."""
    _require_wireguard()
    client_id = _require_client_uuid(client_id)
    try:
        vpn_clients_service.delete_client(client_id)
    except KeyError:
        abort(404)
    return redirect(url_for("home"))


@selfvpn_app.route("/login", methods=["GET", "POST"])
def login():
    """
    Форма входа: GET — страница; POST — проверка пароля и учёт блокировок по IP.

    Шаблон ``login.html`` получает флаги ``config_error``, ``locked``, ``wrong_password`` и т.д.
    """
    if session.get("admin_authenticated"):
        return redirect(url_for("home"))

    config_ok = _ADMIN_PASSWORD_MD5 is not None and len(_ADMIN_PASSWORD_MD5) == 32
    attempts_path = settings.LOGIN_ATTEMPTS_JSON_PATH
    ip = _client_ip()
    locked, locked_until = login_attempts_store.is_locked(attempts_path, ip)

    if request.method == "POST" and not config_ok:
        return (
            render_template(
                "login.html",
                config_error=True,
                locked=False,
                locked_until=None,
                wrong_password=False,
            ),
            503,
        )

    if request.method == "POST" and locked:
        return render_template(
            "login.html",
            config_error=False,
            locked=True,
            locked_until=locked_until,
            wrong_password=False,
        )

    if request.method == "POST":
        password = request.form.get("password") or ""
        if _password_ok(password):
            session["admin_authenticated"] = True
            login_attempts_store.clear_ip(attempts_path, ip)
            return redirect(url_for("home"))
        if not password.strip():
            return render_template(
                "login.html",
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
            "login.html",
            config_error=False,
            locked=locked,
            locked_until=locked_until,
            wrong_password=not locked,
        )

    return render_template(
        "login.html",
        config_error=not config_ok,
        locked=locked,
        locked_until=locked_until,
        wrong_password=False,
    )


@selfvpn_app.template_filter("fmt_lockout_utc")
def fmt_lockout_utc(dt):
    """
    Jinja-фильтр: время окончания блокировки в UTC для отображения.

    Args:
        dt: ``datetime`` или ``None``.

    Returns:
        Строка ``дд.мм.гггг чч:мм UTC`` или пустая строка.
    """
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%d.%m.%Y %H:%M UTC")


wg_background_sync.register_wireguard_background_sync(selfvpn_app)


if __name__ == "__main__":
    selfvpn_app.run()
