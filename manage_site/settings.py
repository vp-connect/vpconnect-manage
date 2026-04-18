"""
Конфигурация приложения: **env-settings** + корневой ``settings.env``.

Назначение
    Централизованное чтение переменных окружения и объявление констант, которые
    используют маршруты Flask и сервисы (пути к JSON, WireGuard, MTProxy).

Зависимости
    Внешний пакет ``env_settings`` (``configure``, ``load_env_params``, ``get_*_env_param``).
    Файл переменных задаётся ``ENV_FILENAME`` (по умолчанию ``settings.env`` в корне репо).

Кто читает этот модуль
    Почти все подмодули ``manage_site`` импортируют ``settings`` для путей и флагов.

Новые параметры
    Сначала объявление через ``get_*_env_param`` здесь, затем строка в ``settings.env``.
"""

from pathlib import Path

from env_settings import configure
from env_settings import get_file_env_param, get_int_env_param, get_str_env_param
from env_settings import load_env_params

configure(error_handling="exit")

ENV_FILENAME = get_file_env_param(
    "ENV_FILENAME",
    file_mast_exist=True,
    default="settings.env",
)
load_env_params(ENV_FILENAME)

FLASK_SECRET_KEY = get_str_env_param(
    "FLASK_SECRET_KEY",
    required=True,
    do_obfuscate_log_text=True,
)

ADMIN_DEFAULT_PASSWORD = get_str_env_param("ADMIN_DEFAULT_PASSWORD", default="")

LOGIN_MAX_FAILED_ATTEMPTS = get_int_env_param("LOGIN_MAX_FAILED_ATTEMPTS", default=5)
LOGIN_LOCKOUT_MINUTES = get_int_env_param("LOGIN_LOCKOUT_MINUTES", default=60)

_MANAGE_SITE_ROOT = Path(__file__).resolve().parent
ADMIN_USER_JSON_PATH = _MANAGE_SITE_ROOT / "data" / "admin_user.json"
LOGIN_ATTEMPTS_JSON_PATH = _MANAGE_SITE_ROOT / "data" / "login_attempts.json"
VPN_CLIENTS_JSON_PATH = _MANAGE_SITE_ROOT / "data" / "vpn_clients.json"

WIREGUARD_CONF_PATH = (get_str_env_param("WIREGUARD_CONF_PATH", default="") or "").strip()

WIREGUARD_SYNC_INTERVAL_MINUTES = get_int_env_param(
    "WIREGUARD_SYNC_INTERVAL_MINUTES",
    default=5,
)

WIREGUARD_INTERFACE_NAME = (
    get_str_env_param("WIREGUARD_INTERFACE_NAME", default="wg0") or ""
).strip() or "wg0"

# CIDR сети WireGuard (например 10.8.0.1/24).
# Используется для выдачи IP и Address в клиентских конфигах.
WIREGUARD_NETWORK_CIDR = (get_str_env_param("WIREGUARD_NETWORK_CIDR", default="") or "").strip()

WIREGUARD_ENDPOINT = (get_str_env_param("WIREGUARD_ENDPOINT", default="") or "").strip()

WIREGUARD_PUBLIC_HOST = (get_str_env_param("WIREGUARD_PUBLIC_HOST", default="") or "").strip()

WIREGUARD_LISTEN_PORT = get_int_env_param("WIREGUARD_LISTEN_PORT", default=0)

WIREGUARD_DNS = (get_str_env_param("WIREGUARD_DNS", default="8.8.8.8") or "").strip() or "8.8.8.8"

WIREGUARD_CLIENT_CONFIG_DIR = (
    get_str_env_param("WIREGUARD_CLIENT_CONFIG_DIR", default="") or ""
).strip()

WIREGUARD_CLIENT_KEYS_DIR = get_file_env_param(
    "WIREGUARD_CLIENT_KEYS_DIR",
    file_mast_exist=False,
    dir_mast_exist=False,
    default=str(_MANAGE_SITE_ROOT / "data" / "vpn_client_keys"),
)

MTPROXY_LINK_FILE = (get_str_env_param("MTPROXY_LINK_FILE", default="") or "").strip()


def wireguard_enabled() -> bool:
    """
    Проверить, включена ли интеграция с WireGuard в панели.

    Прецедент: перед маршрутами и сервисами, где нужен ``wg0.conf``.

    Returns:
        ``True``, если в настройках задан непустой ``WIREGUARD_CONF_PATH``.
    """
    return bool(WIREGUARD_CONF_PATH)


def mtproxy_enabled() -> bool:
    """
    Проверить, показывать ли блок MTProxy (ссылка из файла).

    Прецедент: дашборд, QR MTProxy.

    Returns:
        ``True``, если задан непустой ``MTPROXY_LINK_FILE``.
    """
    return bool(MTPROXY_LINK_FILE)
