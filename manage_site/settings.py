"""
Общие настройки для работы
Специальные настройки для работы с конкретными нагрузочными тестами,
указываются в файлах settings.py соответствующих модулей

Пользовательская настройка производится в файле конфигурации в формате .env

Файл .env может иметь любое имя,
чтобы скрипт настройки использовал файл необходимо:
  - либо указать значение в переменной окружения ENV_FILENAME
  - либо указать этот файл в параметре командной строки --envfile {файл}

По умолчанию используется файл .env
"""

from pathlib import Path

from env_settings import get_file_env_param, get_str_env_param
from env_settings import get_int_env_param
from env_settings import load_env_params, configure

configure(error_handling='exit')

# .env файл для загрузки параметров
ENV_FILENAME = get_file_env_param('ENV_FILENAME', file_mast_exist=True, default='settings.env')
load_env_params(ENV_FILENAME)

# веб-панель: подпись cookie сессии
FLASK_SECRET_KEY = get_str_env_param('FLASK_SECRET_KEY', required=True, do_obfuscate_log_text=True)

# пароль администратора по умолчанию (для будущего мастера установки; вход сверяется с admin_user.json)
ADMIN_DEFAULT_PASSWORD = get_str_env_param('ADMIN_DEFAULT_PASSWORD', default='')

# лимит неверных попыток входа с одного IP и длительность блокировки
LOGIN_MAX_FAILED_ATTEMPTS = get_int_env_param('LOGIN_MAX_FAILED_ATTEMPTS', default=5)
LOGIN_LOCKOUT_MINUTES = get_int_env_param('LOGIN_LOCKOUT_MINUTES', default=60)

_MANAGE_SITE_ROOT = Path(__file__).resolve().parent
ADMIN_USER_JSON_PATH = _MANAGE_SITE_ROOT / 'data' / 'admin_user.json'
LOGIN_ATTEMPTS_JSON_PATH = _MANAGE_SITE_ROOT / 'data' / 'login_attempts.json'
VPN_CLIENTS_JSON_PATH = _MANAGE_SITE_ROOT / 'data' / 'vpn_clients.json'

# путь к конфигу WireGuard на сервере (например /etc/wireguard/wg0.conf). Пусто — интеграция с WG отключена
WIREGUARD_CONF_PATH = (get_str_env_param('WIREGUARD_CONF_PATH', default='') or '').strip()

# период фоновой синхронизации JSON с wg0.conf (минуты); 0 — только при старте и при запросах к панели
WIREGUARD_SYNC_INTERVAL_MINUTES = get_int_env_param('WIREGUARD_SYNC_INTERVAL_MINUTES', default=5)

# имя интерфейса для wg-quick / wg syncconf (должен совпадать с именем файла в /etc/wireguard/)
WIREGUARD_INTERFACE_NAME = (
    (get_str_env_param('WIREGUARD_INTERFACE_NAME', default='wg0') or '').strip() or 'wg0'
)

# Полный Endpoint для клиентских .conf (host:port). Альтернатива — WIREGUARD_PUBLIC_HOST + порт из ListenPort / WIREGUARD_LISTEN_PORT
WIREGUARD_ENDPOINT = (get_str_env_param('WIREGUARD_ENDPOINT', default='') or '').strip()

# Публичный FQDN или IP для строки Endpoint, если не задан WIREGUARD_ENDPOINT (порт см. WIREGUARD_LISTEN_PORT и README)
WIREGUARD_PUBLIC_HOST = (get_str_env_param('WIREGUARD_PUBLIC_HOST', default='') or '').strip()

# Порт UDP в Endpoint для клиентов; 0 — взять ListenPort из wg0.conf, и нет — 51820
WIREGUARD_LISTEN_PORT = get_int_env_param('WIREGUARD_LISTEN_PORT', default=0)

WIREGUARD_DNS = (get_str_env_param('WIREGUARD_DNS', default='8.8.8.8') or '').strip() or '8.8.8.8'

# каталог клиентских .conf и qr; пусто — рядом с каталогом ключей: <parent>/client_config
WIREGUARD_CLIENT_CONFIG_DIR = (
    (get_str_env_param('WIREGUARD_CLIENT_CONFIG_DIR', default='') or '').strip()
)

# каталог для файлов ключей клиентов WireGuard (создаётся при необходимости)
WIREGUARD_CLIENT_KEYS_DIR = get_file_env_param(
    'WIREGUARD_CLIENT_KEYS_DIR',
    file_mast_exist=False,
    dir_mast_exist=False,
    default=str(_MANAGE_SITE_ROOT / 'data' / 'vpn_client_keys'),
)

# файл со ссылкой MTProxy (первая непустая строка). Пусто — секция MTProxy в панели скрыта
MTPROXY_LINK_FILE = (get_str_env_param('MTPROXY_LINK_FILE', default='') or '').strip()


def wireguard_enabled() -> bool:
    return bool(WIREGUARD_CONF_PATH)


def mtproxy_enabled() -> bool:
    return bool(MTPROXY_LINK_FILE)
