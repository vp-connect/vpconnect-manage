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

from env_settings import get_file_env_param, get_str_env_param, get_float_env_param, get_bool_env_param
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

# каталог для файлов ключей клиентов VPN (создаётся при необходимости)
VPN_CLIENT_KEYS_BASE_DIR = get_file_env_param(
    'VPN_CLIENT_KEYS_BASE_DIR',
    file_mast_exist=False,
    dir_mast_exist=False,
    default=str(_MANAGE_SITE_ROOT / 'data' / 'vpn_client_keys'),
)

# файл с текстовой ссылкой на MTProxy / t.me/proxy (первая непустая строка)
MTPROXY_LINK_FILE = get_file_env_param(
    'MTPROXY_LINK_FILE',
    file_mast_exist=False,
    dir_mast_exist=False,
    default=str(_MANAGE_SITE_ROOT / 'data' / 'mtproxy_link.txt'),
)
