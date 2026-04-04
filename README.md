# vpconnect-manage

Веб-панель администратора для **SelfVPN / vpconnect**: один администратор, опционально **WireGuard** (синхронизация с `wg0.conf`), опционально **Telegram MTProxy** (ссылка и QR). Конфигурация — **`settings.env`** в корне репозитория.

Лицензия: [MIT](LICENSE).

## Возможности

- **Авторизация** — MD5 пароля в `manage_site/data/admin_user.json`, лимит попыток и блокировка по IP (`settings.env`).
- **Первый запуск** — при заданном `ADMIN_DEFAULT_PASSWORD` и отсутствии `admin_user.json` создаётся файл с хэшем.
- **WireGuard** — при непустом `WIREGUARD_CONF_PATH`: дашборд, CRUD с правкой `wg0.conf`, синхронизация JSON, выдача `.conf` и QR.
- **MTProxy** — при непустом `MTPROXY_LINK_FILE`: блок в UI и QR.

## Почему отдельно Endpoint и публичный хост

Серверный `wg0.conf` не содержит «внешний» адрес для клиентов из интернета. Строка **`Endpoint`** в клиентском конфиге — это **публичный host:port**. Задаётся либо **`WIREGUARD_ENDPOINT`**, либо **`WIREGUARD_PUBLIC_HOST`** плюс порт из **`WIREGUARD_LISTEN_PORT`**, из **`ListenPort`** в конфиге или **51820**.

## Структура проекта

| Путь | Назначение |
|------|------------|
| `manage_site/selfvpn_app.py` | Экземпляр Flask `selfvpn_app`, маршруты |
| `manage_site/settings.py` | Загрузка env и константы |
| `manage_site/vpn_clients_service.py` | JSON клиентов и операции с WG |
| `manage_site/wireguard_conf.py` | Парсинг и запись `wg0.conf` |
| `manage_site/wg_local_runtime.py` | Ключи, Endpoint, `wg syncconf` |
| `manage_site/wg_background_sync.py` | Фоновая синхронизация JSON |
| `manage_site/templates/`, `manage_site/static/` | UI |
| `manage_site/data/` | JSON и примеры данных (не статика) |
| `settings.env` | Значения переменных окружения |
| `pyproject.toml` | Настройки **Black** (длина строки 100) |
| `.flake8` | Правила **Flake8** |

## Требования

- Python **3.10+**
- Зависимости: `requirements.txt`
- На сервере с WG: **`wg`**; для авто-применения конфига — **`bash`** и путь к `wg0.conf`, совместимый с `wg-quick` (см. `wireguard_conf.try_run_wg_syncconf`)

## Установка

1. Клонировать репозиторий, перейти в корень.

2. Виртуальное окружение и зависимости:

   **Windows**

   ```shell
   python -m venv venv
   venv\Scripts\python -m pip install -U pip
   venv\Scripts\python -m pip install -r requirements.txt
   ```

   **Linux / macOS**

   ```shell
   python3 -m venv venv
   venv/bin/python -m pip install -U pip
   venv/bin/python -m pip install -r requirements.txt
   ```

3. Настроить **`settings.env`** (шаблон и комментарии в файле).

4. При необходимости задать **`ENV_FILENAME`** в окружении процесса (иначе используется `settings.env`).

5. Для входа нужен **`manage_site/data/admin_user.json`** с `password_md5`, если не сработало автосоздание из `ADMIN_DEFAULT_PASSWORD`.

## Переменные `settings.env`

Объявления и типы — в **`manage_site/settings.py`**.

| Переменная | Смысл |
|------------|--------|
| `ENV_FILENAME` | Имя файла с переменными (часто из окружения ОС). |
| `FLASK_SECRET_KEY` | Секрет сессий Flask (**обязательно** менять в продакшене). |
| `ADMIN_DEFAULT_PASSWORD` | Автосоздание `admin_user.json` и сброс пароля из UI. |
| `LOGIN_MAX_FAILED_ATTEMPTS` | Порог неудачных попыток входа с IP. |
| `LOGIN_LOCKOUT_MINUTES` | Длительность блокировки IP (минуты). |
| `WIREGUARD_CONF_PATH` | Путь к `wg0.conf`; **пусто** — WG в UI отключён. |
| `WIREGUARD_SYNC_INTERVAL_MINUTES` | Интервал фоновой синхронизации JSON; **0** — только старт и открытие дашборда. |
| `WIREGUARD_INTERFACE_NAME` | Имя интерфейса для `wg-quick` / `wg syncconf`. |
| `WIREGUARD_ENDPOINT` | Полный `host:port` для клиентских конфигов. |
| `WIREGUARD_PUBLIC_HOST` | FQDN/IP, если `WIREGUARD_ENDPOINT` пуст. |
| `WIREGUARD_LISTEN_PORT` | Порт для Endpoint; **0** — из `ListenPort` в конфиге или 51820. |
| `WIREGUARD_DNS` | DNS в клиентском `[Interface]`. |
| `WIREGUARD_CLIENT_CONFIG_DIR` | Каталог клиентских `.conf`; пусто — рядом с ключами. |
| `WIREGUARD_CLIENT_KEYS_DIR` | Каталог ключей клиентов; пусто — `manage_site/data/vpn_client_keys` (относительно **cwd**). |
| `MTPROXY_LINK_FILE` | Файл со ссылкой MTProxy; **пусто** — блок MTProxy скрыт. |

Для **создания** клиентов WG нужны `WIREGUARD_CONF_PATH` и задание Endpoint (`WIREGUARD_ENDPOINT` или `WIREGUARD_PUBLIC_HOST` + порт по правилам выше).

На серверах с **VPCONFIGURE_*** часто совмещают: `WIREGUARD_PUBLIC_HOST` ≈ `VPCONFIGURE_DOMAIN`, `MTPROXY_LINK_FILE` ≈ путь из `VPCONFIGURE_MTPROXY_LINK_PATH`.

## Запуск

Из **корня** репозитория.

```shell
venv/bin/python -m flask --app manage_site.selfvpn_app:selfvpn_app run --debug
```

Сеть: добавьте `--host=0.0.0.0`.

```shell
venv/bin/python -m manage_site.selfvpn_app
```

**Продакшен:** WSGI (gunicorn и т.д.) → **`manage_site.selfvpn_app:selfvpn_app`**.

## Данные на диске

| Путь | Назначение |
|------|------------|
| `manage_site/data/admin_user.json` | Пароль администратора (MD5). |
| `manage_site/data/vpn_clients.json` | Клиенты (`wg_name`, …). |
| `manage_site/data/login_attempts.json` | Блокировки входа (часто в `.gitignore`). |
| `WIREGUARD_CLIENT_KEYS_DIR` | Ключи. |
| `WIREGUARD_CLIENT_CONFIG_DIR` | `.conf`, при необходимости `qr/`. |
| Файл по `MTPROXY_LINK_FILE` | Ссылка MTProxy. |

Не отдавать эти пути как публичную статику.

## Разработка и проверка кода

```shell
venv/bin/python -m pip install -r requirements-test.txt
venv/bin/python -m black -l 100 manage_site
venv/bin/python -m flake8 manage_site
```

## Перед публикацией репозитория

- Убедиться, что в индекс не попали секреты (`settings.env` с прод-значениями, ключи, личные пути).
- Каталог **`.history/`** (резервы редактора) в **`.gitignore`**; локальные копии можно удалить.
- Каталоги **`.idea/`**, **`.run/`**, **`.cursor/`** обычно не нужны в публичном клоне — при необходимости добавьте в `.gitignore` или не коммитьте (часть уже игнорируется).
- Проверить `flake8` и при необходимости `black` по командам выше.

---

WSGI: **`manage_site.selfvpn_app:selfvpn_app`**.
