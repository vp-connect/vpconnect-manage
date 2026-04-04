# vpconnect-manage

Веб-панель администратора для **SelfVPN / vpconnect**: вход одного администратора, при необходимости — управление клиентами **WireGuard** (синхронизация с `wg0.conf`), блок **Telegram MTProxy** (ссылка и QR). Конфигурация читается из **`settings.env`** в корне репозитория.

## Возможности

- **Авторизация** — пароль сверяется с MD5 в `manage_site/data/admin_user.json`; лимит попыток и блокировка по IP настраиваются в `settings.env`.
- **Первый запуск** — если задан `ADMIN_DEFAULT_PASSWORD` и нет `admin_user.json`, приложение создаст файл с хэшем этого пароля.
- **WireGuard** — включается только при **непустом** `WIREGUARD_CONF_PATH`: дашборд клиентов, создание/вкл/выкл/удаление с правкой `wg0.conf`, фоновая или запросная синхронизация с JSON, выдача `.conf` и QR.
- **MTProxy** — секция в UI только если **задан** путь `MTPROXY_LINK_FILE` (пустое значение = функция отключена).

## Зачем отдельные поля для Endpoint WireGuard

В **серверном** `wg0.conf` обычно нет строки, которую можно однозначно взять как «куда с телефона стучаться из интернета»: там адреса туннеля и ключи, а **`Endpoint` в клиентском конфиге** — это публичный **хост:порт**, видимый клиенту снаружи. Поэтому панель должна получить эту информацию из настроек:

- либо целиком **`WIREGUARD_ENDPOINT`** (например `vpn.example.com:51820`);
- либо **`WIREGUARD_PUBLIC_HOST`** + порт: сначала **`WIREGUARD_LISTEN_PORT`**, если задан ненулевой; иначе **`ListenPort`** из секции `[Interface]` в `wg0.conf`; если и его нет — **51820**.

Так **`WIREGUARD_ENDPOINT` не обязателен**, если задан публичный хост и порт можно вывести из конфига.

## Требования

- **Python** 3.10+
- Зависимости из `requirements.txt` (`flask`, `env-settings`, `qrcode[pil]`).
- На сервере с WireGuard: утилиты **`wg`**, при автоприменении конфига — **`bash`** и совпадение пути к конфигу с ожиданиями `wg-quick` (см. комментарии в коде `wireguard_conf.try_run_wg_syncconf`).

## Установка

1. Клонируйте репозиторий, перейдите в корень проекта.

2. Создайте виртуальное окружение и установите зависимости:

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

3. Создайте или скопируйте **`settings.env`** в корне и заполните переменные (см. следующий раздел и комментарии в самом файле).

4. Имя файла с переменными можно переопределить через **`ENV_FILENAME`** в окружении процесса (по умолчанию в проекте ожидается `settings.env`).

5. Файл **`manage_site/data/admin_user.json`** с полем `password_md5` (32 hex) нужен для входа, если не сработало автосоздание из `ADMIN_DEFAULT_PASSWORD`.

## Переменные `settings.env`

Имена и типы объявлены в **`manage_site/settings.py`**. Смысл:

| Переменная | Смысл |
|------------|--------|
| `ENV_FILENAME` | Имя файла с переменными (часто задаётся в окружении ОС, не в `settings.env`). По умолчанию используется `settings.env`. |
| `FLASK_SECRET_KEY` | Секрет подписи сессий Flask; в продакшене — длинная случайная строка. |
| `ADMIN_DEFAULT_PASSWORD` | Пароль для автосоздания `admin_user.json` при первом запуске и для сброса пароля из UI; пусто — автосоздание и сброс по умолчанию недоступны. |
| `LOGIN_MAX_FAILED_ATTEMPTS` | Число неверных попыток входа с одного IP до блокировки (по умолчанию 5). |
| `LOGIN_LOCKOUT_MINUTES` | Длительность блокировки IP в минутах (по умолчанию 60). |
| `WIREGUARD_CONF_PATH` | Путь к `wg0.conf`. **Пусто** — интеграция WireGuard выключена: секция клиентов скрыта, маршруты `/clients/*` не обрабатываются. |
| `WIREGUARD_SYNC_INTERVAL_MINUTES` | Период фоновой синхронизации JSON с `wg0.conf` в минутах. **0** — только при старте приложения и при открытии главной страницы. |
| `WIREGUARD_INTERFACE_NAME` | Имя интерфейса для `wg-quick strip` / `wg syncconf` (по умолчанию `wg0`). |
| `WIREGUARD_ENDPOINT` | Полный `Endpoint` для клиентских конфигов: `хост:порт`. Достаточно **либо** его, **либо** связки ниже. |
| `WIREGUARD_PUBLIC_HOST` | Публичный FQDN или IP для клиентского `Endpoint`, если `WIREGUARD_ENDPOINT` пуст. |
| `WIREGUARD_LISTEN_PORT` | Порт UDP в `Endpoint`, когда не задан полный `WIREGUARD_ENDPOINT`: **0** — взять `ListenPort` из `wg0.conf`, иначе при отсутствии в файле используется **51820**. Ненулевое значение переопределяет порт явно. |
| `WIREGUARD_DNS` | DNS в клиентском `[Interface]` (по умолчанию `8.8.8.8`). |
| `WIREGUARD_CLIENT_CONFIG_DIR` | Каталог для клиентских `.conf`. **Пусто** — `<родитель WIREGUARD_CLIENT_KEYS_DIR>/client_config`. |
| `WIREGUARD_CLIENT_KEYS_DIR` | Каталог файлов ключей клиентов WireGuard. **Пусто** — путь по умолчанию под `manage_site/data/vpn_client_keys`. Относительные пути считаются от **текущей рабочей директории** процесса. |
| `MTPROXY_LINK_FILE` | Путь к текстовому файлу со ссылкой MTProxy (первая непустая строка). **Пусто** — секция MTProxy в UI скрыта, маршрут QR не используется. |

\*Для **создания новых клиентов** WireGuard нужны `WIREGUARD_CONF_PATH` и способ задать Endpoint: **`WIREGUARD_ENDPOINT`** или **`WIREGUARD_PUBLIC_HOST`** (с портом по правилам выше).

Дублирование с переменными **`VPCONFIGURE_*`** на установленном сервере: часто `WIREGUARD_PUBLIC_HOST` совпадает с `VPCONFIGURE_DOMAIN`, путь к `mtproxy.link` — с `VPCONFIGURE_MTPROXY_LINK_PATH`; в `settings.env` панели нужно указать те же пути/смыслы явно (или через симлинк).

## Документирование `settings.env`

- В репозитории лежит образец **`settings.env`** с **пошаговыми комментариями** к каждой группе переменных.
- Не коммитьте в открытый репозиторий продакшен-значения секретов и внутренних путей; для команды достаточно шаблона и описания в README.

## Запуск

Запускайте из **корня репозитория**, чтобы находились `settings.env` и относительные пути.

**Встроенный сервер разработки**

Windows:

```shell
venv\Scripts\python -m flask --app manage_site.selfvpn_app:selfvpn_app run --debug
```

Linux / macOS:

```shell
venv/bin/python -m flask --app manage_site.selfvpn_app:selfvpn_app run --debug
```

По умолчанию: `http://127.0.0.1:5000/`. Для доступа из сети: `--host=0.0.0.0`.

**Запуск модуля**

```shell
venv/bin/python -m manage_site.selfvpn_app
```

**Продакшен** — WSGI-сервер (gunicorn, uwsgi и т.д.) с целевым объектом **`manage_site.selfvpn_app:selfvpn_app`**.

## Данные на диске

| Путь | Назначение |
|------|------------|
| `manage_site/data/admin_user.json` | MD5 пароля администратора. |
| `manage_site/data/vpn_clients.json` | Список клиентов (поле `wg_name` и др. при включённом WireGuard). |
| `manage_site/data/login_attempts.json` | Попытки входа и блокировки по IP. |
| Каталог ключей (`WIREGUARD_CLIENT_KEYS_DIR`) | Приватные/публичные ключи клиентов. |
| `WIREGUARD_CLIENT_CONFIG_DIR` | Клиентские `.conf` (и при необходимости `qr/`). |
| Файл по `MTPROXY_LINK_FILE` | Текст ссылки MTProxy. |

Эти пути не должны отдаваться как статика веб-сервера.

## Разработка и качество

```shell
venv/bin/python -m pip install -r requirements-test.txt
venv/bin/python -m flake8 manage_site
```

---

Пакет приложения: **`manage_site`**, экземпляр Flask: **`selfvpn_app`**.
