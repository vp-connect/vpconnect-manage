# vpconnect-manage

Веб-панель администратора для: вход под одним администратором, учёт VPN-клиентов, ссылки и QR для Telegram MTProxy

## Возможности

- **Авторизация** — пароль длявхода; при многократных неверных попытках с одного IP включается временная блокировка (настраивается в `settings.env`).
- **Смена пароля администратора** — через форму после входа.

- **Дашборд клиентов** — создание, включение/отключение, удаление записей; выдача QR-кода и файла `.conf` 
- **Telegram MTProxy** — отображение ссылки

## Требования

- **Python** 3.10+ 
- Зависимости из `requirements.txt`

## Установка

1. Клонируйте репозиторий и перейдите в корень проекта.

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

3. Скопируйте или отредактируйте **`settings.env`** в корне репозитория (см. ниже). Файл должен существовать: путь к нему задаётся переменной `ENV_FILENAME` (по умолчанию `settings.env`).

4. Убедитесь, что есть **`manage_site/data/admin_user.json`** с полем `password_md5` — 32-символьный hex MD5 пароля администратора. В репозитории может лежать пример; для продакшена задайте свой хэш и храните секреты только вне системы контроля версий, если это уместно для вашего деплоя.

## Конфигурация (`settings.env`)

Основные переменные (полный список и типы — в `manage_site/settings.py`):

| Переменная | Назначение |
|------------|------------|
| `FLASK_SECRET_KEY` | Секрет для подписи сессий Flask (**обязательно** сменить в продакшене на длинную случайную строку). |
| `ADMIN_DEFAULT_PASSWORD` | Пароль для сброса через UI (опционально; если пусто — сброс недоступен). |
| `LOGIN_MAX_FAILED_ATTEMPTS` | Число неудачных попыток входа с IP до блокировки. |
| `LOGIN_LOCKOUT_MINUTES` | Длительность блокировки в минутах. |
| `VPN_CLIENT_KEYS_BASE_DIR` | Каталог для файлов ключей клиентов (пусто = значение по умолчанию под `manage_site/data/vpn_client_keys`). Относительные пути считаются от **текущей рабочей директории** процесса. |
| `MTPROXY_LINK_FILE` | Файл со ссылкой MTProxy (первая непустая строка); по умолчанию `manage_site/data/mtproxy_link.txt`. |

При необходимости путь к файлу с переменными можно переопределить через **`ENV_FILENAME`** в окружении до запуска.

## Запуск

Запускайте из **корня репозитория**, чтобы корректно находились `settings.env` и относительные пути.

**Встроенный сервер разработки Flask**

Windows:

```shell
venv\Scripts\python -m flask --app manage_site.selfvpn_app:selfvpn_app run --debug
```

Linux / macOS:

```shell
venv/bin/python -m flask --app manage_site.selfvpn_app:selfvpn_app run --debug
```

По умолчанию интерфейс будет на `http://127.0.0.1:5000/`. Для доступа из сети: добавьте `--host=0.0.0.0` (и настройте firewall / reverse proxy).

**Альтернатива** — прямой вызуск модуля (тот же эффект, что у `if __name__ == '__main__'` в `selfvpn_app.py`):

```shell
venv/bin/python -m manage_site.selfvpn_app
```

Для продакшена используйте **WSGI-сервер** (gunicorn, waitress, uwsgi и т.д.) с объектом приложения `manage_site.selfvpn_app:selfvpn_app`, а не встроенный `run()` Flask.

## Данные на диске

| Путь | Назначение |
|------|------------|
| `manage_site/data/admin_user.json` | MD5 пароля администратора. |
| `manage_site/data/vpn_clients.json` | Список клиентов. |
| `manage_site/data/login_attempts.json` | Учёт попыток входа и блокировок по IP. |
| `manage_site/data/mtproxy_link.txt` | Ссылка на MTProxy (опционально). |
| Каталог ключей (`VPN_CLIENT_KEYS_BASE_DIR`) | Файлы ключей по мере реализации. |

Эти файлы не предназначены для публичной раздачи как статика; веб-сервер должен отдавать только маршруты приложения.

## Разработка и проверка качества

Дополнительно для линтера и тестов:

```shell
venv/bin/python -m pip install -r requirements-test.txt
venv/bin/python -m flake8 manage_site
```

Отдельные автотесты в репозитории могут отсутствовать; набор инструментов в `requirements-test.txt` рассчитан на их появление.

---

Репозиторий: веб-панель управления **vpconnect-manage**. Имена пакета `manage_site` и объекта приложения `selfvpn_app` используются в командах запуска и импортах как есть.
