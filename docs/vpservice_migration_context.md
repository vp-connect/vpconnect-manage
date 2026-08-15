# VPService Migration Context (`vpconnect-manage`)

## Цель

- Убрать жесткую привязку панели к WireGuard-only сценарию.
- Поддержать выбор активного VPN-сервиса: `wireguard` или `amneziawg`.
- Сохранить обратную совместимость текущих `WIREGUARD_*` путей и настроек.

## Реализовано в этом репозитории

### 1) Определение активного сервиса (env + fallback-автодетект)

- Добавлен модуль `manage_site/vpservice.py`:
  - `configured_vpservice_type()` — читает явный выбор из `VP_SERVICE_TYPE`.
  - `detect_vpservice_type_from_conf()` — fallback по preamble конфига (`Jc/Jmin/Jmax/S1/S2/H1..H4` => `amneziawg`).
  - `active_vpservice_type()` — итоговый выбор.
  - `vpservice_display_name()` — UI-имя: `Wireguard` / `Amnezia WG`.
- В `manage_site/settings.py` добавлены новые env-параметры:
  - `VP_SERVICE_TYPE` (`wireguard|amneziawg`, пусто = автодетект),
  - `VP_SERVICE_BINARY`,
  - `VP_SERVICE_QUICK_BINARY`.

### 2) Бэкенд-операции клиентов под текущий сервис

- `manage_site/vpn_clients_service.py`:
  - проверки включенности переведены на `settings.vpservice_enabled()`;
  - все операции работают через существующий общий peer/config-пайплайн:
    - синхронизация (`sync_clients_json_with_runtime_state`),
    - создание (`create_client`),
    - включение/выключение (`set_client_enabled`),
    - удаление (`delete_client`),
    - загрузка/чтение конфигов (`client_config_text/bytes`),
    - QR (`qr_png_bytes`).
- `manage_site/wg_local_runtime.py`:
  - runtime-команды (`show/genkey/pubkey/syncconf`) используют бинарники по активному сервису:
    - wireguard: `wg`, `wg-quick`,
    - amneziawg: `awg`, `awg-quick`,
    - приоритет у явных override `VP_SERVICE_BINARY` / `VP_SERVICE_QUICK_BINARY`.
- `manage_site/wireguard_conf.py`:
  - `try_run_wg_syncconf(...)` параметризован бинарниками, чтобы применять конфиг под выбранный сервис.
  - добавлены стандартные пути для `awg-quick` (`/etc/amnezia/amneziawg` и `/etc/amnezia/wireguard`) при safe-проверке перед `syncconf`.

### 3) UI-отображение типа сервиса

- `manage_site/selfvpn_app.py`:
  - в `home()` добавлен контекст `vpn_service_display_name`.
- `manage_site/templates/clients.html`:
  - заголовок секции клиентов: `Клиенты ({{ vpn_service_display_name }})`,
  - заголовок страницы также дополняется типом при включенной секции.

### 4) Сопутствующие изменения

- `manage_site/wg_background_sync.py`:
  - gating синхронизации переведен на `settings.vpservice_enabled()`.
- `settings.env`:
  - добавлены комментарии и ключи для `VP_SERVICE_TYPE` и бинарников.
- `README.md`:
  - обновлено описание на уровень `VPN service` вместо WireGuard-only.

## Матрица операций (что и как адаптировано)

| Операция | Было | Стало |
| --- | --- | --- |
| Проверка включенности | `wireguard_enabled()` | `vpservice_enabled()` (алиас WG сохранен) |
| Определение типа | не было | `VP_SERVICE_TYPE` + автодетект по конфигу |
| syncconf | `wg syncconf` + `wg-quick strip` | параметризованные бинарники `wg/awg` + `wg-quick/awg-quick` |
| keygen/pubkey/show | только `wg` | `wg` или `awg` по активному сервису |
| CRUD пиров в конфиге | WG parser/writer | сохранен parser/writer, используется для обоих типов при совместимом формате |
| download/QR | WG-config flow | тот же flow, но в контексте активного сервиса |
| UI заголовок | `Клиенты` | `Клиенты (Wireguard\|Amnezia WG)` |

## Тесты, обновленные в рамках миграции

- Добавлен `tests/test_vpservice.py`.
- Обновлен `tests/test_settings_api.py` (проверка `vpservice_enabled`).
- Обновлен `tests/test_selfvpn_app.py` (рендер заголовка с типом сервиса).

## Требуемые изменения в shell-скриптах смежных репозиториев

### `vpconnect-configure` (обязательно)

- Ввести/использовать `06_setvpservice.sh` вместо `06_setwireguard.sh`.
- Поддержать аргумент выбора сервиса `wireguard|amneziawg`.
- Унифицировать env-контракт с `wg*` на `vp*` / `vpserver*`, включая:
  - порты,
  - пути cert/config,
  - путь к публичному/приватному ключу,
  - service-specific артефакты.
- Обновить потребители:
  - `07_setmtproxy.sh`,
  - `08_setvpmanage.sh`,
  - `10_uninstall.sh`.
- Привести default пути к:
  - `/usr/vpserver/client_cert`,
  - `/usr/vpserver/client_config`.

### `vpconnect-install` (обязательно)

- Обновить модель `ProvisionConfig` и CLI/GUI:
  - флаг установки VP service (вместо `set_wireguard`),
  - явный выбор `wireguard|amneziawg`.
- Обновить оркестрацию шага 06:
  - вызов `06_setvpservice.sh`,
  - прокидка новых `vp*` параметров.
- Обновить тексты, defaults, outputs и precheck на `vp/vpserver` термины.

## Текущее ограничение в `vpconnect-manage`

- Внутренние имена переменных и некоторые модули по-прежнему имеют исторический префикс `WIREGUARD_`/`wg_` для обратной совместимости.
- Для полного нейтрального контракта потребуется отдельный этап переименований API/переменных (с миграцией тестов и env).
