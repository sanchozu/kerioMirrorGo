# kerio-mirror-go

`kerio-mirror-go` - це застосунок на Go для локального дзеркала файлів оновлень Kerio Control: IDS, GeoIP, WebFilter, Bitdefender, Shield Matrix, Snort template та власних URL.

Застосунок завантажує дані за розкладом, зберігає їх локально, веде стан у SQLite і віддає файли через HTTP. Він підходить як для класичного запуску на сервері, так і для PaaS/managed hosting середовищ, де платформа сама видає адресу й порт для процесу.

## Можливості

- Автоматичні оновлення за розкладом.
- SQLite без CGO через pure-Go реалізацію.
- Один конфігурований HTTP listener.
- Підтримка Linux, Windows і macOS.
- Web Dashboard для перегляду стану й налаштувань.
- IDS 1-5 з вибірковим увімкненням.
- GeoIP IPv4/IPv6.
- Bitdefender у режимах mirror/proxy з кешуванням.
- WebFilter із керуванням ліцензійним ключем.
- Shield Matrix для Kerio Control 9.5+.
- Snort template для Kerio Control 9.5+.
- Власні URL для завантаження.
- IP whitelist/blacklist з CIDR.
- Outbound proxy: HTTP, HTTPS, SOCKS5.
- Telegram-сповіщення про старт, помилки й успішне завершення оновлення.

## Встановлення

### Готові бінарні файли

Завантажте потрібний файл зі сторінки Releases:

- `kerio-mirror-go-linux-amd64` - Linux x64
- `kerio-mirror-go-windows-amd64.exe` - Windows x64
- `kerio-mirror-go-darwin-amd64` - macOS x64

### Збірка з коду

Потрібен Go 1.24.x або новіший.

```bash
git clone https://github.com/sanchozu/kerioMirrorGo.git
cd kerioMirrorGo
go build -o kerio-mirror-go ./cmd/server
```

Проєкт використовує `modernc.org/sqlite`, тому GCC/CGO не потрібні.

## Запуск

```bash
./kerio-mirror-go -config config.yaml
```

Якщо `-config` не вказано, використовується `config.yaml`.

### Адреса HTTP-сервера

HTTP-сервер слухає одну адресу, яка формується з environment variables:

| Змінна | Призначення | Fallback |
|--------|-------------|----------|
| `HOST` | Host/IP для bind address. Має пріоритет над `IP`. | - |
| `IP` | Host/IP, якщо `HOST` порожній. | - |
| `PORT` | Порт HTTP listener. | `8080` |

Якщо `HOST` і `IP` порожні, застосунок слухає `0.0.0.0`. Повний fallback:

```text
0.0.0.0:8080
```

Приклади:

```bash
# Локальний запуск на дефолтному порту
./kerio-mirror-go -config config.yaml

# Явний порт
PORT=8080 ./kerio-mirror-go -config config.yaml

# Явна адреса й порт
HOST=127.0.0.1 PORT=9090 ./kerio-mirror-go -config config.yaml

# Якщо платформа видає IP замість HOST
IP=:: PORT=8300 ./kerio-mirror-go -config config.yaml
```

Застосунок більше не стартує окремі listener-и на `:80` і `:443` за замовчуванням та не вимагає `cert.pem`/`key.pem` для базового запуску. Якщо потрібен HTTPS, завершіть TLS на reverse proxy, load balancer або засобами хостинг-платформи, а до `kerio-mirror-go` проксируйте HTTP на адресу з `HOST`/`IP`/`PORT`.

## Конфігурація

Основні налаштування читаються з `config.yaml`. Частину параметрів можна змінювати через web interface на `/settings`.

| Параметр | Опис | Типове значення |
|----------|------|-----------------|
| `SCHEDULE_TIME` | Час щоденного оновлення у форматі `HH:MM` | `03:00` |
| `LICENSE_NUMBER` | Номер ліцензії Kerio Control для IDS/WebFilter | обов'язково |
| `DATABASE_PATH` | Шлях до SQLite бази | `./mirror.db` |
| `LOG_PATH` | Шлях до лог-файлу | `./logs/mirror.log` |
| `LOG_LEVEL` | Рівень логування | `info` |
| `PROXY_URL` | Outbound proxy для HTTP-запитів | порожньо |
| `ENABLE_IDS1` - `ENABLE_IDS5` | Увімкнення версій IDS | `true` |
| `BITDEFENDER_MODE` | `disabled`, `mirror` або `proxy` | `disabled` |
| `BITDEFENDER_PROXY_BASE_URL` | Upstream для proxy mode | `https://upgrade.bitdefender.com` |
| `ENABLE_SHIELD_MATRIX` | Shield Matrix для Kerio 9.5+ | `true` |
| `SHIELD_MATRIX_BASE_URL` | Endpoint перевірки Shield Matrix | `https://shieldmatrix-updates.gfikeriocontrol.com/check_update/` |
| `SHIELD_MATRIX_CLIENT_ID` | Client ID для Shield Matrix | `control` |
| `SHIELD_MATRIX_VERSION` | Версія Kerio Control | `9.5.0` |
| `SHIELD_MATRIX_PRELOAD_FILES` | Попередньо завантажувати всі Shield Matrix файли | `false` |
| `ENABLE_SNORT_TEMPLATE` | Оновлення Snort template | `true` |
| `SNORT_TEMPLATE_URL` | URL Snort template | `http://download.kerio.com/control-update/config/v1/snort.tpl` |
| `CUSTOM_DOWNLOAD_URLS` | Додаткові URL для дзеркала | `[]` |
| `ALLOWED_IPS` | Whitelist IP/CIDR | `[]` |
| `BLOCKED_IPS` | Blacklist IP/CIDR | `[]` |
| `RETRY_COUNT` | Кількість повторів завантаження | `3` |
| `RETRY_DELAY_SECONDS` | Затримка між повторами | `10` |
| `TELEGRAM_BOT_TOKEN` | Токен Telegram Bot API | порожньо |
| `TELEGRAM_CHAT_ID` | Chat/channel ID | порожньо |
| `TELEGRAM_NOTIFY_ON_ERROR` | Сповіщення про помилки | `true` |
| `TELEGRAM_NOTIFY_ON_SUCCESS` | Сповіщення про успішне завершення | `false` |
| `TELEGRAM_NOTIFY_ON_START` | Сповіщення про старт оновлення | `false` |

### Приклад `config.yaml`

```yaml
SCHEDULE_TIME: "03:00"
LICENSE_NUMBER: "your-license-here"
DATABASE_PATH: ./mirror.db
LOG_PATH: ./logs/mirror.log
LOG_LEVEL: info
PROXY_URL: ""

ENABLE_IDS1: true
ENABLE_IDS2: true
ENABLE_IDS3: true
ENABLE_IDS4: true
ENABLE_IDS5: true
IDS_URL: https://update.kerio.com/dwn/control/update.php?license=%s&version=%s

BITDEFENDER_MODE: "disabled"
BITDEFENDER_PROXY_BASE_URL: https://upgrade.bitdefender.com
BITDEFENDER_URLS: []

ENABLE_SHIELD_MATRIX: true
SHIELD_MATRIX_BASE_URL: https://shieldmatrix-updates.gfikeriocontrol.com/check_update/
SHIELD_MATRIX_CLIENT_ID: control
SHIELD_MATRIX_VERSION: 9.5.0
SHIELD_MATRIX_PRELOAD_FILES: false

ENABLE_SNORT_TEMPLATE: true
SNORT_TEMPLATE_URL: http://download.kerio.com/control-update/config/v1/snort.tpl

GEOIP4_URL: https://raw.githubusercontent.com/wyot1/GeoLite2-Unwalled/downloads/COUNTRY/CSV/GeoLite2-Country-Blocks-IPv4.csv
GEOIP6_URL: https://raw.githubusercontent.com/wyot1/GeoLite2-Unwalled/downloads/COUNTRY/CSV/GeoLite2-Country-Blocks-IPv6.csv
GEOLOC_URL: https://raw.githubusercontent.com/wyot1/GeoLite2-Unwalled/downloads/COUNTRY/CSV/GeoLite2-Country-Locations-en.csv

WEBFILTER_API: https://updates.kerio.com/webfilter/key

CUSTOM_DOWNLOAD_URLS:
  - http://download.kerio.com/control-update/config/v1/snort.tpl
  - http://download.kerio.com/control-update/config/v1/snort.tpl.md5

ALLOWED_IPS: []
BLOCKED_IPS: []

TELEGRAM_BOT_TOKEN: ""
TELEGRAM_CHAT_ID: ""
TELEGRAM_NOTIFY_ON_ERROR: true
TELEGRAM_NOTIFY_ON_SUCCESS: false
TELEGRAM_NOTIFY_ON_START: false

RETRY_COUNT: 3
RETRY_DELAY_SECONDS: 10
```

## DNS і reverse proxy

Щоб Kerio Control отримував оновлення з дзеркала, DNS має спрямовувати потрібні домени на сервер або reverse proxy перед `kerio-mirror-go`.

Обов'язкові домени:

- `ids-update.kerio.com`
- `update.kerio.com`
- `updates.kerio.com`
- `download.kerio.com`

Для Bitdefender:

- `bdupdate.kerio.com`
- `bda-update.kerio.com`

Для Shield Matrix:

- `shieldmatrix-updates.gfikeriocontrol.com`
- `d2akeya8d016xi.cloudfront.net`

Приклад DNS:

```dns
ids-update.kerio.com.        IN A    192.168.1.100
update.kerio.com.            IN A    192.168.1.100
updates.kerio.com.           IN A    192.168.1.100
download.kerio.com.          IN A    192.168.1.100
bdupdate.kerio.com.          IN A    192.168.1.100
bda-update.kerio.com.        IN A    192.168.1.100
shieldmatrix-updates.gfikeriocontrol.com. IN A 192.168.1.100
d2akeya8d016xi.cloudfront.net. IN A 192.168.1.100
```

Якщо застосунок працює за reverse proxy, проксі має передавати запити на внутрішню адресу `HOST`/`IP` + `PORT`, на якій слухає `kerio-mirror-go`.

## Web Dashboard

Після запуску dashboard доступний за адресою, яку ви відкриваєте через HTTP або через зовнішній HTTPS reverse proxy.

Основні маршрути:

- `/` - dashboard зі статусом оновлень і версіями.
- `/settings` - керування налаштуваннями.
- `/logs` - перегляд логів.
- `/update.php` - endpoint оновлень Kerio Control.
- `/control-update/*` - видача файлів дзеркала.
- `/getkey.php` - endpoint ключа WebFilter.

## Bitdefender

`BITDEFENDER_MODE` підтримує три режими:

| Режим | Опис |
|-------|------|
| `disabled` | Bitdefender вимкнено, файли не завантажуються. |
| `mirror` | Файли завантажуються з налаштованих URL і зберігаються у `mirror/bitdefender/`. |
| `proxy` | Застосунок працює як кешуючий proxy до `BITDEFENDER_PROXY_BASE_URL`. |

У proxy mode кешовані відповіді зберігаються локально, а файли на кшталт `versions.id`, `version.txt`, `cumulative.txt` отримуються свіжими.

## Shield Matrix

Shield Matrix використовується Kerio Control 9.5+.

Алгоритм:

1. Перевірка наявності оновлення через `SHIELD_MATRIX_BASE_URL`.
2. Отримання версії з CloudFront.
3. Завантаження threat data файлів IPv4/IPv6 on-demand або через preload.
4. Кешування файлів у `mirror/matrix/`.

Режими завантаження:

| Режим | Значення `SHIELD_MATRIX_PRELOAD_FILES` | Коли використовувати |
|-------|----------------------------------------|----------------------|
| On-demand | `false` | Звичайний інтернет, мінімальне сховище. |
| Preload | `true` | Повільний або обмежений інтернет, offline-сценарії. |

## IP Access Control

Доступ можна обмежити через `ALLOWED_IPS` і `BLOCKED_IPS`.

```yaml
ALLOWED_IPS:
  - 192.168.1.100
  - 192.168.2.0/24
  - 10.0.0.0/8

BLOCKED_IPS:
  - 203.0.113.50
  - 198.51.100.0/24
```

Логіка:

1. Якщо IP є в `BLOCKED_IPS`, запит блокується.
2. Якщо `ALLOWED_IPS` непорожній і IP не входить у список, запит блокується.
3. Якщо обидва списки порожні, доступ відкритий.

## Proxy для outbound-запитів

Усі зовнішні HTTP-запити можуть проходити через `PROXY_URL`.

| Схема | Приклад |
|-------|---------|
| HTTP | `http://proxy.host:3128` |
| HTTP з авторизацією | `http://user:pass@proxy.host:3128` |
| SOCKS5 | `socks5://proxy.host:1080` |
| SOCKS5 з авторизацією | `socks5://user:pass@proxy.host:1080` |

## Telegram-сповіщення

Для сповіщень потрібні:

1. Bot token від `@BotFather`.
2. Chat ID користувача, групи або каналу.
3. Значення `TELEGRAM_BOT_TOKEN` і `TELEGRAM_CHAT_ID` у конфігурації.

Сповіщення:

| Подія | Ключ | Типове значення |
|-------|------|-----------------|
| Помилки оновлення | `TELEGRAM_NOTIFY_ON_ERROR` | `true` |
| Успішне завершення | `TELEGRAM_NOTIFY_ON_SUCCESS` | `false` |
| Початок оновлення | `TELEGRAM_NOTIFY_ON_START` | `false` |

Telegram-запити також використовують `PROXY_URL`, якщо він налаштований.

## Тестування

```bash
go fmt ./...
go test ./...
go vet ./...
```

Окремо можна запустити:

```bash
make test
make test-coverage
```

## Розробка

Структура проєкту:

```text
kerioMirrorGo/
├── cmd/server/          # Точка входу застосунку
├── config/              # Завантаження конфігурації
├── db/                  # Ініціалізація SQLite і схема
├── handlers/            # HTTP handlers
├── logging/             # Логування
├── middleware/          # Middleware, зокрема IP filter
├── mirror/              # Логіка дзеркала
├── telegram/            # Telegram client
├── utils/               # Допоміжні утиліти
├── templates/           # HTML templates
└── static/              # Статичні файли
```

## Release

Для створення релізів є скрипти:

```bash
./release.sh patch
./release.sh minor
./release.sh major
./release.sh v2.5.0
```

Для Windows:

```batch
release.bat patch
```

Скрипти перевіряють git-стан, підвищують версію або приймають заданий tag і пушать його в remote.

## Підтримка

- Telegram Group: [https://t.me/+j_e5rm0pXLRjZmQy](https://t.me/+j_e5rm0pXLRjZmQy)
- Issues: [https://github.com/sanchozu/kerioMirrorGo/issues](https://github.com/sanchozu/kerioMirrorGo/issues)
