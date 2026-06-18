# MWS IP-Hunter

Перебор публичных IPv4-адресов в облаке MWS (MTS Web Services) с фильтром по
целевой подсети (CIDR) и/или автономной системе (AS), управляемый через
Telegram-бот: резервирует адрес через MWS API, проверяет принадлежность к
цели через локальную ip2asn-базу, освобождает промахи и удерживает
попадания, не превышая квоту аккаунта (по умолчанию 5 IP).

## Быстрый старт

```bash
cp .env.example .env
# заполни TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_CHAT_IDS, MWS_API_TOKEN,
# MWS_PROJECT_ID, MWS_NETWORK_ID, MWS_ZONE_CODE, TARGET_CIDRS/TARGET_ASNS

# (опционально, но рекомендуется) скачать ip2asn-v4.tsv в data/, см. data/README.md
curl -L https://iptoasn.com/data/ip2asn-v4.tsv.gz | gunzip > data/ip2asn-v4.tsv

docker compose up --build
```

Без локальной ip2asn-базы резолв ASN падает на фоллбэк через RIPEstat (сеть,
медленнее, есть троттлинг) — нормально для проверки, но не для боевого
перебора.

## Команды бота

`/start`, `/hunt`, `/stop`, `/status`, `/target [cidr <list>|asn <list>|clear]`,
`/strategy [release_immediately|hold_window]`, `/calibrate [n]`,
`/proxy [host:port:user:pass|test]`, `/list`, `/release <id|all|misses>`,
`/found`, `/limits [<поле> <значение>]`, `/logs [n]`. Доступ только для
chat_id из `TELEGRAM_ALLOWED_CHAT_IDS`.

## Структура

```
app/
├── main.py            # запуск бота + wiring
├── config.py          # .env -> Settings (значения по умолчанию)
├── context.py          # AppContext, общий для всех хендлеров бота
├── mws_client.py       # клиент MWS API (create/get/list/delete IP) -- см. TODO
├── proxy.py             # парсинг host:port:user:pass, SOCKS5 connector
├── asn_resolver.py      # ip2asn локально + fallback RIPEstat
├── hunter.py            # движок перебора, стратегии, стоп-условия
├── matcher.py           # CIDR/ASN matching
├── storage.py           # SQLite (aiosqlite)
├── calibrate.py         # детектор характера выдачи (sequential/clustered/random)
└── bot/
    ├── handlers.py       # команды Telegram
    └── notifications.py  # уведомления (hit/stop/error/progress)
```

## Открытые вопросы / TODO по MWS API

Эндпоинты в `app/mws_client.py` подтверждены по публичной документации
(https://docs.cloud.mts.ru/api/) на момент написания: базовый gateway,
форма тела `POST /ocs/v1/services` для `kind: "ip"`, формат ошибок,
аутентификация через долгоживущий Bearer-токен сервисного аккаунта,
заголовок `Idempotency-Key`. **Не подтверждены явно** (помечены `TODO` в коде):

- точный JSON-путь до присвоенного адреса в ответе create/get;
- параметры фильтрации списка сервисов (`list_ip_services`);
- поведение DELETE (мгновенный возврат IP в пул или с задержкой);
- тело запроса `POST /iam/v2/tokens` для авто-обновления токена (сейчас
  используется статический `MWS_API_TOKEN` из `.env` — это основной
  поддерживаемый режим);
- реальная единица тарификации зарезервированного IP (для оценки бюджета
  используется конфигурируемая константа `ESTIMATED_COST_PER_IP_HOUR`).

Сверь эти места с актуальной OpenAPI-спецификацией перед использованием в
проде и поправь `_extract_ip` / `list_ip_services` в `mws_client.py`, если
реальный формат ответа отличается.
