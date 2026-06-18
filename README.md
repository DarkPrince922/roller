# MWS IP-Hunter

Перебор публичных IPv4-адресов в облаке MWS (MTS Web Services) с фильтром по
целевой подсети (CIDR) и/или автономной системе (AS), управляемый через
Telegram-бот: резервирует адрес через MWS API, проверяет принадлежность к
цели через локальную ip2asn-базу, освобождает промахи и удерживает
попадания, не превышая квоту аккаунта (по умолчанию 5 IP).

## Быстрый старт

```bash
cp .env.example .env
# заполни TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_CHAT_IDS,
# MWS_PROJECT_ID, TARGET_CIDRS/TARGET_ASNS

# создай сервисный аккаунт и авторизованный ключ в консоли MWS (IAM / Сервисные
# аккаунты), скачай JSON ключа и положи его в data/ -- бот сам обменивает его на
# короткоживущие IAM-токены и обновляет их по истечении срока действия
cp ~/Downloads/authorized-key.json data/mws-authorized-key.json
# в .env укажи MWS_SA_KEY_FILE=/data/mws-authorized-key.json (это значение по
# умолчанию в .env.example)

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

`/start` показывает постоянную клавиатуру с кнопками для команд без
аргументов (hunt/stop/status/list/found/calibrate/strategy/target/proxy/
limits). `/strategy` без аргумента и каждый IP в `/list`/`/found` также
показывают inline-кнопки (переключение стратегии, точечное `release`).

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

Эндпоинты в `app/mws_client.py` подтверждены по официальной OpenAPI-спецификации
(https://github.com/mws-cloud-platform/api, сервис `vpc`) и эталонной реализации
в go-sdk (https://github.com/mws-cloud-platform/go-sdk): ресурс публичного IP,
формат тела запроса/ответа, формат ошибок, заголовок `Idempotency-Key`, а также
полный флоу аутентификации через IAM.

Изначальная реализация ходила на `POST {base}/ocs/v1/services` с `kind: "ip"`
на хост `gateway.cloud.mts.ru` — этого ресурса вообще нет ни в одной публичной
OpenAPI-спеке mws-cloud-platform, отсюда и `401 Unauthorized` / `domain: hub`
на `/hunt` и `/calibrate` (ответ от стороннего/легаси-гейтвея, который не
понимает IAM access-токены — это видно по `domain: hub` в теле ошибки,
которого нет в формате `ApiError` ни у одного сервиса mws-cloud-platform).
Авторизация через IAM сама по себе была и остаётся корректной, проблема была
именно в адресе/форме ресурса.

Правильный ресурс — `externalAddress` на хосте `https://vpc.mwsapis.ru`:

- `GET    /vpc/v1/projects/{project}/externalAddresses` — список (с пагинацией
  через `pageToken`/`nextPageToken`);
- `POST   /vpc/v1/projects/{project}/externalAddresses/{name}` — создание/
  обновление ("upsert"); `{name}` выбирается клиентом (паттерн
  `^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`), бот генерирует его сам
  (`ip-hunter-<hex>`), поэтому отдельного "service id" из ответа вычленять не
  нужно — он известен сразу; `?createOnly=true` гарантирует, что запрос не
  обновит чужой ресурс с таким именем по ошибке;
- `GET`/`DELETE /vpc/v1/projects/{project}/externalAddresses/{name}` — чтение/
  удаление по тому же имени;
- присвоенный адрес лежит в `status.ipAddress`, статус реконсиляции — в
  `status.ready.state` (`OK`/`FAILED`/`PROCESSING`);
- ресурс не имеет региона/зоны на уровне API — только `project`; опциональный
  `spec.natGateway` (по умолчанию — `natGateways/internet-gateway`)
  настраивается через `MWS_NAT_GATEWAY`, если нужен отдельный NAT-шлюз.

Аутентификация (IAM, без изменений с прошлого фикса):

- статический Bearer-токен сервисного аккаунта из консоли **нельзя** слать в
  resource-gateway напрямую — его нужно обменять на короткоживущий IAM
  access-токен;
- обмен: подписанный ES256-JWT (`kid` = id авторизованного ключа, `sub` =
  `projects/<project>/serviceAccounts/<sa>`) отправляется в заголовке
  `Authorization` (без префикса `Bearer`, как есть) на
  `GET https://iam.mwsapis.ru/iam/v2/tokens/:issueServiceAccountToken
  ?serviceAccount=<sub>`; ответ — `{"accessToken": "...", "expirationTs":
  "..."}`; `accessToken` затем используется как `Authorization: Bearer
  <accessToken>` для resource-gateway и обновляется заранее до истечения
  `expirationTs`;
- реализовано в `MwsClient._ensure_token` / `_refresh_token_via_iam`, ключ
  читается из файла `MWS_SA_KEY_FILE` (JSON, как скачивается из консоли).

**Не подтверждено явно**:

- реальная единица тарификации зарезервированного IP (для оценки бюджета
  используется конфигурируемая константа `ESTIMATED_COST_PER_IP_HOUR`).
