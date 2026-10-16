# REST-контракты

Префикс `/api/v1`. UUID — идентификаторы сущностей, timestamp — UTC ISO 8601
(для пакетов timestamp_ns — точная десятичная строка либо null), byte offsets — целые >= 0, интервалы `[start,end)`.
Ошибки текущего API: `{"detail": string}`; ошибки входной схемы FastAPI: 422
с массивом описаний. Неверный UUID: 422; отсутствующий ресурс: 404.

## Реализовано на этапах 2–4

OpenAPI: `docs/openapi.json` (снимок) и `/openapi.json` (живой API), Swagger `/docs`.
TypeScript генерируется из этого снимка: `frontend/src/shared/api-types.ts`.

| Метод / путь | Запрос | Ответ |
| --- | --- | --- |
| GET `/health` | — | 200 HealthResponse: status, version, stage=4, persistence=not_configured или postgresql_configured |
| POST `/jobs/diagnostic` | DiagnosticRequest: steps=20 (1–100), delay_ms=100 (0–300) | 202 JobSnapshot, queued |
| GET `/jobs` | — | 200 `{items: JobSnapshot[]}` |
| GET `/jobs/{id}` | — | 200 JobSnapshot; 404 |
| POST `/jobs/{id}/cancel` | — | 200 актуальный JobSnapshot; 404 |
| GET `/jobs/{id}/events` | — | 200 text/event-stream; 404 до начала потока |

JobSnapshot: id, kind=worker_diagnostic/capture_import/tcp_reconstruction, status, completed, total, message,
revision, created_at, updated_at, result (только успешная задача), error.
POST diagnostic возвращает 429 при заполнении реестра. Неизвестные поля запрещены.
SSE: `id: revision`, `event: job`, `data: JSON JobSnapshot`, пустая строка.
Heartbeat каждые ~10 s. Last-Event-ID не воспроизводит историю: при каждом
подключении передаётся полный текущий снимок. Терминальный снимок завершает поток.

## Проекты и импорт — реализовано на этапе 3

Storage routes требуют PostgreSQL и применённой миграции. 503 означает отсутствие
конфигурации/соединения/схемы. 409 — incompatible manifest либо checksum integrity
ошибка. Список использует offset/limit вместо ранее предложенного cursor:
`{items: [...], next_offset: integer|null}`, limit=100 (1–1000), offset=0 (>=0).

| Метод / путь | Вход | Ответ |
| --- | --- | --- |
| POST `/projects` | `{name: string}` (1–200) | 201 Project: UUID id, name, format_version=1, created_at |
| GET `/projects` | offset/limit | ProjectList |
| GET `/projects/{id}` | UUID | Project, manifest identity/version проверяются |
| POST `/projects/{id}/captures` | multipart file + checksum_policy=warn/ignore/reject | 202 JobSnapshot kind=capture_import, total в байтах источника |
| GET `/projects/{id}/captures` | offset/limit | CaptureList |
| GET `/captures/{id}` | UUID | StoredCapture: Capture + packet_count, diagnostics counts, import_settings, engine_version |
| GET `/captures/{id}/packets` | offset/limit | PacketList: IndexedPacket[] |
| POST `/captures/{id}/verify` | UUID | VerifyResult: capture_id, sha256, status=verified; 409 при missing/modified source |

Дополнительное job status `committing`: индекс публикуется транзакцией; cancel
идемпотентно возвращает текущий snapshot и уже не прерывает эту фазу.
Результат import job:

- imported: `{outcome: "imported", capture_id, packet_count, diagnostics}`;
- duplicate: `{outcome: "already_imported", capture_id, checksum_policy, requested_checksum_policy}`.

Duplicate не создаёт новую Capture, не меняет настройки и не сливает исследования.
Malformed magic → 422 до job; malformed container → failed job с error/range,
result=null. Ошибка одного network packet → сохранённый IndexedPacket с diagnostics,
остальные доступны. Upload limit → 413; registry full → 429.

Смещения packet: record_offset от начала оригинала до record/block, file_offset
до link-layer packet, payload_offset относительно file_offset, payload_length
только реально захваченных байтов. Checksum statuses valid/invalid/unchecked/unavailable.
Точные ns передаются строками; SPB timestamp=null; подробнее [storage-and-import](storage-and-import.md).

## Запроектировано для следующих этапов — маршруты пока не доступны

Следующие контракты — проект решений для ревью. Не выдаём успешные ответы
или вымышленные данные на ещё не реализованные операции.

| Метод / путь | Вход | Ответ / поведение |
| --- | --- | --- |
| POST `/projects/open` | `{directory: string}` (локально проверенный путь) | 200 Project; 409 несовместимая версия/контрольная сумма |
| GET `/projects/{id}/models` | limit/cursor | список моделей и latest_version_id |
| POST `/projects/{id}/models` | name, schema_version, document | 201 InterpretationVersion после schema validation |
| POST `/models/{id}/versions` | parent_version_id, schema_version, document | 201 новая неизменяемая версия; 409 устаревший parent; 422 неверная схема |
| GET `/models/{id}/versions/{version_id}` | UUID | InterpretationVersion |
| POST `/projects/{id}/validation-runs` | corpus (capture IDs + filters), interpretation_version_id, reconstruction/framing settings | 202 JobSnapshot; результат ValidationRun ID |
| GET `/validation-runs/{id}` | UUID | ValidationRun, stale, coverage по всей выборке и счётчики пяти статусов |
| GET `/validation-runs/{id}/results` | limit/cursor, status | результаты и контрпримеры со StreamRange/SourceRange |
| POST `/projects/{id}/exports` | versioned export options | 202 JobSnapshot; результат относительного archive artifact |

Чтение bytes ограничено 65536 позициями за запрос, не размером прикладного сообщения.
Долгие операции используют общий жизненный цикл jobs, опубликованные результаты
имеют источник, версии и diagnostics. Наблюдения привязываются к устойчивым
StreamRange/SourceRange, а не только к Message. Поля разобранных фактов и семантические
гипотезы хранятся отдельно. Никакое удаление или перезапись источников не предусмотрены.


## Контракты этапа 4 — реализовано

Реализованы реконструкция как POST `/captures/{id}/reconstruct`, GET
`/captures/{id}/sessions`, `/sessions/{id}`, `/streams/{id}`, диапазонный GET
`/streams/{id}/bytes?offset&length`, GET `/packets/{id}` и POST/GET
`/projects/{id}/observations`. Job kind дополнен `tcp_reconstruction`.
Детальная семантика статусов диапазонов, вариантов и SourceRange:
[tcp-reconstruction](tcp-reconstruction.md). Актуальные JSON-контракты находятся
в OpenAPI и сгенерированных TypeScript-типах.


| Метод / путь | Вход | Ответ |
| --- | --- | --- |
| POST `/captures/{id}/reconstruct` | ReconstructionSettings, можно `{}` | 202 JobSnapshot, kind=tcp_reconstruction |
| GET `/captures/{id}/sessions` | offset/limit | SessionList: metadata, packet_count, streams; 409 до публикации |
| GET `/sessions/{id}` | UUID | SessionView |
| GET `/streams/{id}` | UUID | RebuiltStream metadata; spans пусты, bytes запрашиваются отдельно |
| GET `/streams/{id}/bytes` | offset >=0, length 1..65536 | StreamBytes: blocks с known/ambiguous/gap/truncated, variants + точные sources; 422 вне extent |
| GET `/packets/{id}` | UUID | IndexedPacket |
| POST `/projects/{id}/observations` | text, StreamRange anchors | 201 Observation с проверенными SourceRange |
| GET `/projects/{id}/observations` | offset/limit | ObservationList |

Реконструкция публикуется неизменяемо: result.outcome=reconstructed или
already_reconstructed, capture_id, reconstruction_id, version, session_count,
excluded_packet_count. Gaps/conflicts возвращаются явно внутри JSON; бинарный
ответ со скрытым выбором варианта не применяется. Source mappings включены в
range ответ, отдельного sources endpoint нет. Endpoint/time filters — этап 5.

## Этап 5

Добавлены фильтры project sessions, оригинальные packet bytes, поисковые jobs,
импорт/список журналов, clock revision, временные кандидаты и ручные evidence links.
[Контракты и ограничения](investigation.md), [OpenAPI](openapi.json).

## Этап 6

POST/GET streams/{id}/framing, GET framing-runs/{id}, GET framing-runs/{id}/pieces
реализованы. Input — discriminated versioned FramingSpec; job kind=stream_framing.
Диапазоны неизменяемы и покрывают весь stream, provenance через stable anchors.
[Контракты и правила](framing.md), [OpenAPI](openapi.json).

## Этап 7 — интерпретации

[Модели и endpoints](interpretations.md). JSON Schema опубликована локально в
`docs/interpretation.schema.json` и через `/api/v1/interpretations/schema`. Версии
immutable; разбор — process job с отменой, закреплёнными входами и paginated summary.
Значения целых — десятичные строки, anchors — прежние stream/source ranges.

## Этап 8 — корпус и гипотезы

[Scope, API, статусы и ограничения](validation.md). POST validation-runs фиксирует
corpus/model/source/settings versions и создаёт отменяемую process job. Lists — лёгкие
summaries; детали одного result содержат source anchors. Currentness и comparison
не переписывают исторические результаты. Evidence hypotheses остаётся на observations.

## Этап 9: перенос и exports

- `POST /projects/{id}/operations/{save|verify|export|report}` → 202 JobSnapshot.
  Все длинные операции работают в local process + transactional finalize.
- `POST /projects/restore` multipart `file` ZIP → 202 JobSnapshot; restore в configured
  destination PostgreSQL/root. Route объявлен перед `/projects/{id}`.
- `GET /projects/{id}/exports/{artifact_uuid}/{project.zip|report.md|validation.json}`
  → completed file attachment. User paths не принимаются.
- `GET /interpretation-versions/{id}/export` → JSON DSL attachment + X-Model-SHA256.
- `POST /validation-runs/{id}/export` → 202 job; полный JSON envelope snapshot/coverage/results.

Job kinds: `project_operation`, `project_restore`. Result содержит `outcome`, project ID,
checkpoint relative path или `download_url`. Cancelled/failed не содержат готового результата.
Manifest version/hash/incompatible destination/duplicate identity failures явные,
никакого overwrite/merge. Registry перезапускается с API; опубликованные files сохраняются.
[Format, restore, CLI, limits](portability.md). OpenAPI и frontend types обновлены.

## Этап 10: защитные пределы

Health возвращает `stage=10`. REST shapes и DB schema сохраняются. Число локальных
workers/jobs и output budgets читаются из Settings; [настройки](reliability.md).
Upload превышение — 413, registry capacity — 429. Превышение output budget уже
принятой задачи — terminal `failed`, явная диагностика rows/bytes/limits, `result=null`,
без completed artifact. Прежние immutable результаты остаются доступны.
Бюджет строки валидации общий для GUI worker и CLI apply; это ресурсная защита,
не новое правило протокола. Полные source/settings/model versions прежних runs сохраняются.

## Автоматический анализатор — A4

Без БД доступны `GET /inference/capabilities`, `GET /inference/schemas/{name}`
и `POST /inference/spec/check` с `{document_json}`. Проверка возвращает valid/issues,
нормализованный spec и `scope_verified=false`; существование UUID и ownership
проверяются при загрузке project snapshot. PostgreSQL routes запускают discovery,
просмотр run/candidates/evidence, генерацию model draft и frozen-rule evaluation;
долгие операции идут через отменяемые jobs и атомарную публикацию.

Доступны семейства `framing`, `structure`, `groups`, `events`, `data_mapping`,
`entropy`, `counters`, `tokens`, `timestamps` и `checksums`. Typed evaluation повторно
исполняет frozen framing и фиксированное отношение на выбранном корпусе; правила
с неизвестной/неподдержанной framing-зависимостью отклоняются до постановки job.
Состояние конкретных возможностей возвращает `/inference/capabilities`.
Реестр и DSL описаны в [inference-a4.md](inference-a4.md), ограничения A3 — в [inference-a3.md](inference-a3.md), [A2](inference-a2.md),
[A1](inference-a1.md) и [A0](inference-a0.md).

`GET /inference/checksum-registry` возвращает exact registry parameters и check
vector. `RunInput.log_ids` выбирает замораживаемые журналы для validation.
`ValidationItem.kind=corpus_check`, `check_name`, `check_ordinal` и `related_anchors`
сохраняют relational результаты отдельно; `Coverage.corpus_check_counts` не
увеличивает byte coverage повторно. Поддерживается export модели interpretation-2.

Framing Piece, MessageResult/MessageSummary, ValidationItem/ValidationSummary
дополнены необязательным `technical_limit` (name, observed, maximum,
observed_is_lower_bound). Старые записи читаются с null, числовые значения — строки.
SQL/bundle revisions не изменились. Interpretation-2 добавляет bounded
`delimited_bytes`, сохраняя чтение interpretation-1; [описание и схемы](inference-a0.md).
