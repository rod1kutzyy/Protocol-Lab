Ревью пользователя успешно; переход к этапу 7 одобрен.

# Этап 6 — материал для ревью

Реализованы 6.1–6.9. Этапы 2–6 одобрены пользователем; этап 7 разрешён.

## Изменения

- `framing/engine.py`: versioned discriminated FramingSpec, manual/fixed/length/markers,
  полный набор message/leftover ranges, независимые boundary/data statuses,
  bounded reads, диагностика неизвестных заголовков/длин/маркеров, cancellation.
- `storage/framing.py`, миграция 0004: immutable content-addressed artifacts/runs/pieces,
  source hashes, reconstruction/engine/config versions, транзакционная publication,
  pagination и verification coverage. Наблюдения/action links не изменяются.
- `services/framing.py`, jobs: отдельный локальный процесс, progress/cancel/committing,
  result только при завершённой публикации; failed/cancelled сохраняет прежнее.
- `api/framing.py`: typed POST/GET stream framing, GET run и paginated pieces.
- `FramingPanel`, `framing-config.ts`: четыре формы, добавление HEX selection как
  ручной границы, сохранённые версии, сводка покрытия и virtual preview,
  сообщения/остатки/status/diagnostics, переход к HEX/source packets.
- OpenAPI/TypeScript и детерминированные fixtures + генератор, docs/acceptance/PLAN.

## Проверки — 12 октября 2026

- **110 Python-тестов прошли**, включая **18 настоящих PostgreSQL integration tests**.
  PostgreSQL 17 — отдельный временный tmpfs контейнер на localhost:55433;
  каждый integration test использует отдельную UUID schema. Пользовательская БД
  и настоящие исследовательские captures не изменялись.
- **23 framing tests**: manual/fixed leftovers, length widths/endian/formula,
  variable lengths, malformed/incomplete/unknown lengths, explicit marker boundaries
  через packets/read chunks, unknown barriers, safe model rejection, protective
  limits/cancel, stable IDs, deterministic PCAPs и exact bytes.
- Storage/API: duplicate/concurrent-safe publication, новые версии без переписывания,
  metadata/pieces pagination, source navigation, stable observations после reframing,
  restart, queue cancellation и failed job без partial artifacts.
- Migration upgrade populated stage 5: identity всех старых DB records, включая
  logs/actions/action links/observations; byte identity sources/manifest/derived.
  Alembic check прошёл. Прежние upgrade tests этапов 3/4 также проходят.
- Ruff check / format --check прошли.
- TypeScript/Vite build прошёл; **11 Vitest-тестов** прошли, включая manual overlap,
  integer formulas/HEX validation и сравнение сохранённых spec независимо от key order.
- Существующий Playwright e2e jobs/SSE/cancel/local Monaco: **1 passed**.
- TShark независимо подтвердил TCP sequence numbers и payload bytes **12 пакетов**
  из четырёх новых framing fixtures.
- Через отдельный Playwright CLI браузер на синтетических источниках проверены
  fixed preview HELLO/WORLD, добавление выделения как manual message, source packet
  navigation и length preview (3 variable messages). Проверка markers и визуальный
  осмотр выполнены в том же тестовом проекте.

## Ревью и границы

[Пошаговый сценарий](manual-stage-6.md), [API, правила и пределы](framing.md).

Превью сохраняет результат; каждая изменённая конфигурация даёт immutable версию.
Границы по правилу не доказывают семантику протокола; missing/ambiguous payload виден.
Length framing не угадывает alignment после неизвестного поля, marker search не
пересекает unknown bytes и не предполагает escaping/вложенность. UI фильтр работает
среди загруженных диапазонов, это явно обозначено; сводка покрывает весь stream.

Полный Linux workload/peak RSS и authentic corpus framing не проверены (этап 10).
PPP и объединение MPTCP subflows не добавлены. Construct field parsing/модель — этап 7,
corpus validation — этап 8, portable export/report/CLI — этап 9.
Сохранились предупреждения Monaco chunk size и Starlette TestClient/httpx.
