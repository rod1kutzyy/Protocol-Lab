# Этап 3 — материал для ревью

Ревью одобрено пользователем; ниже сохранены результаты проверки этапа 3.

Реализованы пункты 3.1–3.8. Этап 2 одобрен пользователем, этап 4 не начат.
Отметки в PLAN означают завершение реализации, **не** одобрение ревью этапа 3.

| Пункт | Реализация |
| --- | --- |
| 3.1 | UUID project directory, manifest format v1, relative sources/derived, PostgreSQL projects/captures/packets, additive Alembic migration |
| 3.2 | Multipart copy в managed staging; source publication без replace, read-only source |
| 3.3 | SHA-256 по оригинальным байтам, повторная проверка перед publication, endpoint verify |
| 3.4 | Explicit already_imported, исходный capture_id/policy, PostgreSQL uniqueness + per-project advisory lock |
| 3.5 | Direct PCAP/PCAPNG structures dpkt, multi-interface/section, micro/nano/base-2 time, SPB без вымышленного времени |
| 3.6 | Индекс с record/file/payload offsets, packet lengths, IP/TCP headers, deterministic packet IDs |
| 3.7 | Сохраняемые warn/ignore/reject, checksum statuses и counts; warn не отбрасывает payload |
| 3.8 | Fixture-to-source побайтное совпадение, hashes, verify, повторный импорт, API restart |

## Изменения

- `capture/index.py`: независимое от HTTP/DB ядро индексирования.
- `storage/database.py`, `storage/projects.py`, `backend/migrations/`: PostgreSQL
  metadata и managed paths/manifest/source publication.
- `services/imports.py`, `services/jobs.py`: process indexing + asynchronous
  non-cancellable publication; другие jobs и запросы обслуживаются во время commit.
- `api/projects.py`, `api/limits.py`, `api/app.py`: project/capture/packet/verify routes,
  upload/body bounds, configured storage; обновлённый OpenAPI и TypeScript.
- `compose.dev.yml`, `.env.example`: local PostgreSQL dev configuration.
- `tests/fixtures/`, generator и тесты: small synthetic sources и ожидаемые ranges.
- Frontend: отображение capture_import jobs, committing status, запрет отмены при commit,
  актуальное описание этапа; отдельные порты browser tests без конфликта с dev servers.

## Проверки — 11 октября 2026

- pytest полный прогон: **33 passed**, включая **6 real PostgreSQL integration tests**;
  integration tests не пропущены. PostgreSQL 17 в отдельном tmpfs Docker-контейнере,
  localhost:55432; каждый тест использует новую UUID schema, не сбрасывает чужие данные.
- Повторный `alembic upgrade head` и `alembic check`: выполнены в integration test,
  migration соответствует SQLAlchemy metadata.
- Ruff check и format --check: успешно, 31 Python-файл.
- `uv sync --frozen --offline`: успешно, без изменений lock-файла.
- TypeScript typecheck, `npm run build`: успешно.
- Vitest: **2 passed**.
- Playwright/Chromium: **1 passed**, localhost UI/API/SSE/отмена и локальный Monaco;
  тестовые порты 18000/15173, внешних запросов и page errors нет.
- `docker compose -f compose.dev.yml config --quiet`: успешно с placeholder password.

Тесты покрывают PCAP endian/precision, PCAPNG interfaces/sections/legacy PB/SPB/
base-2 rounding/skipped blocks, exact offsets, checksum policies, malformed/truncated
packets/container, bounds, cancellation, concurrent duplicate imports, rollback
и retry, PostgreSQL restart access, manifest/symlink/path checks и source tampering.
Во время заблокированной publication тест отдельно проверяет доступность API,
закрытую отмену commit и успешное завершение другой процессной задачи.

## Что проверить вручную

[Полная инструкция](manual-stage-3.md): настроить отдельную PostgreSQL, применить
миграции, создать проект в Swagger, загрузить fixtures, посмотреть packets/diagnostics,
повторить импорт, проверить checksum и перезапустить API.

UI проектов/импорта запланирован на этапе 5. Сейчас соответствующие операции доступны
через API/Swagger; jobs отображаются в существующем интерфейсе.

## Ограничения

- TCP sessions/reassembly и stream provenance ещё не реализованы (этап 4).
- Filesystem и PostgreSQL не образуют единую ACID-транзакцию. После rollback/crash
  может остаться immutable source без DB row или stale staging. Источник не удаляется
  автоматически, retry проверяет hash и использует его; см. storage-and-import.md.
- Каталог manifest + runtime DB ещё не portable export. Dump/snapshot и восстановление
  в новую БД — этап 9.
- Job registry не переживает рестарт, runtime API один Uvicorn worker.
- Modified PCAP, IPv6, неподдержанные link layers и fragmented IPv4 не разбираются;
  соответствующие ошибки/diagnostics явные. Блоки PCAPNG вне поддержанных структур
  учитываются в diagnostics; оригинальные bytes сохранены.
- Проверено на macOS ARM64 с маленькими deterministic fixtures. Linux контрольный
  workload, peak RSS, TShark и recovery после hard power loss не проверялись.
- Сохраняются предупреждения Vite о размере лениво загружаемого Monaco и Starlette
  об устаревании TestClient с httpx; проверки проходят.
