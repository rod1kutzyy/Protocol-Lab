# Ревью этапа 8

Этап 7 одобрен пользователем. Выполнены 8.1–8.11; этап 8 ожидает ревью, этап 9 не начат.

## Реализовано

- Immutable версии гипотез: statement/rationale/scope/evidence/unknowns/contradictions,
  parent history и переходы к наблюдениям/пакетам. Нет автоматического подтверждения семантики.
- Immutable corpus versions: явные capture IDs, direction/address/port/точные time filters.
- Frozen согласованный snapshot источников, модели, framing/reconstruction/settings/engine versions.
- Локальная отменяемая validation job на общих framing и Construct engines; результаты JSONL
  и PostgreSQL indexes, atomically published. Старые исследования не переписываются.
- Полная сводка пяти статусов: messages, leftovers, excluded/empty streams, unsupported capture
  diagnostics и записи без reconstruction. Unframed в выбранной области — Unknown/Ambiguous.
  Отдельно считаются missing/truncated/conflicting source bytes и decoded leaf coverage.
- Контрпримеры с полями и stable source anchors, currentness с причинами/деталями/временем,
  paged comparison по capture/stream/reconstruction version/source ranges.
- Новый раздел проекта «Гипотезы и проверка корпуса»; source navigation сохраняет его локальный
  выбор. Сводки/virtual lists не сериализуют весь capture; details загружаются для выбранной строки.
- Добавляющая миграция `0006_validation`, typed API/OpenAPI, [контракт](validation.md) и
  [ручная проверка](manual-stage-8.md).

Основные файлы: validation/models.py и engine.py; research/hypotheses.py;
storage/validation.py и hypotheses.py; services/validation.py; api/validation.py;
frontend CorpusPanel/HypothesesPanel/ValidationDetails и corpus-config.

## Проверки, выполненные фактически

- Полный `pytest backend/tests`: **177 passed**, включая **26 real PostgreSQL integration**.
  Каждый integration test использует отдельную UUID schema во временном PostgreSQL.
- `test_validation.py`: **13 тестов** — повторный разбор и counterexample, фильтры/time overlap,
  полное coverage, empty stream identity, malformed framing, missing/ambiguous data,
  точные comparison keys, reframing/смена reconstruction coordinates, cancellation и leaf counts.
- Integration: дополнительная запись выявляет ошибочную константу; исправление той же модели
  меняет три статуса; повтор с теми же входами не меняет факты. Проверены paged summaries,
  source packet ranges, stale после model/corpus/reconstruction changes, integrity failure без
  completed result, queued cancel/cleanup, scope guards, hypothesis revisions/evidence и restart.
- Отдельно: ошибка framing одного capture не блокирует короткое пригодное сообщение другого;
  настоящие gaps/conflicting spans дают explicit uncertainty counters. Миграция с populated
  stage 7 сохраняет прежние таблицы и все original/derived файлы побайтно; Alembic check проходит.
- Ruff check + format --check: успешно, **71 файл**.
- Vitest: **17 passed**, включая exact nanosecond scope, port 0, immutable filter round-trip
  и отклонение invalid/empty scope. TypeScript и Vite production build: успешно.
- Существующий Playwright e2e: **1 passed**; задачи/SSE/отмена, локальный Monaco, отсутствие
  внешних HTTP-запросов и page errors в этом сценарии.
- Ручной Playwright CLI browser flow на двух synthetic PCAP:
  hypothesis + observation reference → explicit corpus A→B → immutable save → validation.
  Получено 1 Passed/3 Failed, 21 selected bytes, 10 undecoded bytes.
  Counterexample n=4 из дополнительной записи открывает `[0,2)`, packet #3, file offset 304.
  Уточнение модели через Monaco и сохранение новой версии помечает старый запуск устаревшим;
  повтор даёт 4 Passed, сравнение — 3 Failed→Passed на тех же диапазонах.
  После рестарта API/UI сохранённые corpus/hypothesis/run/comparison доступны; evidence link
  открывает `[0,2)` первого capture в packet #3 `[0,1)` и #4 `[1,2)`.
- Визуально проверены screenshots корпуса/coverage/comparison, hypothesis card и HEX navigation.
  Browser artifacts лежат в ignored `output/playwright/`.

Временные API/Vite/browser/PostgreSQL остановлены; пользовательская БД и captures не изменялись.
Синтетические файлы для проверки используются из `tests/fixtures`,
fixture-specific правила/filename shortcuts в движке отсутствуют.

## Границы этой проверки

Не выполнялись Linux workload/peak RSS measurements (этап 10), перенос/report/CLI (этап 9).
Нет PPP/MPTCP/IPv6/AI/live capture, расшифровки, декодирования сжатия или state-machine reconstruction.
Гипотеза не становится доказанной из-за Passed. Проверка применяется только к явно сохранённой
области, а не к невыбранным записям устройства.

Нефатальные сообщения инструментов: существующая Starlette/httpx deprecation, Vite warning
о размере Monaco chunk и отсутствующий bundled marked source map в dev-режиме. Проверки проходят.
