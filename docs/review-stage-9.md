# Ревью этапа 9

Выполнены 9.1–9.10. Ревью этапа 9 одобрено пользователем; переход к этапу 10 разрешён.

## Реализовано

- Полный consistent project-scoped PostgreSQL snapshot всех 20 research tables под
  одним read-only REPEATABLE READ: captures/packet indexes/TCP provenance, framing,
  immutable models/hypotheses/corpora/history, actions/mappings/clock revisions/links,
  observations, parsing/validation runs/results/settings/engine snapshots.
- Самостоятельный checkpoint в каталоге проекта; версия bundle v1/schema 0006,
  original manifest, metadata JSONL и exact originals/derived с SHA-256/relative paths.
  Export не сохраняет credentials, DB URL или прежний абсолютный root.
- Background opening integrity check; ZIP export и restore в отдельные migrated PostgreSQL/root,
  сохранение IDs/anchors/history, explicit duplicate identity без merge/overwrite.
- Проверка file inventory/hash, runtime metadata schemas/model content hash,
  FK project ownership, table counts/types и archive limits/path/symlink/duplicate guards.
  При сбое restore откатывает metadata и только созданную им директорию.
- Jobs с progress по строкам metadata и байтам файлов/ZIP; отмена подготовки,
  non-cancellable transactional publication; downloads только completed artifacts.
- JSON выбранной immutable модели и полный JSON validation run с coverage/всеми statuses.
- Human-readable Markdown через fixed packaged Jinja2 template: evidence/hypotheses,
  rationale/scope/unknowns/contradictions, model/corpus/engine versions, coverage,
  examples/counterexamples и packet/file/payload offsets; выборка первых пяти примеров
  каждого статуса каждого run обозначена явно, полные данные находятся в JSON/архиве.
- Offline `protocol-lab apply --model … --capture … --output …` без PostgreSQL/HTTP:
  общие dpkt/TCP/framing/Construct/validation engines, counts и полная source provenance.
  CLI project save/verify/export/restore, fixtures модели и expected results.
- GUI «Перенос и отчёт» и форма restore; typed OpenAPI/API client,
  [контракт](portability.md), [ручная проверка](manual-stage-9.md), обновлённый PLAN/R1–R6.
  Runtime schema не менялась, добавляющая миграция для этой функциональности не требуется.

Основные файлы: storage/portable.py, services/portability.py и application.py,
framing/source.py, validation/engine.py, cli/main.py, api/portability.py,
reports/render.py и templates/research.md.j2, frontend PortablePanel.tsx.

## Проверки, выполненные фактически

- Полный `pytest backend/tests`: **200 passed**, включая **30 real PostgreSQL integration**.
  Тесты использовали отдельный одноразовый PostgreSQL на localhost:55439;
  каждый integration test создавал собственную UUID schema.
- Новые unit scenarios `test_portability.py`: **19 passed** — path traversal/absolute/Windows
  paths, duplicate ZIP/symlink/expanded limits, bundle version/hash/unlisted files/cancel,
  installed CLI execution, expected results on new parameters, uncertain/unsupported
  PCAP/PCAPNG, exact packet provenance и отказ от partial/overwritten output.
- Новые integration scenarios: **4 passed** — полный snapshot всех 20 tables,
  API restore в другую DB schema/root при недоступном исходном root, exact bytes/API
  metadata/history/clock/evidence/run/comparison/currentness/restart parity;
  duplicate original import/restore; checksum failure/cancel/invalid snapshot rollback;
  CLI save/verify/export/restore и согласованный clock snapshot во время изменения clock.
- GUI/CLI сравнение всех result facts/fields/anchors/diagnostics/coverage на пяти fixtures:
  length-big, gaps-overlaps, mixed-diagnostics, multi-interface PCAPNG, unsupported-link.
  Использован GUI capture ID для прямого сравнения provenance; production CLI IDs из SHA-256.
- Ruff check и format --check: успешно, **81 файл**.
- Vitest: **17 passed**; TypeScript + Vite production build: успешно.
- Существующий Playwright e2e: **1 passed** — jobs/SSE/отмена, local Monaco,
  отсутствие внешних HTTP и page errors в этом regression scenario.
- Ручной Playwright CLI browser scenario на полном synthetic research:
  opening integrity check → checkpoint → ZIP download → model JSON → full validation JSON
  → Markdown report. JSON содержит 1 Passed / 2 Failed для исходной записи;
  report содержит два counterexamples и exact source File offset 304.
- Скачанная в браузере immutable модель применена CLI к arrays-new-parameters.pcap:
  1 Failed, n=4 против правила n=3, 6 bytes; предыдущие files не переписаны.
- Browser restore скачанного ZIP в новую пустую schema/root, при физически недоступном
  первоначальном synthetic root: автоматическое открытие проекта, прежние capture/connection
  IDs, сохранённые actions/clock offset 123456789012345 и manual evidence link.
  Проверена навигация связи к исходным байтам после переноса.
- Offline `uv build backend`: wheel/sdist успешно. Wheel включает Jinja2 template
  и console entry point protocol-lab; offline frozen editable sync и CLI help успешны.
- Визуально проверен новый раздел экспорта. Browser artifacts в ignored `output/playwright/`.

Исправлена ложная диагностика checksum при первом чтении перенесённого файла:
verification сравнивает inode/size/mtime/ctime, access time не считается изменением bytes.
Bundle guards ограничены его компонентами; системный alias macOS `/var` допустим,
symlinks внутри bundle отвергаются. Оба случая покрыты round-trip/CLI tests.

## Границы приёмки

Поддерживается bundle v1/schema revision 0006; destination нужно явно мигрировать.
Existing identities не объединяются; вторая копия требует отдельной DB/root.
Jobs registry не переживает API restart, опубликованные exports/checkpoints сохраняются.
Restore после `committing` не отменяется; DB insert и копирование final files идут в
транзакционной публикации. Проверки workload/peak RSS на Linux 4 vCPU/8 GiB,
широкий robustness/end-to-end demo и production launcher относятся к этапам 10–11.
Не заявлена семантическая доказанность гипотез из Passed.

Нефатальные сообщения: существующие Starlette/httpx deprecation, Vite warning о Monaco
chunk size и missing bundled marked source map. Во время ручного переключения на пустую
destination ожидаемо зарегистрирован HTTP 404 для прежнего project ID; UI сбросил selection.
Пока API был остановлен для смены тестовой БД, Vite proxy временно возвращал HTTP 500
на health checks; после запуска destination API подключение восстановилось.
Пользовательская БД/captures не использовались и не изменялись.

Временные browser/API/Vite и одноразовый PostgreSQL остановлены после проверки.
Артефакты содержат только synthetic fixtures; пользовательские services не останавливались.
