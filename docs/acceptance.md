# Статус R1–R6

Этап 1 пропущен по запросу. Эта таблица описывает вклад архитектуры этапа 2;
приёмка настоящих исследовательских сценариев остаётся для дальнейших этапов.

| Требование | Основа этапа 2 | Что ещё предстоит |
| --- | --- | --- |
| R1 | Capture/Packet/Session/DirectedStream/SourceRange, отдельные importer/reconstructor ports | Импорт, восстановление, provenance на PCAP |
| R2 | Observation anchors, диапазонные REST-контракты | HEX, поиск, сравнение, action logs |
| R3 | InterpretationVersion и раздельные framer/interpreter ports | Схема, Construct, редактирование |
| R4 | Corpus, ValidationRun, пять статусов, процессные jobs/SSE/отмена | Проверка корпуса, покрытие, контрпримеры, stale |
| R5 | Относительные capture paths, immutable records, решение PostgreSQL | Схема/миграции, manifest, export/import |
| R6 | Независимое ядро и место для CLI | Общий GUI/CLI engine, отчёт и модель |

Приёмка этапа 2: API/UI запускаются на localhost; браузер создаёт диагностику,
видит завершение и отменяет следующую задачу; API остаётся доступен во время работы;
отменённая/сбойная задача не получает результат; reconnect получает terminal snapshot;
Monaco не обращается к CDN. Автоматизация: `backend/tests`, frontend Vitest и
`frontend/e2e/scaffold.spec.ts`. Этап 3 начинается только после ревью этапа 2.


## Вклад этапа 3

R1: прямое индексирование PCAP/PCAPNG, точные file/payload offsets, заголовки и
checksum/truncation/unsupported диагностика. TCP-сессии и reassembly ещё не реализованы.
R5: PostgreSQL-метаданные и packet index, manifest v1, относительные пути, SHA-256,
проверка immutable source, восстановление доступа после рестарта API. Полный
переносимый экспорт требует этапа 9.

Приёмка: fixtures в tests/fixtures; test_capture_index и настоящие PostgreSQL
integration tests проверяют совпадение байтов/смещений, duplicate/concurrent import,
откат, отмену, manifesto/path/integrity diagnostics и перезапуск API.
Ручная проверка: [manual-stage-3](manual-stage-3.md).


## Вклад этапа 4

R1: connection instances, два направления, SYN/FIN/wrap, reorder/retransmissions,
явные gaps/truncation/conflicting overlaps и exact source ranges. Неопределенные
начала/роли и identity между capture interfaces явно обозначены.
R2/R5: сохраняемые observations со stream/source anchors версии восстановления,
устойчивые к будущему framing; добавляющая DB migration и immutable derived artifact.
Полный перенос проекта, framing, GUI HEX и action logs остаются для своих этапов.

Приемка: test_tcp.py проверяет bytes и provenance по deterministic PCAP;
test_storage_integration.py проверяет publication, restart, range clipping,
источники конфликтов, observation scope/version, повтор, concurrent jobs и отмену.
[Ручная проверка](manual-stage-4.md), [результаты проверок](review-stage-4.md).

## Вклад этапа 5

R1: UI импорта/соединений/направлений и навигация от выделения к original packets.
R2: виртуальный HEX/ASCII, известные/неопределённые bytes, поиск и diff, сохраняемые
наблюдения, CSV/JSON mapping, точные часы с поправкой, временные кандидаты и manual links.
R5: постоянные журналы/настройки/links, additive migration с сохранением прежних evidence.

Приёмка: 73 Python-теста (включая 15 real PostgreSQL integration), frontend unit/build,
существующий e2e каркаса и ручной браузерный сценарий stage 5.
[Сценарий](manual-stage-5.md), [проверки](review-stage-5.md).
На этапе 5 R3/R4/R6 и полный portable export ещё не завершены. Этап 5 одобрен.

## Вклад этапа 6

R1/R2/R3: ручные, fixed, length-field и marker boundaries, явные leftovers и
неопределённые данные, immutable framing versions, GUI preview и исходные packets.
Фрейминг не заменяет field parser/семантическую интерпретацию.
R5: сохранение настроек, source hash/version, range anchors и полного покрытия;
миграция не изменяет предыдущий проект.

Приёмка: tests/test_framing.py, PostgreSQL publication/restart/cancel/migration tests
и browser review четырёх режимов; [сценарий](manual-stage-6.md), [отчёт](review-stage-6.md).
Этап 6 одобрен; вклад этапа 7 описан ниже.

## Вклад этапа 7

R3: versioned JSON Schema/Pydantic, Construct, целые/bytes/arrays/switch, декларативные
проверки, редактор с ошибками, immutable версии и применение к разным размерам/параметрам.
R1/R2: поля и неизвестные участки с точными stream anchors и исходными packets.
R5: additive migration, сохранение и повторный запуск без изменения старых evidence.
Этап 7 одобрен; вклад этапа 8 описан ниже.
[Ручная проверка](manual-stage-7.md), [отчёт](review-stage-7.md).

## Вклад этапа 8

R4: явный versioned corpus/filter scope, frozen source/model/settings snapshot, process
validation, пять статусов, coverage всего состава (включая excluded/unframed/missing TCP),
source counterexamples, stale/currentness и сравнение immutable запусков.
R2/R3: authored semantic hypotheses отдельно от parsed facts, evidence-to-source links,
повтор после уточнения той же модели без per-message правок.
R5: история corpus/hypothesis/run versions, относительные JSONL, additive migration и restart.
Перенос, report и CLI остаются для этапа 9.
[Сценарий](manual-stage-8.md), [проверки](review-stage-8.md).

## Вклад этапа 9

R5: full project-scoped consistent PostgreSQL snapshot + sources/derived в catalog checkpoint
и ZIP; version/SHA-256 verification; restore в отдельный root и migrated PostgreSQL,
без старых файлов/DB URLs, с полным сохранением IDs/history/settings/provenance/coverage.
R6: JSON DSL и full validation JSON, human-readable fixed Jinja2 Markdown report с evidence,
examples/counterexamples/open questions; documented offline CLI apply на общем engine.

Приёмка: automated full snapshot всех 20 tables, restore в новой PostgreSQL schema/root
после переименования старого root, exact API/bytes/evidence/revision/clock/run parity;
пять PCAP/PCAPNG GUI/CLI comparisons; format/hash/path/link/duplicate/cancel/rollback tests.
[Ручная проверка](manual-stage-9.md), [контракт](portability.md), [проверки](review-stage-9.md).
Этап 9 одобрен пользователем. Вклад этапа 10 описан ниже.

## Вклад этапа 10

R1: независимая TShark сверка 27 fixtures/131 packets по headers/time/length/payload
и original offsets; прежний набор TCP edge cases. R2/R5: API restart/reopen и перенос
сохраняют stable observations/action links, точные bytes и source packet navigation.
R3/R4: повтор одинаковых inputs/settings/models даёт те же facts/diagnostics/provenance;
новая версия правил даёт stale исторический run и явное сравнение.
R5/R6: полный synthetic контрольный corpus проходит PostgreSQL publication, snapshot,
ZIP и restore без старого root; скачанная GUI модель применяется CLI к новой записи.

Настроены защитные input/output/worker budgets; превышение и cancellation сохраняют
предыдущее исследование. Реальные framing/decoding/validation jobs отменяются после
progress; старые bytes/packets/runs читаются одновременно. Контрольный Linux x86-64
core профиль: 96,18 MiB, 250000 packets, 1000 connections, 100000 messages, до 64 KiB.
Это эмуляция ARM64 с CPU quota 4 и memory limit 8 GiB; native аппаратный SLA и
суммарный RSS GUI/API/двух workers/DB не подтверждены.

[Ревью](review-stage-10.md), [повторение](manual-stage-10.md),
[пределы и методика](reliability.md), [машинные результаты](benchmarks/stage10-linux.json).
Этап 10 ожидает ревью; production launcher и сдача относятся к этапу 11.

## Исправления по ревью

R4: невосстановленные TCP-направления сохраняются в снимке и отдельных диагностических
строках, учитываются в Unknown либо Not applicable согласно фильтрам, без выдуманных
байтов. Публикация проверяет их наличие; история переносится и открывается повторно.
Регрессии: `test_cli_keeps_failed_reconstruction_directions_in_coverage`,
`test_unreconstructed_directions_publication_scope_restart_and_restore` и
`test_stage9_gui_cli_values_diagnostics_and_export_model`.

R3/R6: общий загрузчик моделей отклоняет дублирующиеся JSON-свойства и NaN/Infinity
в GUI, CLI и импортируемых проектах. Регрессия:
`test_cli_and_gui_reject_same_ambiguous_model_documents`; CLI не публикует выходной файл.

Проверки исправлений: полный backend-набор — 240 passed, включая реальные PostgreSQL
integration tests; дополнительный тест экспорта исторического JSON — 1 passed.
Frontend — 17 passed, существующий полный Playwright-сценарий — 2 passed.
Ruff lint/format и `npm run build` прошли. PostgreSQL запускался в отдельном временном
контейнере; тесты использовали собственные UUID-схемы и синтетические captures.

## Переработка UI: разделы и исследовательская область

R1/R2: импорт и фильтры отделены от исследования; HEX и источники находятся рядом,
поиск/сравнение/журнал/наблюдения/гипотезы доступны отдельными инструментами.
R3: фрейминг и поля вынесены в раздел модели с независимыми вкладками.
R4: корпус и история проверок находятся в собственном разделе; контрпример
открывает исходный диапазон, не сбрасывая выбранный запуск или черновик модели.
R5/R6: прежние snapshot/restore/ZIP/report/JSON/CLI остаются доступны.

Наблюдаемая приёмка: заполнить формы и Monaco, выбрать диапазон и опорное
сравнение, прокрутить HEX; обойти пять разделов и фоновые задачи; вернуться
к прежним значениям и прокрутке. Переключить направление и вернуться к его
черновику. Открыть источник из гипотезы/привязки/контрпримера.
Проверки: frontend/e2e/workspace.spec.ts, обновлённый research.spec.ts,
unit tests selection/navigation; [контракт UI](ui-workspace.md).
## Автоматический анализатор: A0

R2–R4: добавлены versioned контракты spec/rule/candidate/snapshot/run/evidence/
evaluation/decision/transform, локальные JSON Schema и API capabilities/spec check.
Реализована deterministic discovery sampling по capture/session/direction,
deduplication с сохранением occurrences и независимый explicit holdout.
Технические лимиты framer/parser отделены от опровержения правил, метаданные
сохраняются в corpus results и отображаются в GUI; engine versions повышены.
Исторические модели/результаты читаются, DB migration не требуется.
Это фундамент A0, автоматический поиск и persistence новых runs относятся к A1.
[Контракты, ограничения и проверки A0](inference-a0.md).
