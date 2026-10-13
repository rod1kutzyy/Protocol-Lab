# Ревью этапа 10

Этап 9 одобрен пользователем. Выполнены 10.1–10.10 с указанными ниже границами
контрольного стенда. Этап 10 ожидает ревью; переход к этапу 11 не выполнен.
Дата проверок: 12 октября 2026.

## Изменения

- Конфигурируемые Settings для local worker concurrency, job capacity, числа/байтов
  результатов validation и байтов interpretation; проверка положительных значений.
  Общий UTF-8 ResultBudget в GUI worker и offline CLI. При превышении — явная ошибка,
  cleanup staging, отсутствие completed output, прежнее исследование сохранено.
- TShark сверка расширена до 27 применимых PCAP/PCAPNG: frame lengths/time,
  IPv4 адреса, TCP ports/sequence/ack/flags/length и exact original payload offsets.
  Сверка включает sequence wrap, SYN/FIN, reused tuple, retransmission, overlaps,
  truncation, VLAN, raw IP, big endian/nanosecond PCAP и multi-interface PCAPNG.
- Новые тесты воспроизводимости на четырёх разных captures; явное различие
  run timestamps и стабильных facts/diagnostics/coverage/provenance.
- Настоящие worker framing/decoding/validation отменяются после progress;
  тот же API читает прежние bytes/packets/runs, отменённые результаты не публикуются.
  Успешные framing/model/run/evidence выдерживают reopen/restart и перенос.
- Воспроизводимые scripts для control/smoke core workload и полного PostgreSQL
  publication/validation/export/restore benchmark; маленькие JSON отчёты сохранены
  в docs/benchmarks, большие synthetic files остаются в ignored output.
- Полный Playwright GUI workflow с двумя временными мигрированными DB schemas/roots:
  наблюдение → гипотеза → контрпример → новая модель → повтор → перенос → CLI.
  Обычная e2e конфигурация не выбирает research DB из `.env`; без runner исследование
  явно skipped. TypeScript проверяет e2e файлы вместе с приложением.
- PLAN/README/R1–R6/API docs, health/UI stage=10, [пределы](reliability.md),
  [повторение](manual-stage-10.md). Runtime schema остаётся 0006, новой миграции нет.

Основные файлы: services/resources.py, settings.py, validation.py, interpretations.py,
application.py; API app/validation/interpretations; CLI main; test_resources.py,
test_jobs.py, test_storage_integration.py; scripts/check_tcp_with_tshark.py,
benchmark.py, benchmark_storage.py, Dockerfile.benchmark, run_e2e.py;
frontend/e2e/research.spec.ts и playwright.config.ts. TCP/framing/parser алгоритмы
сохраняются; resource checks стоят в orchestration/output publication.

## Фактически выполненные проверки

- Полный `pytest backend/tests`: **228 passed**, включая **32 real PostgreSQL
  integration tests**, 61,70 s. Каждая integration schema — отдельная test-owned UUID.
  Новые 28 tests проверяют budgets/конфигурацию, повторные факты и source ranges,
  failed publication без потери старых данных, реальные progress/cancel/read сценарии.
- Ruff check и format --check: успешно, **86 файлов**.
- Vitest: **17 passed**, 6 файлов. TypeScript (включая e2e) и Vite build: успешно.
- TShark 4.6.9: **27 fixtures / 131 packets**, все выбранные network fields и
  payload source offsets совпали. [Полный JSON](benchmarks/stage10-tshark.json).
  Неприменимые malformed/linktype/timestamp случаи перечислены, а не объявлены Passed.
- Playwright: **2 passed**, 17,6 s, Chromium 156 / Playwright browser build 1248.
  Diagnostic jobs/SSE/cancel regression и полный research workflow без mocks.
- GUI: один Passed / два Failed для constant n=3; counterexample n=5 в [5,12)
  открывается в HEX/source packets; модель без constant даёт три Passed и два status
  differences; старый run отмечен stale. После reload manual action evidence открывает
  прежние [0,2), source packets #3/#4 и file offset 304.
- ZIP, model JSON и Markdown скачаны из UI; report содержит сохранённую гипотезу.
  Исходный root физически переименован, UI restore выполнен в другую schema/root;
  прежние IDs, bytes, source offsets и три Passed доступны.
- Скачанная новая модель применена установленным CLI к arrays-new-parameters.pcap:
  **1 Passed** с новым значением n=4. PostgreSQL CLI apply не требуется.
- Страница не делала внешних HTTP-запросов, page errors отсутствовали. Screenshots
  export/restored проверены визуально; artifacts в ignored frontend/test-results.
- Docker benchmark image успешно собран из pinned Python digest, uv 0.13.0 и frozen
  uv.lock. Сам Linux workload выполнен с `--network none`.

При подготовке e2e исправлены селекторы combobox, способ ввода JSON в Monaco и
адрес опроса jobs после перехода к destination origin. Финальный прогон прошёл
целиком; предыдущие неуспешные попытки не считаются успешными gates.

## Контрольный Linux core профиль

[Машинный отчёт](benchmarks/stage10-linux.json). Linux 7.0.14 x86-64, Python 3.12.15;
CPU quota 400000/100000 = 4 CPU, memory limit 8589934592 = 8 GiB, swap выключен.
Capture: **100856024 bytes (96,18 MiB)**, **250000 packets**, **1000 connections**,
**100000 messages**, максимум **65536 bytes**. Application bytes: **83356000**.
SHA-256: `a0ffab96634b7596d956a54cdb4dc0d5d5bff4659d210c5e401d47275d84aa4a`.

| Операция | Время, s | Пик RSS, MiB |
| --- | ---: | ---: |
| Packet indexing + JSONL | 8,765 | 51,72 |
| TCP reconstruction + artifact | 4,881 | 1209,07 |
| Load reconstruction + framing | 2,538 | 566,79 |
| Load reconstruction + framing + field parsing | 5,836 | 566,79 |
| Полный общий apply/validation + JSON/provenance | 21,592 | 1247,27 |
| Повтор apply | 22,099 | 1247,07 |

Все 100000 messages — Passed; дополнительно 1000 empty directions — Not applicable.
Вся область учтена; unframed, undecoded, missing, ambiguous bytes равны нулю на этом
упорядоченном синтетическом профиле. Повтор имеет идентичный semantic SHA-256
`701cf18001fef398c20c96a7ae93cdf9618785dcfdfced320479855ed8e8171a` после удаления
только wall-clock created_at. Полные IDs/settings/coverage/facts/provenance сохранены.

**Граница стенда:** x86-64 эмулируется Docker на macOS ARM64. Docker VM имеет около
7,75 GiB физической RAM, cgroup memory limit — 8 GiB. Это выполненный container
profile, но скорость native Linux x86-64 машины с 8 GiB RAM не подтверждена. RSS
отдельного процесса не является суммой API/двух workers/PostgreSQL. Нативный полный
GUI/DB workload нужно повторить на целевой машине перед аппаратными обещаниями.

## Полный PostgreSQL corpus

[Машинный отчёт](benchmarks/stage10-storage.json). Тот же control capture/core
artifacts, macOS ARM64 + localhost PostgreSQL 17 Docker; это отдельные измерения,
не Linux hardware profile. Каждый этап — новый процесс. Использованы две отдельные
мигрированные UUID schemas; после прогона они удалены.

| Операция | Время, s | Пик RSS, MiB |
| --- | ---: | ---: |
| Source copy + 250000 packet rows publication | 8,899 | 78,88 |
| Reconstruction publication (1000 sessions/60000 spans) | 7,362 | 614,77 |
| Freeze corpus + validation worker (100000 messages) | 16,949 | 122,48 |
| Validation publication (101000 rows) | 6,990 | 123,38 |
| 20 чтений bytes + packet + run | 0,654 | 83,55 |
| Consistent project snapshot | 9,148 | 113,41 |
| ZIP | 3,956 | 77,42 |
| Bundle SHA-256 verification | 0,244 | 73,77 |
| Unpack/restore + source/result reads, старый root недоступен | 16,592 | 87,00 |

20 sequential read samples: p95 **56,8 ms**, максимум **109,7 ms** на полном
сохранённом корпусе. Одновременность с compute проверена отдельно integration
тестом на настоящих длительных jobs; его read gate — <3 s, без общего latency SLA.
Expanded snapshot **654604252 bytes**, ZIP **62064969 bytes**; восстановлены
250000 packet rows, 1000 sessions, 2000 streams, 60000 spans, 101000 validation
rows, source hashes и 100000 Passed при недоступном прежнем root.

## Границы приёмки

Проверены deterministic captures; внешний корпус организатора не предоставлен в
этом задании. Control нагрузка не содержит большого количества конфликтующих
retransmissions; они покрыты focused tests и max_comparison_bytes, а максимальная
нагрузка такой формы отдельно не измерялась. Production-раздача, единая команда
запуска, полный offline запуск и native аппаратный прогон остаются отдельными
проверками. Passed по правилам не объявляется доказательством семантики гипотезы.

Нефатальные сообщения: прежний Starlette/httpx deprecation, Vite Monaco chunk warning,
missing bundled marked source map и Node NO_COLOR/FORCE_COLOR. Тесты/сборка успешны.
Пользовательские DB/captures/services не изменялись; временные test servers и отдельный
PostgreSQL остановлены после проверки. Synthetic artifacts сохранены для ревью.
