# Автоматический анализатор A4

A4 добавляет реестр checksum/CRC, ограниченный поиск, перенос поддерживаемых
кандидатов в `interpretation-2`, общий исполнитель `corpus_checks`, свидетельства
в отчётах и проверку переноса проекта. Capabilities возвращает `stage=A4` и все
десять семейств. Доступность детектора означает наличие ограниченного алгоритма,
а не доказательство семантики или исчерпывающий поиск всех протоколов.

## Реестр

`GET /api/v1/inference/checksum-registry` возвращает version, параметры и
контрольные значения для ASCII `123456789`. В модели сохраняется algorithm ID;
порядок хранения результата задаётся отдельно от отражения битов CRC.

| ID | Width | Poly | Init | RefIn/RefOut | XorOut | Check |
| --- | --- | --- | --- | --- | --- | --- |
| xor8 | 8 | XOR байтов | 0 | — | 0 | 31 |
| sum8 | 8 | сумма байтов modulo 256 | 0 | — | 0 | DD |
| sum16 | 16 | сумма байтов modulo 65536 | 0 | — | 0 | 01DD |
| internet_checksum | 16 | one's complement суммы big-endian слов; нечётный последний байт — старший | 0 | — | FFFF | F62A |
| CRC-8/SMBUS | 8 | 07 | 00 | false/false | 00 | F4 |
| CRC-16/ARC | 16 | 8005 | 0000 | true/true | 0000 | BB3D |
| CRC-16/IBM-3740 | 16 | 1021 | FFFF | false/false | 0000 | 29B1 |
| CRC-16/IBM-SDLC | 16 | 1021 | FFFF | true/true | FFFF | 906E |
| CRC-32/ISO-HDLC | 32 | 04C11DB7 | FFFFFFFF | true/true | FFFFFFFF | CBF43926 |

Поиск проверяет хвост и bounded offsets в заголовке; варианты покрытия — всё
сообщение или байты перед полем, с началом покрытия 0..4 и исключением поля.
Сначала проверяются хвостовые варианты всех алгоритмов, затем offsets заголовка.
Первые восемь выбранных сообщений служат screening; сохранение требует минимум
трёх математических совпадений и двух разных payload. Сохранённые правила затем
проверяются на всей выбранной discovery-выборке, включая противоречия.
Эквивалентные объяснения остаются отдельными кандидатами. Произвольные polynomial,
init/xorout и произвольные области автоматически не подбираются; явные диапазоны
можно задавать в правиле/DSL. `max_checksum_operations` считает обработанные байты
консервативно по длине входного сообщения; истощение поиска не становится Failed.

Бюджет `max_rule_trials` общий: часть резервируется под framing, остальное делится
между выбранными relational families; Data Mapping получает отдельную долю.
Поле checksum TCP/IP и гипотеза прикладной checksum не смешиваются.

## interpretation-2

Сохраняется чтение и исполнение `interpretation-1`; добавленные значения по
умолчанию не меняют content hash прежних моделей. Поддерживаются:

- `delimited_bytes`, включая явную политику отсутствующего terminator;
- `bytes.length={"remaining_minus": N}` для bounded данных перед хвостовым полем;
- discriminated `checks.kind=checksum`: безопасный field path, algorithm ID,
  byte_order, coverage, coverage_start, covered_ranges и exclude_field;
- `corpus_checks`: `counter`, `copied_value`, `timestamp`, `event_association`,
  `parameter_mapping` с уникальным именем каждой проверки и явными предпосылками.

Межсообщенческие проверки выполняются после разбора общим `validation/corpus.py`.
Они публикуются как `ValidationItem.kind=corpus_check`, отдельно от message facts;
`Coverage.corpus_check_counts` содержит их сводку. Они влияют на общие counts,
но не добавляют те же bytes второй раз в byte coverage. `related_anchors` открывают
второе сообщение перехода/копирования. Порядок счётчика задаётся stream offsets,
копирования — интервалами packet timestamps. Копирование сравнивает исходные bytes,
а не одинаковые числа в разных endian. Timestamp хранит точные decimal строки,
unit, epoch, reference_ns, offset, tolerance и drift_ppm.

Лимиты `max_corpus_units`, `max_corpus_bytes`, `max_checksum_bytes` являются
техническими: результат Unknown с diagnostic/technical_limit, а не противоречием.
Нет предыдущего сообщения, packet times или выбранного журнала — Unknown.
Пересечение окон действий — Ambiguous; сообщение вне окон — Not applicable;
событие без сообщения — Unknown. Поля и прежние результаты сохраняются.

GUI замораживает выбранные `log_ids` вместе с SHA-256, mapping, clock revision,
offset и событиями; изменение журнала/часов предотвращает публикацию устаревшего
результата. CLI `apply` принимает повторные `--action-log`, `--log-mapping` JSON
и `--clock-offset-ns`; без них правила действий явно получают Unknown.
Локальный экран разбора исполняет поля/checksum и сообщает, что corpus checks
выполняются отдельно в проверке корпуса.

Черновик модели доступен для хвостовой checksum, counter и timestamp с frozen
framing. Неоднозначная структура, незафиксированные позиции и аналитические
наблюдения сохраняют `not_compilable` и причину. Проверка fixed candidate доступна
и для аналитических A3-правил с frozen framing независимо от compilability.

## Перенос и проверка

Используется существующий portable format 2 / metadata revision `0007_inference`:
новые поля находятся в versioned JSON, SQL-колонки не менялись, миграция не нужна.
Архив включает sources, models, snapshots, inference/evaluation evidence и
validation results. Format 1 / `0006_validation` по-прежнему читается. Отчёт
содержит настройки, hashes, версии, scope, метрики, limitations и ограниченные
примеры с точными packet/payload ranges для discovery и evaluation.

Fixtures: `tests/fixtures/inference/README.md`; генератор —
`scripts/generate_inference_fixtures.py`. Тесты A4 — `test_inference_a4.py` и
`test_inference_a4_storage.py`; второй сценарий требует отдельной локальной
PostgreSQL через `PROTOCOL_LAB_TEST_DATABASE_URL` и восстанавливает bundle в другом
root/schema. Playwright запускается существующим isolated runner.

`scripts/benchmark_inference_a4.py` измеряет native file adapter. Записан Windows
baseline для 1000 сообщений: `benchmarks/inference-a4-windows.json`. RSS —
накопленный пик одного процесса во всех измеренных фазах, не сумма workers/DB/UI.
Linux control workload 100 MiB/250000 packets, PostgreSQL publication, UI чтение
и concurrency этим baseline не проверены. Эти проверки остаются отдельными
приёмочными воротами, пока требуемый стенд не доступен.
