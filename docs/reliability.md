# Надёжность и защитные пределы

Этап 10 проверяет R1–R6 на существующем общем движке. Полные результаты и границы
замеров: [ревью](review-stage-10.md), [повторение проверок](manual-stage-10.md).
Изменений runtime DB schema нет; миграция `0006_validation` остаётся текущей.

## Настройка пределов

API и CLI читают `.env` в корне и переменные окружения через один `Settings`.
Экспортированные значения имеют приоритет. Изменения требуют перезапуска API.
Нулевые/отрицательные значения отвергаются при запуске; block limit — минимум 1024.
Пределы защищают ресурсы и не определяют формат исследуемого протокола.

| Переменная PROTOCOL_LAB_* | Значение по умолчанию | Что ограничивается |
| --- | ---: | --- |
| MAX_UPLOAD_BYTES | 134217728 | PCAP/PCAPNG; превышение HTTP 413 до публикации |
| MAX_BLOCK_BYTES | 16777216 | Один capture block/packet; явный file offset в ошибке |
| MAX_PACKETS | 1000000 | Индексируемые пакеты одного capture |
| MAX_ARCHIVE_BYTES | 536870912 | Загружаемый ZIP проекта |
| MAX_WORKERS | 2 | Одновременные локальные worker/committing jobs |
| MAX_JOBS | 128 | Все снимки задач, включая terminal, до рестарта API |
| MAX_VALIDATION_RESULTS | 500000 | Все строки валидации, включая диагностические и excluded |
| MAX_VALIDATION_BYTES | 536870912 | UTF-8 bytes сериализованных строк результатов |
| MAX_INTERPRETATION_BYTES | 268435456 | UTF-8 bytes строк разбора одного framing run |

При превышении output budget worker завершает job как `failed` с фактическим
числом строк/байтов и настроенным пределом. HTTP-принятие задачи (202) не означает
публикацию исследования. Staging очищается, `result=null`, прежние результаты
доступны. CLI `apply` использует тот же бюджет строк: exit 2, stderr с причиной,
без final output и без перезаписи других файлов. MAX_VALIDATION_BYTES учитывает
строки результатов; CLI envelope/snapshot/provenance в этот бюджет не входят.

TCP `max_sessions`, `max_spans_per_stream`, `max_comparison_bytes` задаются в
`POST /captures/{id}/reconstruct`; настройки сохраняются в reconstruction.
Framing `max_message_bytes`/`max_pieces`, interpretation `max_array_items`/
`max_decoded_fields` задаются в versioned JSON. Ошибка отдельного направления или
сообщения явно диагностируется, остальные данные сохраняются. Archive expanded
limit 2 GiB, member 512 MiB, 20000 members и 2 million snapshot rows остаются
фиксированными защитами bundle v1; подробнее [portability](portability.md).

## Отмена и чтение данных

До `committing` сигнал отмены проверяется в worker. При отсутствии ответа процесс
останавливается через 2 s; частичный staging никогда не объявляется готовым.
В `committing` отмена закрыта, транзакционная публикация завершается целиком.
Уже опубликованные capture/stream/model/run не блокируются процессом вычисления;
DB publication выполняется вне API event loop. Registry/SSE не переживают рестарт,
но исследовательские результаты и исходные ссылки переживают его.

Автоматические тесты отменяют framing, interpretation и corpus validation после
настоящего progress (а не только при запуске spawn). Во время этих jobs тот же API
возвращает старые bytes, packets и validation runs. Дополнительно прежние gates
проверяют import/reconstruction/export cancellation, queued cancellation и
non-cancellable publication. Сохраняется различие между partial, unknown и complete.

## Воспроизводимость и измерения

Одинаковые capture hashes, settings и model content дают одинаковые факты,
диагностику, coverage, границы и provenance. Wall-clock `created_at` и независимые
GUI run IDs относятся к истории запусков; они не обязаны совпадать. Сравнение
immutable запусков сопоставляет source ranges, не изменяет старые результаты.

`scripts/benchmark.py` создаёт детерминированный PCAP: 250000 packets, 1000 TCP
connections, 100000 messages, 100856024 bytes (96,18 MiB). Каждый connection имеет
100 reply messages; один размером 65536 bytes, остальные по 180. TCP payloads
разрезаны по 1400 bytes, поэтому границы сообщений не совпадают с packet boundaries.
ACK-only packets доводят профиль до 250000. SHA-256 и ожидаемые размеры проверяются;
тест не основывается на имени файла или action label.

Каждая фаза запускается в свежем Python subprocess. Время включает чтение входных
артефактов и их сериализацию; `parse` включает framing, а `apply` — индекс,
TCP, framing, parsing, validation и полный JSON с provenance. RSS — ru_maxrss
процесса (Linux KiB конвертируются в bytes), не память PostgreSQL или сумма двух
воркеров. Нагрузка идёт без сети после сборки образа.

Linux x86-64 запуск использует Docker CPU quota 400000/100000 (4 CPU), memory.max
8589934592 (8 GiB), swap выключен. Хост ARM64 macOS, поэтому x86-64 эмулируется;
Docker VM имеет 8319504384 bytes (~7,75 GiB) физической RAM. Это измерения данного
контейнера, а не подтверждение скорости native Linux x86-64 машины с 8 GiB RAM.
Профиль следует повторить там перед обещанием аппаратного SLA. Число видимых
logical CPUs в JSON равно 10; эффективная CPU квота равна 4.

`scripts/benchmark_storage.py` отдельно измеряет реальные PostgreSQL operations
на том же корпусе: publication, validation, reads, consistent snapshot, ZIP,
integrity verification и restore в другой UUID schema/root. Эти измерения получены
на macOS ARM64 с localhost PostgreSQL 17 в Docker и не подменяют Linux core profile.
Нативный Linux прогон всей GUI/DB системы, сумма RSS API + двух workers + PostgreSQL
и максимальная нагрузка конфликтующих overlaps не измерялись.
