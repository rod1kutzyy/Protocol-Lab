# Хранение и импорт — этап 3

Этап 2 одобрен пользователем. Этап 3 реализует основу R1 (источник и пакетный
индекс) и R5 (сохраняемое исследование). TCP-сессии и восстановление байтов
относятся к этапу 4. Пользовательские экраны проектов/импорта — к этапу 5.

## Локальный каталог и PostgreSQL

Корень задаётся `PROTOCOL_LAB_PROJECT_ROOT` (по умолчанию `./projects`). Каждый
проект имеет сгенерированный UUID-каталог:

```text
projects/<project_uuid>/
  manifest.json
  sources/<sha256>.pcap|pcapng
  derived/                      # зарезервировано для потоков последующих этапов
  .staging/<upload_uuid>/        # только незавершённые загрузки/индексы
```

`manifest.json` содержит `format=protocol-lab-project`, `format_version=1`,
`project_id`, `metadata_schema_revision=0001_capture_storage`, относительные имена
`sources_directory` и `derived_directory`, UTC `created_at`. Абсолютные пути,
пароли и connection string в него не попадают. Изменение версии/идентичности
manifest вызывает 409 при открытии проекта; источники не перезаписываются.

PostgreSQL сохраняет projects, captures и packets. SQLAlchemy ORM и начальная
**добавляющая** миграция Alembic `0001_capture_storage`. Уникальность
`(project_id, sha256)` предотвращает повторные записи; `(capture_id, index)`
защищает индекс. В packet JSONB сохраняется IndexedPacket, без raw payload.
Индекс и метаданные сохраняются после рестарта API; job registry остаётся в памяти.

API не применяет миграции автоматически. Пользователь явно запускает
`alembic upgrade head`. Destructive downgrade отключён, существующая БД не
сбрасывается. При отсутствующей конфигурации API/диагностика работают, storage routes
возвращают 503. `health.persistence=postgresql_configured` означает наличие
конфигурации, не проверку доступности БД; ошибка подключения/схемы также даёт 503.

Каталог с manifest и connection string **ещё не переносимый экспорт**. Этап 9
добавит versioned manifest архива и согласованный PostgreSQL dump/snapshot вместе
с источниками, моделями и результатами, восстановление в новую БД и миграции.
Нельзя считать простое копирование каталога заменой этому экспорту.

## Импорт и публикация

1. Multipart-загрузка копируется в уникальную `.staging` директорию. Имя
   пользователя не используется как путь. SHA-256 рассчитывается по исходным байтам.
2. Magic определяет PCAP/PCAPNG, независимо от имени/расширения.
3. Spawn-процесс строит JSONL-индекс пакет за пакетом, сообщает прогресс в байтах
   источника и проверяет отмену. Некорректный сетевой пакет сохраняется с diagnostics;
   соседние пакеты остаются доступными. Повреждение контейнера, неверный record/block
   length и превышение лимитов завершают импорт ошибкой без опубликованного capture.
4. `running → committing`: публикация уже не отменяется. Транзакция PostgreSQL
   сериализует публикации проекта через advisory lock, повторно проверяет checksum,
   распознаёт дубликат, связывает источник через hard link без перезаписи и сохраняет
   весь индекс пакетными INSERT. Источник получает read-only права.
5. Только успешная транзакция публикует capture; затем job получает `succeeded`.
   Переданный checksum policy, пределы индексирования и версия движка сохраняются.
   Дубликат возвращает `already_imported` и **прежний capture_id/policy**, а также
   `requested_checksum_policy`. Автоматического изменения исследования не происходит.
6. Отмена/ошибка/штатное завершение очищают только временную staging-директорию.

При откате транзакции после создания source-файла может остаться immutable orphan.
При повторной попытке файл проверяется по SHA-256 и используется без перезаписи.
При аварийном завершении всего API могут остаться staging-файлы. Автоматического
удаления неизвестных файлов/источников нет: такое обслуживание требует отдельного
решения. Транзакция и filesystem не образуют единую ACID-транзакцию; commit БД —
граница видимости готового capture. Штатное выключение API дожидается текущей публикации.

## Контейнеры, время и смещения

- PCAP 2.4: little/big endian, micro/nanosecond magic. Modified PCAP magic пока
  отклоняется явно. File/packet headers разбираются структурами dpkt.
- PCAPNG 1.0: SectionHeader/InterfaceDescription/EnhancedPacket/legacy Packet blocks
  разбираются структурами dpkt; SPB читается напрямую (dpkt не имеет этой структуры).
  Несколько секций с разным endian, несколько интерфейсов, if_tsresol (base 10/2),
  if_tsoffset. Блоки вне SHB/IDB/EPB/PB/SPB сохраняются в оригинале, но не интерпретируются;
  summary содержит unindexed_pcapng_block_type_<type> count (число типов ограничено 64).
- Время вычисляется целочисленно без float. Если разрешение тоньше наносекунды,
  округляется вниз с `timestamp_rounded_to_ns`. SPB имеет timestamp=null, а не 0.
  В JSON `timestamp_ns` — **десятичная строка или null**, чтобы сохранить точность в JS.
- `index` — 0-based индекс пакета; ID = UUIDv5(capture_id, index).
- `record_offset` — начало packet record/PCAPNG block в оригинале.
- `file_offset` — начало сохранённого link-layer packet в оригинале.
- `payload_offset` — начало TCP payload относительно `file_offset`.
- `payload_length` — только имеющиеся bytes; `declared_payload_length` — длина
  из IP/TCP-заголовков. При усечении они отличаются; байты не дополняются.
- Точные байты payload: `[file_offset + payload_offset,
  file_offset + payload_offset + payload_length)` в неизменённом источнике.

Поддержаны Ethernet (включая до двух VLAN tags), raw IPv4 (LINKTYPE 101/228 и
распространённый DLT_RAW 12), Linux cooked v1 (113). Unsupported link/network
protocols и IPv4 fragments диагностируются и не используются для будущего TCP
восстановления. Фрагментация IP не восстанавливается на этом этапе. SYN/FIN,
retransmissions и объединение TCP будут реализованы на этапе 4.

Индекс сохраняет capture/interface/section identity, captured/original lengths,
IP endpoints/protocol/header/total lengths, TCP ports/sequence/ack/flags/header lengths,
checksum statuses и diagnostics. При malformed headers часть полей nullable;
доступные исходные байты и packet identity сохраняются.

## Checksum policy

| Policy | Поведение |
| --- | --- |
| warn (default) | Проверить IPv4/TCP, сохранить предупреждение; invalid не отбрасывает payload |
| ignore | Сохранить `unchecked`, не проверять checksum |
| reject | Сохранить пакет/исходник и warning; invalid помечает `eligible_for_reassembly=false` |

У неполного TCP сегмента checksum `unavailable`, не `invalid`. Invalid checksum
сам по себе не доказывает повреждение данных: на локальной машине возможен offloading.
Checksum-warning/rejection не удаляет доказательства.

## Защитные пределы

Настраиваемые env: `MAX_UPLOAD_BYTES` — 128 MiB, `MAX_BLOCK_BYTES` — 16 MiB,
`MAX_PACKETS` — 1,000,000 (полные имена начинаются с `PROTOCOL_LAB_`).
ASGI также ограничивает весь multipart-request: max_upload_bytes + 1 MiB на поля
и headers, включая requests без Content-Length, до полного spool на диск.
Worker processes ≤2, registry ≤128; list endpoints limit 1–1000, offset ≥0.
Это protective limits, не форматные ограничения TCP-протокола. Рабочий профиль
100 MiB/250,000 пакетов и Linux peak RSS/timings измеряется на этапе 10.

Проверка checksum сохранённого источника: POST `/captures/{id}/verify`.
Missing/modified source вызывает 409. Пути вне корня, `../` и symlinks в проекте
отклоняются. Отдельные ошибки БД не показывают DSN/password или raw payload.

## Полное portable состояние (этап 9)

Runtime directory/manifest v1 сохраняет совместимость этапа 3. Полный snapshot directory
и ZIP содержат `bundle.json` v1, PostgreSQL metadata JSONL revision 0006, originals/derived
с SHA-256 и relative paths. [Формат и восстановление на новой DB/root](portability.md).
DB connection string не экспортируется. История evidence/model/corpus/hypothesis/validation
сохраняет прежние IDs. Existing identities не merge/overwrite; rollback затрагивает только
созданные restore строки/директорию. Current GUI opening выполняет checksum/version job.
