# Перенос проекта, отчёт и CLI (этап 9)

## Полное сохранение и открытие

PostgreSQL остаётся runtime БД. Автоматические публикации сохраняют metadata,
immutable версии и результаты транзакционно; originals/derived лежат в каталоге проекта.
«Сохранить полный снимок» создаёт `checkpoints/<UUID>/` с полным состоянием выбранного
проекта. Снимок независим от исходного PostgreSQL и может быть восстановлен в новой БД.
Снимок фиксирует состояние на момент начала REPEATABLE READ transaction;
изменения, завершённые позже, попадут в следующий снимок.

При открытии в GUI запускается фоновая проверка manifest version и SHA-256 всех
зарегистрированных sources/derived. Ошибка явно показывается в «Перенос и отчёт»;
старые metadata остаются доступными, повреждённые файлы не исправляются молча.
Кнопка проверки повторяет проверку по текущим данным. Проверка не объявляет
семантические гипотезы доказанными и не делает старые validation runs актуальными.

Рабочий каталог по-прежнему имеет manifest `protocol-lab-project`, version 1,
metadata schema bootstrap `0001_capture_storage` (совместимость этапа 3).
Полный снимок имеет отдельный `bundle.json`, format `protocol-lab-bundle`, version 1,
metadata schema revision `0006_validation`. Никаких DB URL/credentials/абсолютных
путей исходной установки в экспорт не записывается.

```text
checkpoints/<UUID>/  или корень распакованного ZIP
  bundle.json       # формат, project ID, таблицы/число строк, file sizes/SHA-256
  manifest.json     # исходный manifest проекта
  metadata.jsonl    # versioned PostgreSQL data snapshot, строки {table, row}
  sources/          # оригинальные PCAP/PCAPNG и журналы действий
  derived/          # reconstruction/framing/interpretation/validation artifacts
```

В metadata включены все 20 research tables: проекты, captures/packets, TCP connections,
streams/spans/provenance, action logs/mapping/clock revisions/actions/links,
observations, все immutable model/hypothesis/corpus versions с parent history,
framing/parsing/validation runs/results и frozen settings/engine/source snapshots.
Snapshot ограничен выбранным проектом; другие исследования из той же БД не экспортируются.
Старые checkpoints, временные jobs, downloads, runtime DB files, connection settings
и локальный выбор строк интерфейса не входят в исследовательский snapshot.
GUI хранит временный выбор в Zustand; архив восстанавливает стабильные evidence anchors.

Все строки читаются в одной read-only REPEATABLE READ transaction. Файлы копируются
из зарегистрированных относительных путей с проверкой hashes и неизменности во время
чтения; packet bytes не превращаются в JSON payloads. Не зарегистрированные orphan
файлы не входят в архив и не удаляются. Export не требует pg_dump/pg_restore:
metadata.jsonl — согласованный snapshot PostgreSQL, не альтернативная runtime БД.

## Восстановление на новой установке

1. Установить зависимости по README (сеть требуется только для установки).
2. Запустить локальный PostgreSQL и настроить redacted `.env.example` в новом каталоге.
   `PROTOCOL_LAB_DATABASE_URL` указывает на **новую destination DB**;
   `PROTOCOL_LAB_PROJECT_ROOT` — на новый root. Исходная установка не нужна.
3. Применить миграции из backend:

   ```sh
   cd backend
   uv run --frozen alembic upgrade head
   ```

4. Запустить API/UI, выбрать ZIP в «Перенос проекта» и нажать «Восстановить проект».
   Дождаться `Завершена`. Проект открывается с прежними IDs, bytes и anchors.
   Или выполнить из корня репозитория:

   ```sh
   uv run --project backend --frozen protocol-lab project restore --archive /new/path/project.zip
   ```

   Полный сохранённый каталог открывается так:

   ```sh
   uv run --project backend --frozen protocol-lab project verify --directory /new/path/checkpoint
   uv run --project backend --frozen protocol-lab project restore --directory /new/path/checkpoint
   ```

5. Проверить выбранный packet/field и повторить validation. Старые runs сохраняют
   свои исходные snapshots и stale markers; перенос не переписывает историю.

Restore проверяет формат, все file hashes/sizes, table inventory, column types,
runtime metadata schemas, file references и project ownership FK. Декларативные
модели проходят Pydantic/content hash validation. Imported SQL/templates не исполняются.
UUIDs сохраняются; existing project/row/directory identity вызывает ошибку, без merge,
перенумерации или overwrite. Для второй копии того же проекта используйте новую БД/root.
Self-referencing parent history восстанавливается внутри одной DB transaction.
Ошибка откатывает metadata и удаляет только новую, созданную этим restore директорию;
пользовательские проекты/источники не меняются.

В bundle v1 поддерживается revision 0006. Несовместимая версия диагностируется;
автоматических destructive migrations нет. Destination должна быть мигрирована
до совместимой revision. Новый проект хранит проверенную копию snapshot в
`checkpoints/restored/`, так что его полное состояние остаётся в каталоге.

## Экспорт и отчёт

GUI: «Перенос и отчёт» → ZIP, JSON выбранной immutable interpretation version,
JSON выбранного validation run или Markdown-отчёт. У каждой длинной операции есть
job progress, SSE/polling, cancellation и terminal state. Скачать можно только
завершённый artifact. После API restart файлы уже опубликованных exports доступны;
registry jobs необходимо создать заново для новых операций.

CLI сохранения/архива (PostgreSQL обязателен):

```sh
uv run --project backend --frozen protocol-lab project save --project-id UUID --output /new/path/checkpoint
uv run --project backend --frozen protocol-lab project export --project-id UUID --output /new/path/project.zip
```

JSON модели — сам versioned DSL (`schema_version: interpretation-1`), пригодный для
`apply`, без GUI wrapper. Response header `X-Model-SHA256` идентифицирует модель.
Validation JSON — envelope `protocol-lab-validation`, format version 1:
`run` (frozen snapshot + coverage) и полный `results` array. Five statuses,
fields/unknowns/stream anchors и capture hashes сохраняются без отбора только Passed.

Markdown создаётся локальным **фиксированным Jinja2 template**, включённым в пакет.
Содержит sources/hashes/policies, observations/source ranges, hypothesis history,
rationale/scope/unknowns/contradictions, models, corpus filters, coverage, examples и
counterexamples с packet/file/payload offsets, ограничения и команду CLI.
Первые пять примеров каждого статуса **каждого запуска** показываются с явным указанием
выборки; полная история результатов находится в JSON/архиве. Поля bytes в result имеют
bounded previews (`preview_truncated`), их anchors позволяют прочитать originals.

## CLI apply — общий с GUI движок

Проверка JSON-документа модели общая с GUI: повторные свойства и NaN/Infinity
отвергаются до исполнения. Ошибки TCP-направлений включаются в frozen source snapshot
и строки `reconstruction_diagnostic`. Их размеры неизвестны; они учитываются в
`unreconstructed_directions` и Unknown, сохраняя результаты остальных направлений.
Старые архивы и validation JSON без новых полей читаются с нулевыми/пустыми значениями
по умолчанию; SQL-схема и формат bundle v1 не изменились.

Не требует PostgreSQL, API или браузера; работает offline после установки зависимостей.

```sh
uv run --project backend --frozen protocol-lab apply \
  --model tests/fixtures/cli/length-model.json \
  --capture tests/fixtures/framing/length-big.pcap \
  --output /tmp/length-validation.json
```

`--checksum-policy warn|ignore|reject` (default warn) сохраняется в output.
Capture индексируется через dpkt, реконструируется через общий TCP engine, далее
выполняются **те же** `validate_stream`, framing, Construct parser и `CoverageCounter`,
что у GUI. CLI также сохраняет `provenance` с connections/directions/spans/all variants,
packet IDs/indexes, exact file offsets/payload/stream ranges.

CLI проверяет обе стороны всех TCP connections в новой записи. Для сравнения с GUI
создайте corpus без direction/address/port/time filters и восстановите TCP.
CLI capture ID определяется из SHA-256; GUI назначает capture ID при импорте.
Model/corpus/run IDs CLI локальные; сравнивайте bytes/направления/ranges/значения/диагностику,
а не UUIDs и wall-clock time. Тест parity подставляет GUI capture ID и сравнивает все
result facts/anchors/diagnostics/coverage на пяти PCAP/PCAPNG.
Ручные boundaries остаются координатами stream; для переиспользования на иных размерах
предпочтительны fixed/length/marker rules. Неподходящий manual scope даёт Unknown.

Exit 0 означает, что validation выполнена (Failed/Unknown/Ambiguous могут присутствовать);
exit 2 — ошибка входа, формата, лимита, I/O или PostgreSQL. CLI никогда не заменяет
существующий output; apply публикует JSON только после завершения через atomic link.
Некорректный source/model не оставляет частичный output.

[Fixture model и ожидаемые counts](../tests/fixtures/cli/expected.json):
`length-big.pcap` → 1 Passed / 2 Failed, 15 bytes;
`arrays-new-parameters.pcap` → 0 Passed / 1 Failed, 6 bytes;
`length-incomplete.pcap` → 1 Passed и видимый unframed остаток, 8 bytes.
Тестовая константа намеренно ограничивает n=3: другие значения дают counterexamples.

## Защитные пределы и диагностика

ZIP upload: default 512 MiB (`PROTOCOL_LAB_MAX_ARCHIVE_BYTES`), multipart body bounded
до spooling; expanded bundle ≤2 GiB, каждый member/metadata ≤512 MiB,
≤20,000 files, ≤2,000,000 metadata rows, ≤32 MiB JSONL row, bundle manifest ≤8 MiB.
Это protective limits, не ограничения бинарного протокола.
Traversal, absolute paths, backslashes/Windows paths, duplicate members, symlinks,
special files, directories/encrypted ZIP members и missing/unlisted files отвергаются.
Источники текущего проекта проходят тот же managed-path guard, что импорт.
SHA-256 проверяет целостность, не авторство архива.

Подготовка отменяется без публикации завершённого artifacts. Фаза `committing`
закрывает отмену и выполняет атомарную публикацию/DB transaction; restore
в этой фазе также копирует файлы в final root. При сбое новые строки откатываются.
Прежние проекты остаются доступными во время работы локального worker.
Проверки нагрузки/peak RSS на контрольном Linux профиле относятся к этапу 10.
