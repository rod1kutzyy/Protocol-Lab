# Архитектура — этапы 2–10

Статус: этапы 2–9 одобрены, этап 10 реализован и ожидает ревью. Этап 1 пропущен по запросу.
Подробности хранения и импорта: [storage-and-import](storage-and-import.md).

Приложение работает локально. React обращается к `/api/v1` через Vite proxy;
FastAPI слушает 127.0.0.1:8000. В рабочем запуске API должен иметь **один** процесс
Uvicorn: реестр задач этапа 2 хранится в памяти и не разделяется между процессами.
Monaco, его JSON/editor workers, стили и шрифты загружаются локально. Никакие
исследовательские данные не отправляются внешним сервисам.

## Границы

- `api/`: HTTP, OpenAPI, SSE, проверка входов; не содержит алгоритмов обработки PCAP.
- `services/`: координация задач и будущих операций импорта/проверки.
- `domain/`: неизменяемые Pydantic-записи и интерфейсы этапов обработки.
- `capture/`, `tcp/`, `framing/`, `interpretation/`, `validation/`: отдельные пакеты
  будущего ядра. `capture/` реализует индексирование PCAP/PCAPNG; `tcp/` реализует восстановление и provenance; framing реализует независимые правила границ; interpretation компилирует безопасную JSON-модель в Construct; validation реализует корпусное исполнение, покрытие и source-range comparison.
- `research/`: action logs и поиск; hypotheses сохраняются с immutable версиями и observation evidence.
- `storage/`: PostgreSQL-репозитории и managed project/source files; Alembic migrations.
- `cli/`: будущий адаптер тех же services/core, что использует GUI.
- `frontend/src/shared`: сгенерированные API-типы, клиент, Zustand, UI-компоненты.
- `frontend/src/features/jobs`: реальный диагностический сценарий задач, TanStack Query
  для серверного состояния, TanStack Virtual для списка.

Зависимости направлены от API/CLI к services и core. Core не импортирует HTTP,
SQLAlchemy sessions или UI. Pydantic допустим для общей валидации доменных записей.
Фрейминг и интерпретация имеют отдельные интерфейсы. Настоящие алгоритмы и их
тестовые PCAP добавляются на соответствующих этапах, без демонстрационных заглушек.

## Сущности и происхождение

Исполняемые определения: `backend/src/protocol_lab/domain/models.py`.

| Сущность | Назначение / идентичность |
| --- | --- |
| Capture | UUID источника, SHA-256, формат, относительный путь, checksum policy |
| Packet | UUID пакета, capture ID, индекс, timestamp ns, file offset, captured/original lengths |
| Session | UUID конкретного соединения; адреса и порты не являются его идентификатором |
| DirectedStream | UUID направления сессии, reconstruction version/policy, extent и проблемные интервалы |
| SourceRange | Capture + Packet + TCP payload interval + версионированный StreamRange |
| Message | StreamRange, framing version, boundary status и provenance |
| InterpretationVersion | Неизменяемый JSON, schema version, hash и ссылка на предшествующую версию |
| Observation | Текст и стабильные stream/source anchors; нет зависимости только от message ID |
| Hypothesis | Формулировка, rationale, scope, evidence, unknowns, contradictions |
| Corpus | Capture IDs и явные сериализованные фильтры |
| ValidationRun | Corpus, capture hashes, interpretation ID, настройки и engine version |

Все интервалы имеют вид `[start, end)`, смещения >= 0; SourceRange требует равных
длин исходного и производного интервалов. Packet payload offsets относятся к TCP
payload. Stream extent учитывает отсутствующие байты и не равен размеру сохранённых
данных. Gaps/truncation/ambiguity перечислены явно; заполнение нулями запрещено.
Модели domain фиксируют архитектурный контракт, но не заменяют валидацию фактических
пакетов, интерпретаций и ссылок на существующие объекты в следующих этапах.

## Фоновые задачи

`multiprocessing` с `spawn`, по умолчанию 2 параллельных процесса, очередь остальных
задач. По умолчанию не более 128 записей (включая завершённые); после достижения лимита API
возвращает 429. Число processes/jobs и output budgets настраиваются через Settings; [защитные пределы](reliability.md).
Диагностика: 1–100 шагов по 0–300 ms; никаких PCAP или протокольных результатов.

`queued → running → succeeded | failed`; отмена в очереди сразу даёт `cancelled`,
отмена процесса проходит через `cancelling → cancelled`. Отмена идемпотентна.
Кооперативный сигнал дополняется остановкой процесса через 2 s. Импорт после
индексирования входит в `committing`: отмена закрыта до завершения транзакции. Результат публикуется
только при `succeeded`. Сбой процесса получает явное сообщение и не блокирует API.
При завершении API дочерние процессы закрываются.

SSE отдаёт полные снимки с возрастающей revision. При переподключении клиент
получает актуальный снимок даже завершённой задачи. Промежуточные снимки могут
объединяться; это поток состояния, не журнал событий. Terminal event закрывает поток.
Задачи не переживают рестарт API; постоянное хранение исследовательских результатов
будет PostgreSQL, а не этот реестр.

## Решение о хранении (этап 3)

PostgreSQL + SQLAlchemy + Alembic; начальная схема projects/captures/packets и миграция
созданы на этапе 3. Диагностика доступна без БД, но storage routes требуют конфигурации
и явного применения миграций; иначе возвращают 503.
SQLite/JSON-файл не подменяют согласованную БД. Файлы источников лежат, а производные
потоки будут лежать под корнем проекта с относительными путями и контрольными
суммами. Переносимый экспорт потребует manifest version и согласованного snapshot
или dump БД вместе с источниками; connection string не является проектом.

Восстановление этапа 4: [tcp-reconstruction](tcp-reconstruction.md).

## Интерфейс исследования (этап 5)

UI adapters в features/investigation вызывают typed REST. TanStack Query хранит
server state, Zustand — выбранные project/capture/session/stream/range и эталон
сравнения, TanStack Virtual — строки сессий/HEX/источников/действий.
research/action_logs.py и research/search.py независимы от HTTP/БД;
storage/research.py сохраняет журнал, поправку и связи транзакционно.
services/investigation.py выполняет отменяемый импорт/поиск в локальных процессах.
Миграция 0003 добавляет action_logs/actions/action_links и backfill времени сессий.
[Контракты и ограничения](investigation.md).

## Фрейминг (этап 6)

`framing/engine.py` исполняет versioned FramingSpec по coverage metadata и bounded
byte reader. `services/framing.py` — отменяемый процесс, `storage/framing.py` —
immutable content-addressed artifact и PostgreSQL index. `FramingPanel` показывает
конфигурацию, версии, сообщения и leftovers; click использует прежнюю selection
HEX/source navigation. Результат не изменяет stable observations/action links.
[Политики и API](framing.md).

## Интерпретации (этап 7)

interpretation/schema.py определяет versioned DSL и JSON Schema; engine.py собирает
Construct Struct/BytesInteger/Bytes/Array/Switch с source anchors и bounded execution.
services/interpretations.py выполняет отменяемый разбор потока, storage/interpretations.py
сохраняет immutable модели/JSONL и индексы результатов. API возвращает лёгкие сводки и
детали выбранного сообщения. InterpretationPanel содержит локальный Monaco, версии,
ошибки модели, значения и неизвестные диапазоны. [Контракт](interpretations.md).

## Корпус и гипотезы (этап 8)

validation/models.py задаёт scope/snapshots, engine.py исполняет общие framing/Construct
engines и сравнивает stable source ranges. storage/validation.py сохраняет corpus versions,
согласованный snapshot и atomic results; services/validation.py выполняет process job.
HypothesisStore сохраняет отдельные authored claims и immutable версии, не выводит смысл
из Passed. CorpusPanel/HypothesesPanel показывают scope, полное coverage, currentness и
контрпримеры; source navigation использует прежний HEX/packet adapter.
[Контракт](validation.md).

## Перенос и повторное применение (этап 9)

storage/portable.py сериализует project-scoped PostgreSQL tables под одним REPEATABLE READ
snapshot, проверяет file inventory/hashes и восстанавливает в migrated destination DB
с сохранением UUIDs/parent history/anchors. metadata.jsonl — snapshot, runtime остаётся PostgreSQL.
services/portability.py готовит ZIP/report/results в process jobs; api/portability.py и
PortablePanel — adapters. reports/templates/research.md.j2 — fixed Jinja2 template.
services/application.py и cli/main.py исполняют те же dpkt/TCP/framing/Construct/validation
functions, что GUI; framing/source.py и capture_diagnostics разделяются обоими адаптерами.
[Контракты и формат](portability.md).
