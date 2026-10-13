# Ревью этапа 7

Этап 6 одобрен пользователем. Этап 7 одобрен пользователем; переход к этапу 8 разрешён.

## Поведение

- `interpretation/schema.py`: versioned JSON DSL + JSON Schema/Pydantic, отдельный framing,
  закрытые безопасные формулы, типы int/bytes/array/switch, проверки и защитные пределы.
- `interpretation/engine.py`: Construct, точные целые, ветви и повторения, диапазоны полей,
  остановка на неизвестных/конфликтующих байтах, явные неописанные остатки.
- `storage/interpretations.py`, migration `0005_interpretations`: immutable версии с parent/hash,
  immutable JSONL результатов, PostgreSQL индексы, сверка каждого результата с framing anchor.
- `services/interpretations.py`, `api/interpretations.py`: process job с прогрессом/отменой,
  проверкой источника до/после, лёгкими paginated сводками и деталями одного сообщения.
- `InterpretationPanel.tsx`: локальный Monaco с JSON Schema и дополнительной диагностикой,
  сохранение версий, примеры, просмотр результатов, переход от поля/остатка к HEX и packets.
  Редактор хранит 64-битные числовые токены без округления. Editor contributions локальны;
  команды выделения, поиска, форматирования, clipboard и подсказки ошибок включены.
- Старые framing results, наблюдения, action links и исходные записи не переписываются.
  Нужна добавляющая миграция и перезапуск API. [Ручной сценарий](manual-stage-7.md).

## Выполненные проверки

- Полный `pytest backend/tests`: **159 passed**, включая **21 real PostgreSQL integration**.
  PostgreSQL временный, отдельный localhost port; каждый integration test создаёт свою UUID schema.
  Проверены immutable версии/повтор, Construct на разных размерах, failed checks, paginated summaries,
  source ranges через split header, отмена очереди/cleanup, project scope и framing mismatch,
  restart, сохранность прежних таблиц/файлов при миграции с populated stage 6.
- `test_interpretation.py`: **45 тестов**, включая endian/sign для 1/2/4/8 bytes, uint64,
  computed bytes/length checks, массивы, switch, пустые поля, неизвестный variant/tail,
  missing/truncated/ambiguous data, schema/type/reference rejection, unsafe expressions,
  limits, cancellation внутри большого чтения и две реальные synthetic PCAP с общей моделью.
- Ruff check и format --check: успешно, **62 файла**.
- Vitest: **14 passed**; отдельные проверки сохранения int64/uint64 при форматировании и
  замене framing. TypeScript и Vite production build: успешно.
- Существующий Playwright e2e: **1 passed**; задачи/SSE/отмена, локальная загрузка Monaco,
  отсутствие внешних HTTP-запросов и page errors в этом сценарии.
- Отдельный браузерный сценарий с временным API/БД: проект → TCP → length framing →
  модель → сохранить → разобрать три сообщения. Payload lengths 3/5/1; payload второго
  сообщения `4445464748`, anchor `[7,12)`, source packets #4 `[7,9)` и #5 `[9,12)`.
  Проверены переключение результата, selected field → HEX, invalid JSON и semantic reference
  `missing` с подсветкой/сообщением, блокировка применения несохранённой модели.
  Вставка JSON через обработчик clipboard корректно заменяет целый документ.
- TShark независимо сверил raw sequence и payload для **12 TCP-пакетов** двух новых PCAP.
- OpenAPI, frontend API types и standalone JSON Schema регенерированы; воспроизводимый
  генератор обеих JSON-спецификаций: `scripts/export_openapi.py`.

## Ограничения проверок

Полный корпус/гипотезы/stale workflow относятся к этапу 8, перенос/CLI — к этапу 9.
Linux workload/peak RSS и длительный resource benchmark здесь не выполнялись.
Не добавлены PPP/MPTCP/IPv6, live capture, декодирование сжатия или semantic inference.
Тестовые данные синтетические; поле с понятным названием не доказывает его реальный смысл.

Нефатальные сообщения инструментов: существующая Starlette/httpx deprecation,
предупреждение Vite о размере отдельного Monaco chunk и отсутствие опубликованного
source map для bundled marked в dev-режиме. Это не ошибки выполнения приложения.
