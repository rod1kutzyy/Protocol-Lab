# Этап 5 — материал для ревью

Ревью одобрено пользователем; далее исторический отчёт этапа 5.

Реализованы пункты 5.1–5.12. Этапы 2–4 одобрены пользователем;
этап 6 ожидает ревью этапа 5.

## Изменения

- `frontend/src/features/investigation/`: проекты, импорт и диагностика, фильтры
  сессий, направления, виртуальный HEX/ASCII с диапазонной загрузкой, выделение,
  original packet/source navigation, поиск, diff, наблюдения, журналы и links.
- `frontend/src/shared/store.ts`: локальная selection и reference для сравнения.
  Серверные данные и запросы — TanStack Query, большие списки — TanStack Virtual.
- `research/action_logs.py`, `research/search.py`: независимый разбор CSV/JSON с
  точными nanosecond timestamps и поиск только по известным непрерывным bytes.
- `storage/research.py`: immutable source/hash/settings, сохранённая поправка часов
  с контролем revision, временные кандидаты, атомарные manual links/observations.
- `storage/reconstruction.py`: query filters, время сессий, shared anchor validation.
  `storage/projects.py`: чтение original packet ranges, stat-кэш SHA для GUI pages.
- `services/investigation.py`, `api/investigation.py`: отменяемые процессные jobs,
  typed endpoints, ограниченные запросы, scope/integrity diagnostics.
- `0003_investigation`: добавляющая миграция с backfill прежних сессий;
  исходники, derived artifacts и наблюдения сохраняются.
- Обновлены OpenAPI, TS types, fixtures, документация и инструкция запуска.

## Выполненные проверки — 11 октября 2026

- **73 Python-теста прошли**, включая **15 PostgreSQL integration tests**.
  PostgreSQL 17 в отдельном временном контейнере на localhost:55432;
  тесты используют отдельные UUID schemas. Пользовательская БД не изменялась.
- Migration upgrade populated stage 4, Alembic check, идентичность источников,
  manifest, artifact и наблюдений; фильтры/pagination, original packet bytes,
  поисковые jobs/cancel, известные границы и ambiguous/gap/truncated ranges.
- Журналы: field mapping, точные ISO/epoch timestamps, invalid rows, original/hash,
  duplicate import, clock revision conflict, temporal candidates, manual links,
  project scope, restart persistence и отмена без partial publication.
- Ruff check и format --check прошли. После уточнения terminal progress/messages
  повторно прошли **23 теста jobs/storage**, после JSON NaN rejection — **12 unit**.
- TypeScript/Vite build прошёл, **5 Vitest-тестов** прошли.
- Существующий Playwright e2e: **1 passed** — API/UI/jobs/SSE/cancel и local Monaco.
- Отдельно через Playwright CLI вручную проверены создание проекта, PCAP import,
  reconstruct, HELLOWORLD/OK, выделение, original packet, HEX search, HELLO/WORLD diff,
  CSV mapping/partial diagnostics, clock correction, temporal candidate, manual link,
  переход по link и сохранение после browser reload. Дополнительно проверены
  ?? для конфликтующего byte и — для gap/truncated на gaps-overlaps.pcap.
  Выполнена визуальная проверка.

## Ревью и границы

[Пошаговая ручная проверка](manual-stage-5.md).
[REST и protective limits](investigation.md).

Сравнение: до 4096 позиций на диапазон; link/observation/time matching: до 65536.
Большие HEX потоки доступны окнами, gap/conflict никогда не становится известным byte.
Время в кратких списках отображается до ms, точное original ns доступно в деталях
действия/API; clock offset не переписывает источник.

Журналы и links сохраняются, jobs живут до рестарта API. Открытие проекта относится
к зарегистрированным локальным проектам; portable archive и отчёт — этап 9.
Нагрузочный профиль Linux/peak RSS и authentic corpus не проверены (этап 10).
Сохранились предупреждения Monaco chunk size и Starlette TestClient/httpx.

## Исправления после ревью

Все три замечания исправлены: дробные параметры JSON сохраняют числовой тип
и точность во вложенных структурах; epoch timestamp масштабируется сдвигом
Decimal exponent без округления; классификация gap/truncated использует активный
набор усечённых сегментов вместо полного перебора на каждом интервале.

Добавлены regression tests для чисел/строк/bool/null и вложенных параметров,
избыточной точности всех epoch formats, независимости от Decimal context и
4000 сегментов с чередованием known/truncated/gap и проверкой provenance.
Полный backend-набор: **80 passed**, включая **15 PostgreSQL integration tests**
в отдельной временной PostgreSQL 17; Ruff check/format прошли.
Замер sparse reconstruction 1000/2000/4000 сегментов: 0,043/0,044/0,079 s
на текущей машине. Это локальный замер, не контрольный Linux workload.
Изменения не требуют миграции и не переписывают ранее импортированные журналы.

## Автоматическая загрузка окружения — 12 октября 2026

API и Alembic используют общий загрузчик `.env` в корне проекта через python-dotenv;
зависимость зафиксирована в uv.lock. Экспортированные переменные имеют приоритет,
файл не исполняется как shell и не изменяет os.environ. Относительные пути проекта
считаются от каталога `.env`. Инструкции запуска обновлены.
Четыре проверки настроек прошли: чтение из другого cwd, приоритет окружения,
отсутствующий файл и offline Alembic SQL generation без экспорта/подключения к БД.
Ruff check/format прошли. PostgreSQL integration в этой проверке не запускалась.

## Недействительный сохранённый выбор — 12 октября 2026

Если сохранённый в браузере project ID получает HTTP 404, UI очищает только
локальный выбор этого проекта и зависимые capture/session/stream/range/reference.
Ответ от прежнего проекта не сбрасывает новый выбор. Ошибки сети/503 продолжают
показываться и не удаляют selection. Исследовательские данные не изменяются.

Vitest: **8 passed**, TypeScript/Vite build прошёл. Через Playwright CLI с mock API
в отдельном браузере воспроизведены 404 (плашка исчезает, reset сохраняется в storage)
и 503 (ошибка видна, project ID сохранён). Сохранилось предупреждение Monaco chunk size.
