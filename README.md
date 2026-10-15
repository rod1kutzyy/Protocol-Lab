# Protocol Lab

Локальная лаборатория исследования бинарных TCP/IPv4-протоколов.
Этапы 2–9 одобрены. **Этап 10: надёжность, отзывчивость и ресурсы** готов к ревью.
В UI доступны проекты, импорт, HEX/ASCII, поиск, сравнение, журнал действий, фрейминг, versioned JSON-модели, гипотезы и проверка выбранного корпуса с контрпримерами.

Запуск и ручная проверка: [manual-stage-10](docs/manual-stage-10.md).

## Запуск для разработки

Нужны Python 3.12, uv, Node.js 22.12+ (проверено на 24), npm.
Предварительная установка требует сети; приложение использует локальные ресурсы.

```sh
uv sync --project backend --frozen
cd frontend
npm ci
```

Из корня репозитория, два терминала:

```sh
uv run --project backend --frozen uvicorn protocol_lab.api.app:app --host 127.0.0.1 --port 8000
```

```sh
cd frontend
npm run dev
```

Открыть http://127.0.0.1:5173. Swagger: http://127.0.0.1:8000/docs.
Проекты выбираются в верхней панели; меню содержит «Данные», «Исследование», «Модель», «Проверка» и «Результаты».
Переходы сохраняют выбор, формы, редактор и прокрутку. [Навигация и границы сохранения черновиков](docs/ui-workspace.md).
Кнопка «Задачи» показывает прогресс/JSON и позволяет отменить задачу. Реестр задач находится в памяти и сбрасывается при перезапуске API;
не запускать Uvicorn с несколькими workers. Без БД работают диагностика и проверка JSON-модели.
Для проектов/импорта настройте PostgreSQL и примените миграции по инструкции выше.
API и Alembic автоматически читают `.env` из корня проекта. Переменные терминала
имеют приоритет; относительный PROJECT_ROOT считается от корня проекта.

## Проверки

```sh
uv run --project backend --frozen ruff check backend scripts
uv run --project backend --frozen ruff format --check backend scripts
uv run --project backend --frozen pytest backend/tests
cd frontend
npm run build
npm test
npx playwright install chromium
npm run test:e2e
```

Диагностический Playwright-тест запускает серверы на 18000/15173. Полный research workflow запускайте через `scripts/run_e2e.py` с `PROTOCOL_LAB_TEST_DATABASE_URL`: runner мигрирует две временные UUID schemas и запускает вторую пару 18001/15174 для restore. Без этих настроек research test явно skipped; пользовательская БД не выбирается. [Все команды и контрольный профиль](docs/manual-stage-10.md).
Для запуска тестов браузер нужно предварительно установить. Production-раздача и
единая команда запуска запланированы на этапе 11.

## Обновление API-типов

```sh
backend/.venv/bin/python scripts/export_openapi.py
frontend/node_modules/.bin/openapi-typescript docs/openapi.json -o frontend/src/shared/api-types.ts
```

Документация: [архитектура](docs/architecture.md), [REST-контракты](docs/api-contracts.md),
[хранение/импорт](docs/storage-and-import.md), [статус R1–R6](docs/acceptance.md), [план](PLAN.md).

Этап 4: восстановление TCP и exact provenance реализованы через API.
[Ручная проверка](docs/manual-stage-4.md) · [Политики и ограничения](docs/tcp-reconstruction.md).

Этап 5: [инструкции для ревью](docs/manual-stage-5.md), [контракты и пределы](docs/investigation.md), [проверки](docs/review-stage-5.md).

Этап 6: [сценарий](docs/manual-stage-6.md), [фрейминг](docs/framing.md), [проверки](docs/review-stage-6.md).

Этап 7: [сценарий ревью](docs/manual-stage-7.md), [модели и ограничения](docs/interpretations.md), [проверки](docs/review-stage-7.md).

Этап 8: [сценарий ревью](docs/manual-stage-8.md), [корпус/гипотезы/API](docs/validation.md), [проверки](docs/review-stage-8.md).

Этап 9: [сценарий ревью](docs/manual-stage-9.md), [перенос/CLI/отчёт](docs/portability.md), [проверки](docs/review-stage-9.md).

CLI без PostgreSQL:

```sh
uv run --project backend --frozen protocol-lab apply --model tests/fixtures/cli/length-model.json --capture tests/fixtures/framing/length-big.pcap --output /tmp/validation.json
```

Этап 10: [проверки](docs/review-stage-10.md), [повторение](docs/manual-stage-10.md), [пределы и измерения](docs/reliability.md).
