# Ручная проверка этапа 3

## Установка и PostgreSQL

Нужны uv, Python 3.12, Node.js/npm; PostgreSQL 17 (для предоставленного dev
варианта — запущенный Docker Desktop). Если есть своя PostgreSQL, используйте
отдельную новую БД и пользователя, указав её URL, без сброса прежней БД.

Из корня репозитория:

```sh
uv sync --project backend --frozen
cp -n .env.example .env
```

В `.env` замените `CHANGE_ME` в двух местах на свой пароль. Для простого shell
запуска используйте буквенно-цифровой пароль; специальные символы в URL должны быть
percent-encoded. Файл `.env` не попадает в git.

```sh
docker compose -f docker-compose.yml up -d
uv run --project backend --frozen alembic -c backend/alembic.ini upgrade head
uv run --project backend --frozen uvicorn protocol_lab.api.app:app --host 127.0.0.1 --port 8000
```

API и Alembic автоматически читают `.env` из корня проекта. Экспортированные
переменные окружения имеют приоритет. Относительный PROJECT_ROOT считается от
каталога `.env`, независимо от текущего каталога терминала.
Если порт 5432 уже занят, используйте отдельный свободный порт в compose и URL.
Не подключайте приложение к чужой исследовательской схеме для экспериментов.

Во втором терминале:

```sh
cd frontend
npm ci
npm run dev
```

UI: http://127.0.0.1:5173. Jobs появятся в существующей панели задач.
Экран импорта из браузера появится на этапе 5; сейчас операции выполняются через
Swagger http://127.0.0.1:8000/docs или REST-клиент.

## Проверка через Swagger

1. POST `/api/v1/projects`, Try it out: `{"name":"Ручное исследование"}`.
   Сохраните `id`. В `projects/<id>/` появится `manifest.json` и директории.
2. POST `/api/v1/projects/{project_id}/captures`. Выберите
   `tests/fixtures/ordered.pcap`, checksum_policy=`warn`, Execute. Ответ 202 содержит job `id`.
3. GET `/api/v1/jobs/{job_id}` до status=`succeeded`. Результат содержит
   `outcome=imported`, capture_id, packet_count=2. Через UI можно выбрать эту задачу,
   посмотреть прогресс/JSON. Для маленькой записи промежуточный прогресс может пройти быстро.
4. GET `/api/v1/captures/{capture_id}`: hash, relative_path, settings, engine_version.
   GET `/api/v1/captures/{capture_id}/packets`: первый payload_offset=54,
   file_offset=40, payload_length=5, tcp_sequence=100; timestamp_ns — строка.
5. POST `/api/v1/captures/{capture_id}/verify`: ожидается `status=verified`.
   Сравните оригинал и копию командой `cmp tests/fixtures/ordered.pcap projects/<project_id>/sources/<sha256>.pcap`.
6. Повторите импорт того же файла с checksum_policy=`ignore`: `already_imported`,
   **тот же** capture_id, прежний checksum_policy=`warn`; requested_checksum_policy=`ignore`.
   В GET captures остаётся одна запись.
7. Импортируйте `mixed-diagnostics.pcap` с warn: 4 пакета, в diagnostics видны
   неверный TCP checksum, усечение и malformed headers. Хороший пакет доступен.
   С policy=reject сравнивайте в **другом проекте**, поскольку duplicate import
   намеренно не переписывает ранее сохранённую policy.
8. Импортируйте `multi-interface.pcapng`: 3 пакета, два интерфейса и две секции,
   разные timestamp resolutions и offset. `simple-packet.pcapng`: timestamp=null.
9. Остановите API Ctrl+C и запустите с теми же переменными снова. GET projects,
   captures и packets возвращают прежние данные; список jobs сброшен.

Отмена больших импортов: POST `/jobs/{id}/cancel` во время queued/running.
Итог cancelled, result=null, capture не появляется. Во время committing отмена
уже закрыта; запрос вернёт committing, затем succeeded/failed. Для воспроизводимых
проверок отмены предусмотрены интеграционные тесты; маленький fixture может
завершиться до ручного запроса отмены.

Чтобы остановить PostgreSQL без удаления данных:

```sh
docker compose -f docker-compose.yml stop
```

Не выполняйте `down -v`, reset или downgrade: это удалит/повредит сохранённую БД.

## Автоматические проверки

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

Без тестового URL PostgreSQL integration tests явно skipped. Для полного прогона
задайте `PROTOCOL_LAB_TEST_DATABASE_URL=postgresql+psycopg://...` на отдельную тестовую
БД, где разрешено CREATE SCHEMA. Каждый тест создаёт уникальную `pl_test_<uuid>`
схему, применяет миграции и удаляет **только её**. Другие схемы не сбрасываются.
Пример: `PROTOCOL_LAB_TEST_DATABASE_URL="$PROTOCOL_LAB_DATABASE_URL" uv run --project backend --frozen pytest backend/tests`.
Для изоляции предпочтительна отдельная тестовая БД, не рабочая БД исследования.
