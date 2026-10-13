# Проверка этапа 10

Этап 9 одобрен. Этап 10 готов к ревью; production launcher — этап 11.
Все сценарии ниже используют синтетические captures и новые UUID schemas.
Пользовательские базы, каталоги и captures не нужно очищать или переносить.

## Локальный набор

После установки зависимостей из lockfiles:

```sh
uv run --project backend --frozen ruff check backend scripts
uv run --project backend --frozen ruff format --check backend scripts
uv run --project backend --frozen python scripts/check_tcp_with_tshark.py --output output/stage10/tshark.json
```

TShark нужен только для независимой проверки, runtime приложение от него не зависит.
При его отсутствии скрипт явно завершится с сообщением о невыполненной сверке.
Сравниваются frame lengths/time, IPv4 адреса, TCP ports/sequence/ack/flags/length,
оригинальные payload из exact file offsets на 27 применимых fixtures (131 packet).
Исключения и версия TShark указаны в JSON; совпадение заголовков не доказывает
семантику протокола и не заменяет TCP reconstruction tests.

Выберите **тестовый** PostgreSQL на localhost. Например, отдельный контейнер:

```sh
docker run --detach --name protocol-lab-stage10-check-db --publish 127.0.0.1:55440:5432 --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=protocol_lab_test postgres:17
export PROTOCOL_LAB_TEST_DATABASE_URL=postgresql+psycopg://postgres@127.0.0.1:55440/protocol_lab_test
uv run --project backend --frozen pytest backend/tests
npm --prefix frontend test
npm --prefix frontend run build
```

Integration tests создают/мигрируют/удаляют только собственные UUID schemas.
Без TEST_DATABASE_URL они будут skipped, это не считается полной проверкой.

## Полный Playwright сценарий

```sh
cd frontend
npx playwright install chromium
cd ..
uv run --project backend --frozen python scripts/run_e2e.py
```

Runner создаёт две UUID schemas, применяет миграции и даёт Playwright отдельные
временные roots. Порты 18000/15173 и 18001/15174 должны быть свободны. Обычный
`npm run test:e2e` без специальных E2E переменных запускает диагностический тест;
research test явно skipped и API не использует пользовательский `.env` database URL.

Сценарий проверяет через UI:

1. Создание проекта, PCAP import, реальное соединение, HEX и exact source packet.
2. Наблюдение; CSV field mapping; два действия с разными параметрами; manual evidence link.
3. Length framing; Monaco JSON-модель; гипотеза с наблюдением; versioned corpus.
4. Один Passed / два Failed; конкретный counterexample и переход к его bytes.
5. Новая immutable model version; stale старого run; три Passed; сравнение статусов.
6. Reload и сохранённый evidence link; ZIP, model JSON и Markdown downloads.
7. Физическая недоступность прежнего root; UI restore в другую DB/root;
   прежние source IDs/bytes/provenance/run coverage.
8. CLI применяет скачанную модель к другой записи с новым параметром.

Тест использует настоящие API/DB/worker processes, без mocks. Проверяются отсутствие
page errors и внешних HTTP-запросов страницы. Screenshots/downloads лежат в ignored
`frontend/test-results/.../artifacts/`, trace сохраняется при сбое. Это проверка
отсутствия online requests, а полный production offline запуск относится к этапу 11.

## Контрольный профиль Linux

```sh
docker build --platform linux/amd64 --file scripts/Dockerfile.benchmark --tag protocol-lab-stage10-benchmark .
mkdir -p output/stage10-linux
docker run --rm --platform linux/amd64 --cpus 4 --memory 8g --memory-swap 8g --network none --volume "$PWD/output/stage10-linux:/results" protocol-lab-stage10-benchmark
```

Каталог результата должен быть новым: существующий capture/JSON не перезаписывается.
Образ фиксирует Python image digest и uv; зависимости берутся из committed uv.lock.
Первая сборка требует сети, сам прогон — нет. Для быстрой проверки генератора:

```sh
uv run --project backend --frozen python scripts/benchmark.py --profile smoke --output output/stage10-smoke
```

Нужны все шесть measurements и `reproducible=true` в benchmark.json. Assert проверяет
250000 packets, 1000 connections, 100000 messages, максимальный размер 65536,
полное покрытие 83356000 application bytes и точные повторные результаты/provenance.
Контрольный capture и большие JSON остаются в ignored output, маленькие отчёты —
в [docs/benchmarks](benchmarks/stage10-linux.json). Границы эмуляции/RSS: [reliability](reliability.md).

## Полное хранение на том же корпусе

После Linux core прогона, с TEST_DATABASE_URL:

```sh
uv run --project backend --frozen python scripts/benchmark_storage.py --workload output/stage10-linux --output output/stage10-storage
```

Новый output обязателен. Runner создаёт/удаляет две UUID schemas и измеряет реальные
PostgreSQL publication/validation/reads/snapshot/ZIP/verify/restore. Restore проверяет
100000 Passed и source bytes при переименованном исходном root. benchmark.json
содержит время, RSS и 20 samples чтения bytes/packet/run. Файлы синтетического
исследования остаются в ignored output для инспекции; пользовательская БД не используется.

После проверок можно остановить **созданный выше** контейнер:

```sh
docker stop protocol-lab-stage10-check-db
docker rm protocol-lab-stage10-check-db
```

Прочие пользовательские сервисы не останавливаются.
