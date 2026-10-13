# Этап 4 — материал для ревью

Ревью одобрено пользователем; далее приведён исторический отчёт этапа 4.

Реализованы 4.1–4.11. Этапы 2/3 одобрены пользователем; этап 5 не начат.
Отметки PLAN обозначают реализацию, а не одобрение этого ревью.

- Ядро `tcp/reassembly.py`: соединения, направления, SYN/FIN/wrap, reorder,
  retransmissions, gaps/truncation и все конфликтующие источники; изоляция ошибки
  направления, явные неизвестные начало/роли/межинтерфейсная идентичность.
- `storage/reconstruction.py`, миграция `0002_tcp_reconstruction`: immutable derived
  artifact с SHA-256, PostgreSQL-индекс диапазонов, конкурентная публикация,
  точные source mappings и стабильные observations.
- `services/reconstruction.py`, расширение jobs: отдельный process job с progress,
  SSE/отменой и транзакционной publication; исходники/прежние результаты доступны.
- `api/tcp.py`, packet-by-id: восстановление, session/stream metadata, ограниченный
  range JSON с variants и provenance, создание/чтение observations.
- Ingestion: убран рекурсивный разбор неизвестных Ethernet/IP протоколов,
  добавлен regression test с вложенным Ethernet рядом с хорошим пакетом.
- Обновлены OpenAPI/TypeScript, описание текущего этапа в UI и инструкция запуска
  с фактическим именем `docker-compose.yml`; сообщение 503 указывает верную env variable.
- Synthetic TCP PCAP fixtures, generator, expected bytes и независимая сверка TShark.

Проверки 11 октября 2026:

- pytest: **57 passed**, включая **11 настоящих PostgreSQL integration tests**.
  PostgreSQL 17 в отдельном tmpfs Docker на localhost:55432; каждая проверка создает
  свою UUID schema и удаляет только ее. Проверены совместимые migration upgrade и
  alembic check, upgrade заполненного проекта этапа 3 без изменения исходника/manifest, restart, source integrity, range clipping, scope/version anchors,
  duplicate/concurrent reconstruction, отмена и сохранение прежнего результата.
- TCP unit tests: **18** сценариев, включая SYN/FIN retransmission, wrap, reuse,
  simultaneous open, delayed SYN, полностью усеченный payload и дефект рядом с GOOD.
- Ruff check / format --check: успешно.
- TypeScript/build: успешно; Vitest **2 passed**.
- Playwright/Chromium: **1 passed**, существующая UI jobs/SSE/отмена/локальный Monaco,
  без внешних запросов. GUI просмотра TCP не заявляется на этом этапе.
- TShark: независимо совпали sequence numbers, declared lengths и исходные payload
  **28 пакетов** из ordered, reordered/retransmitted, wrap и reused tuple.

[Ручное ревью через Swagger](manual-stage-4.md).
[Алгоритм, форматы и защитные лимиты](tcp-reconstruction.md).

Ограничения: не доказуемые по записи границы соединений/межинтерфейсная идентичность
диагностируются, sequence extent >=2^31 не угадывается. Изменение уже опубликованных
настроек не переписывает версию. Проверка каждого range читает source для SHA-256.
Контрольный Linux workload, peak RSS и большие authentic captures еще не проверялись
(этап 10); полный portable export — этап 9. Сохранились прежние предупреждения
Monaco chunk size и Starlette TestClient/httpx; тесты проходят.
