# Этап 2 — материал для ревью

Ревью успешно завершено пользователем; далее начат этап 3.

Все пункты 2.1–2.9 реализованы в пределах архитектурного этапа.
Этап 1 пропущен по запросу; этап 3 не начат. Отметки в PLAN означают завершение
реализации, **не** одобрение ревью.

| Пункт | Результат |
| --- | --- |
| 2.1 | backend/frontend/tests/docs/scripts, пакеты по границам ядра |
| 2.2 | Python 3.12, pyproject.toml, backend/uv.lock |
| 2.3 | React + TypeScript + Vite, npm, frontend/package-lock.json |
| 2.4 | Tailwind Vite plugin, shadcn-style Button и components.json, Query/Zustand/Virtual, локальный Monaco |
| 2.5 | Импорт, TCP, фрейминг, интерпретация и валидация разделены пакетами и domain ports; алгоритмы последующих этапов не реализованы |
| 2.6 | Domain records всех сущностей, стабильные source/stream anchors и версии |
| 2.7 | Живой OpenAPI для текущих routes + generated TypeScript; будущие REST-контракты описаны отдельно |
| 2.8 | Spawn-процессы, ограниченная очередь, прогресс, SSE/reconnect, отмена, диагностика сбоя |
| 2.9 | API 127.0.0.1:8000 и UI 127.0.0.1:5173 проверены в Chromium |

## Результаты проверки, 11 октября 2026

- `uv sync --project backend --frozen --offline`: успешно (с предварительно заполненным cache).
- `npm ci --offline`: успешно (с предварительно заполненным cache).
- Ruff check и format --check: успешно.
- pytest: **12 passed** — диапазоны/пути/IPv4/неизменяемость, worker success,
  SSE terminal/reconnect, running/queued cancel, limits, worker crash, invalid input.
- `npm run build`: успешно, TypeScript + production Vite build.
- `npm test`: **2 passed**, статусы задач и передача ошибки API.
- `npm run test:e2e`: **1 passed**, Chromium, реальные localhost-серверы,
  создание/завершение/отмена задач и локальный Monaco; внешние HTTP-запросы отсутствуют.
- npm audit после обновления Vitest: **0 vulnerabilities**.

В проверочном окружении cache размещались в `/tmp/protocol-lab-uv-cache` и
`/tmp/protocol-lab-npm-cache`, браузер в `/tmp/protocol-lab-browsers`.
Для браузерного прогона задавался `PLAYWRIGHT_BROWSERS_PATH`. Это не runtime-настройки
приложения. Sandbox потребовал разрешённый запуск localhost-серверов и Chromium.

## Ограничения и предупреждения

- PostgreSQL schema/migrations, capture import, framing/parser/validation engine
  ещё не реализованы: соответствуют следующим этапам.
- Диагностика worker — проверка инфраструктуры, не исследовательский результат.
- Registry jobs в памяти, до 128 записей, один API worker; рестарт сбрасывает список.
- Vite предупреждает о размере Monaco chunk (~2.3 MB до gzip). Основной JS bundle
  ~328 KB; редактор загружается при открытии панели. Оптимизация ресурсов и
  production-раздача относятся к этапам 10–11.
- Starlette предупреждает об устаревании TestClient с httpx; тесты проходят.
- Проверки выполнялись на macOS ARM64. Контрольная Linux-нагрузка, PostgreSQL,
  перенос проекта и полный сценарий R1–R6 пока не проверялись.

Для ревью: границы ядра и сущностей, диапазоны/provenance, проект будущих
REST-контрактов, жизненный цикл задач и поведение UI при отмене.
Инструкция ручного запуска находится в README.md.
