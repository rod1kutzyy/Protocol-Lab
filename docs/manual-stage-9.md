# Ручное ревью этапа 9

Этап 8 одобрен пользователем. Этап 9 закрывает перенос полного исследования R5
и отчёт/переиспользование R6. Нагрузочные и широкие end-to-end проверки этапа 10
начинаются после отдельного одобрения.

## Подготовка

Запустите PostgreSQL/API/UI по [manual-stage-8](manual-stage-8.md).
После изменения pyproject обновите editable install:

```sh
uv sync --project backend --frozen
```

Для полноценного отчёта выполните stage 8 сценарий (observation → hypothesis →
корпус → ошибочная модель → counterexample → revision → rerun).
Можно использовать `tests/fixtures/framing/length-big.pcap` и
`tests/fixtures/interpretation/arrays-new-parameters.pcap`.

## Сохранение, экспорт и повторное открытие

1. Откройте проект. В «Перенос и отчёт» дождитесь фоновой проверки целостности.
   Статус — `Завершена`, notice сообщает совпадение версии и checksums.
2. Нажмите «Сохранить полный снимок». После завершения появится относительный
   путь `checkpoints/<UUID>`. В нём есть bundle.json, manifest.json, metadata.jsonl,
   original sources и derived artifacts. Проверить без доступа к старой БД:

   ```sh
   uv run --project backend --frozen protocol-lab project verify --directory /absolute/path/checkpoint
   ```

3. Нажмите «Экспортировать проект ZIP» и «Скачать project.zip». ZIP содержит только
   выбранный проект: никаких credentials/DB URLs/старых абсолютных root paths.
4. Перезапустите API. Проект и ранее опубликованные downloads доступны;
   старый jobs registry сброшен. Снимок является отдельной сохранённой точкой истории.
5. При повреждении **копии** любого источника checksum check должен выдать явную
   ошибку, без восстановления выдуманных данных. Не меняйте свои research originals.

## Перенос на новый root и PostgreSQL

1. Используйте отдельную чистую DB; настройте destination `.env` и новый
   `PROTOCOL_LAB_PROJECT_ROOT`, примените Alembic head. Старый root должен быть
   недоступен (на собственной тестовой копии переименуйте каталог).
2. В боковой панели «Перенос проекта» выберите скачанный ZIP → «Восстановить проект».
3. После `Завершена` проект открывается автоматически, проходит checksum check.
   Проверьте:
   - Capture hash и точные stream/packet bytes, обе стороны connections;
   - observation anchors и links к источникам/действиям;
   - log mapping и clock offset/revision;
   - history model/hypothesis/corpus versions;
   - framing/parsing/validation runs, coverage, counterexamples и comparison;
   - stale marker старого run после новой модели/корпуса.
4. Повторите validation на сохранённой модели/корпусе. Facts совпадают; run ID/time новые.
5. Повторный импорт того же PCAP сообщает Already imported и сохраняет capture ID.
6. Повторное восстановление архива в эту же DB должно дать явную ошибку
   `Project identity already exists`, без merge и изменения существующего проекта.

CLI restore и зависимость от destination migrations описаны в [portability](portability.md).

## JSON и Markdown

1. В «Перенос и отчёт» выберите immutable interpretation version → «Скачать
   интерпретацию JSON». Это обычный DSL, пригодный для CLI.
2. Выберите validation run → «Экспортировать результаты JSON». Дождитесь задачи
   и скачайте validation.json. Проверяйте snapshot/coverage/results всех пяти статусов,
   включая unframed/excluded/uncertain результаты.
3. Нажмите «Сформировать Markdown-отчёт». Скачайте report.md. Он должен показывать
   основания гипотез, источник и hashes, модели/filters/engine versions,
   coverage, примеры/контрпримеры и exact packet/file/payload ranges,
   ограничения и открытые вопросы. Первые пять примеров каждого статуса указаны
   как выборка; полные результаты находятся в JSON/архиве.

## Повторное применение к новой записи

```sh
uv run --project backend --frozen protocol-lab apply \
  --model tests/fixtures/cli/length-model.json \
  --capture tests/fixtures/interpretation/arrays-new-parameters.pcap \
  --output /tmp/protocol-lab-new-validation.json
```

Ожидается 1 Failed message, n=4 (тестовая модель требует n=3), 6 stream bytes,
source provenance. Exit 0 — выполненная проверка с counterexample.
Для `framing/length-big.pcap`: 1 Passed / 2 Failed, 15 bytes.
Для `framing/length-incomplete.pcap`: 1 Passed, 8 bytes с видимым unframed остатком.
Не перезаписывайте прежний output: CLI откажется и сохранит предыдущий файл.

Сравните GUI с CLI на том же PCAP и модели, corpus без фильтров. Сопоставляйте
направления/ranges/значения/diagnostics/coverage; UUIDs/created_at между адаптерами
могут отличаться. Проверка CLI работает без PostgreSQL и HTTP.
