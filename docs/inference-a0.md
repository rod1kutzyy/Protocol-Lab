# Автоматический анализатор — A0

Реализован фундамент [ТЗ](automatic-analyzer-spec.md): строгие локальные контракты,
выборка/split и исправление обработки технических пределов. Поиск кандидатов,
процессные inference jobs и их PostgreSQL-публикация относятся к A1 и последующим
поставкам. `capabilities` явно возвращает `analysis_available=false`; endpoints
запуска ещё не существуют. Миграция БД не требуется, runtime revision — прежняя
`0006_validation`; пользовательские проекты и старые результаты не пересчитываются.

## Контракты

Код: `backend/src/protocol_lab/inference/models.py`, `document.py`, `sampling.py`.
Pydantic запрещает неизвестные свойства, числовые бюджеты принимают только целые
(не bool/float), правила — закрытый discriminated union. JSON loader отвергает
повторные свойства, NaN/Infinity, чрезмерную вложенность и документ >512 KiB.
Формулы и преобразования — данные конечного языка, не код для исполнения.

Локальные JSON Schema доступны в [schemas/inference](schemas/inference/spec.schema.json):

| Schema name | Содержание |
| --- | --- |
| `spec` | `inference-spec-1`: corpus version, discovery/evaluate, детекторы, ограничения, split, sampling/seed, logs/clocks, параметры |
| `snapshot` | Corpus/source/reconstruction versions и hashes, точные model/framing документы, engines, sample anchors |
| `rule` | `inference-rule-1`: все семейства кандидатов из ТЗ; это описание, не обещание работающего детектора |
| `candidate` | Canonical rule/hash, scope, зависимости, метрики, ranking components, обоснование и compiler support |
| `run` | Исторический snapshot, обязательный outcome каждого детектора, coverage и completeness |
| `evidence` | Пятёрка статусов исполнения, stream/source anchors, event references, preview до 64 bytes |
| `evaluation` | Зафиксированный rule hash, новый snapshot, метрики и явный статус независимости проверки |
| `decision` | Решение инженера с причиной, idempotency token и ссылками на созданные версии |
| `transform` | Отдельное соответствие Base64 source/decoded ranges разной длины |

Для каждого selected capture snapshot обязателен, включая не восстановленные записи.
Проверяются принадлежность corpus/project, версии модельных документов и их hashes,
уникальность stream IDs и владельцев sessions. Sample/excluded anchors должны
укладываться в конкретный frozen stream и reconstruction version. Sample не может
содержать holdout или excluded bytes.

`eligible = matched + contradicted + unknown + ambiguous`; `not_applicable` учтён
отдельно. Ranking denominator содержит только проверяемые matched/contradicted.
Coverage делит extent на selected/excluded и selected на known/unavailable/ambiguous.
`unframed_bytes` — overlay, а не дополнительное слагаемое. Score не называется
вероятностью. Непроверенные и технически недоступные данные не маскируются успехом.

Offsets в `IntegerLocation` и checksum coverage относятся к началу сообщения.
Для `RegionRule(relative_to=message_start)` диапазон — `[start+offset,
start+offset+length)`, для `message_end` — `[end-offset-length,end-offset)`.
В `TransformMapping` source ranges — абсолютные stream offsets, decoded ranges —
смещения в производном блоке от нуля. Sample anchors всегда stream-relative,
а `FramingSpec.start` сохраняет существующую семантику абсолютного offset потока.

## API без PostgreSQL

| Endpoint с префиксом `/api/v1` | Результат |
| --- | --- |
| `GET /inference/capabilities` | A0, contract version, доступность детекторов, defaults и имена схем |
| `GET /inference/schemas/{name}` | Draft 2020-12 JSON Schema выбранного контракта |
| `POST /inference/spec/check` | `{document_json}` → valid/issues и нормализованный spec |

`spec/check` проверяет синтаксис и внутренние ограничения, но **не** существование
UUID в БД, принадлежность журналов или фактическую целостность sources:
`scope_verified=false` остаётся явным. Проверка полного контекста начинается
с `InferenceSnapshot`; чтение и авторизация project records будут добавлены в A1.
Неизвестное schema name — 422; плохой JSON внутри `document_json` — valid=false
с путём/причиной; слишком большое HTTP-поле — 422.

Контракты HTTP отражены в `docs/openapi.json` и сгенерированных TypeScript types.
Все schema snapshots обновляются штатным `scripts/export_openapi.py`.

## Воспроизводимая выборка

`select_sample` принимает bounded metadata уже размеченных сообщений, без byte reader.
Один вызов используется для выбранного варианта framing. Сначала проверяются scope,
владельцы streams/sessions, reconstruction version, offsets и input-unit budget.

- Explicit split — по целым captures или sessions. Discovery/holdout не пересекаются,
  вместе охватывают все выбранные единицы. Отсутствие holdout требует причины.
- Captures с одним SHA-256 и явно заданные группы одной записи не могут оказаться
  по разные стороны split. Нераспознанное перекрытие разных captures ещё не
  обнаруживается автоматически: независимость должна дополнительно проверяться в A1.
- Берутся только discovery и known units; holdout/unknown/excluded считаются отдельно.
  При пересечении excluded bytes сообщение исключается целиком, не обрезается.
- Одинаковые payload hashes дедуплицируются для discovery; все их source occurrences
  сохраняются, а не выдаются за независимые новые сообщения. Полная evaluation
  впоследствии должна проверить весь явно выбранный корпус.
- Внутри capture/session/direction buckets порядок задаётся SHA-256 от seed и
  canonical metadata, затем применяется round-robin. Результат не зависит от
  порядка входного итератора. Есть semantic hash и число невыбранных unique units.

Стартовые limits и search ranges сериализуются в spec и публикуются capabilities.
Для ещё не реализованных детекторов это `budget_profile=unbenchmarked_a0`:
они не означают измеренную скорость exhaustive search или свойства протокола.

Базовый metadata-only замер: 100000 units, 2 captures, 20 sessions, 40 directed
streams; выбрано 5000 discovery units, 50000 holdout units не использованы в поиске.
На macOS ARM64 / Python 3.12.15: подготовка 0,638 s, выборка 0,748 s,
повтор с обратным порядком 0,844 s, peak RSS процесса 255,234 MiB.
Semantic hashes и полные selections совпали. Это проверка bounded metadata sampling,
не замер TCP/детекторов, не Linux-профиль 4 vCPU/8 GiB и не SLA всего приложения.
[JSON замера](benchmarks/inference-a0-sampling.json); воспроизведение:

```sh
backend/.venv/bin/python scripts/benchmark_inference_sampling.py --units 100000
```

## Исправление технических лимитов R3/R4

Новые версии движков: `framing-v2`, `interpretation-v2`, `validation-v3`.
Версии DSL `framing-1`/`interpretation-1` не меняются.

| Случай | Новый результат |
| --- | --- |
| Отрицательная вычисленная длина/count | Failed, `negative_computed_length_or_count` |
| Count > `max_array_items` | Unknown, `max_array_items_exceeded` |
| Размер > `max_message_bytes` | Unknown, `max_message_bytes_exceeded`; для фрейминга — отдельный leftover |
| Число полей > `max_decoded_fields` | Unknown, `max_decoded_fields_exceeded` |
| Константа/диапазон/длина не соответствует модели | По-прежнему Failed |
| Unknown/ambiguous source data | По-прежнему Unknown/Ambiguous с приоритетом неопределённости |

Необязательное `technical_limit` сохраняет `name`, точные десятичные строки
`observed`/`maximum` и `observed_is_lower_bound`. Последнее используется, когда
неизвестна полная длина сообщения, но для продолжения поиска нужен хотя бы ещё байт.
Отображение нижней границы не выдаёт её за измеренную длину сообщения.

Метаданные проходят до framing pieces, interpretation results/summaries и corpus
results/summaries; GUI показывает объяснение, CLI — тот же структурированный JSON.
Извлечённые до остановки поля и непотреблённые диапазоны сохраняются с provenance.
Сравнение запусков учитывает изменение `technical_limit` отдельно от значений полей.

Отсутствующий end marker теперь различает:

- `end_marker_search_limit_exceeded` — дальнейший поиск остановлен ресурсным пределом;
- `end_marker_search_interrupted_by_unknown_bytes` — поиск прерван разрывом/конфликтом;
- `end_marker_not_found_before_stream_end` — достигнут конец известных данных.

Length-framer различает `invalid_length_no_resynchronization` и
`max_message_bytes_exceeded_no_resynchronization`. Остаток всего потока остаётся видимым;
ресурсный предел не становится контрпримером предполагаемому протоколу.

Старые JSONL/DB metadata без `technical_limit` читаются с `null`. Сохранённые версии,
старые diagnostic codes и statuses остаются прежними. Новые versioned identities
не перезаписывают старые framing/interpretation runs. Старые validation runs
отмечаются stale существующей проверкой engine versions. Snapshot revision и
формат bundle не менялись: добавлены совместимые поля JSON, новых таблиц нет.

## Проверки

`tests/test_inference.py` проверяет схемы, unsafe/ambiguous documents, закрытые
rules, source/split invariants, deterministic sampling и работу API без DB.
Контрактный пример: `tests/fixtures/inference/a0-spec.json` (синтетические UUID,
не ссылки на уже существующие пользовательские captures).

Регрессии limits/negative lengths/Construct wrapping, framing causes и старых
результатов находятся в `test_interpretation.py`, `test_framing.py`,
`test_validation.py`, `test_portability.py`. Настоящий PostgreSQL-тест
`test_a0_resource_limits_publish_as_unknown_with_exact_diagnostics` проверяет
публикацию, summaries, повтор с повышенным бюджетом и restart без изменения старого run.

Этот этап создаёт основу реализации. Автоматические marker/length предложения,
inference persistence/jobs и их полноценный UI появятся в A1.

## Результат проверки 15 октября 2026 года

- Полный backend-набор: **286 passed**, включая настоящую PostgreSQL-интеграцию.
  Использован отдельный временный PostgreSQL 17 без пользовательских volume mounts;
  тесты создавали и удаляли собственные UUID-схемы.
- Vitest: **19 passed**, 7 файлов. TypeScript и Vite build — успешно.
- Playwright: **6 passed**, включая полный research → counterexample → revision
  → export/restore → new-capture CLI и регрессии рабочей области.
- Ruff check/format, проверка diff whitespace, локальных ссылок и schema snapshots
  — успешно. Schema snapshots проверяются на равенство Pydantic-генерации.
- Sampling benchmark: 100000 metadata units, 5000 выбранных, одинаковый результат
  при обратном порядке входа; границы измерения описаны выше.

В ходе прогона исправлена нестабильность существующего теста
`test_stage10_configured_limits_preserve_published_research`: observations API
сортирует записи по UUID, поэтому сравнение только первой записи с заранее выбранным
наблюдением было случайным. Теперь проверяется точное сохранение всего списка.

Нефатальные предупреждения: существующий Starlette/httpx deprecation,
Vite о размере Monaco chunk, source map bundled marked и NO_COLOR/FORCE_COLOR.
Нативный контрольный Linux workload анализатора не выполнен; детекторы ещё отсутствуют.
