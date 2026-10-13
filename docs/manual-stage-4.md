# Ручная проверка этапа 4

Установите зависимости и запустите PostgreSQL/API по [инструкции этапа 3](manual-stage-3.md).
С уже работающим проектом обязательно примените новую добавляющую миграцию
при настроенном `.env` в корне проекта (загружается автоматически):

```sh
uv run --project backend --frozen alembic -c backend/alembic.ini upgrade head
```

Перезапустите API. Откройте Swagger: http://127.0.0.1:8000/docs.
В UI http://127.0.0.1:5173 можно наблюдать jobs и отменять их; просмотр TCP
в пользовательском интерфейсе предусмотрен этапом 5.

1. Создайте project через POST `/api/v1/projects`.
2. Импортируйте `tests/fixtures/tcp/gaps-overlaps.pcap` через POST
   `/projects/{project_id}/captures` с checksum_policy=warn. Дождитесь succeeded
   через GET `/jobs/{job_id}` и сохраните result.capture_id.
3. POST `/captures/{capture_id}/reconstruct` с телом `{}`. Это отдельная фоновая
   задача. Дождитесь succeeded: result.session_count=1, version=tcp-v1.
4. GET `/captures/{capture_id}/sessions`. Одна сессия, start_known=true,
   roles_known=true, endpoint A=192.0.2.1:41000, B=192.0.2.2:9000.
   Направление a_to_b имеет extent=13. Сохраните его stream id.
5. GET `/streams/{stream_id}/bytes?offset=0&length=13`. Ожидается:
   known `ABC` в [0,3), ambiguous `D`/`X` в [3,4), known `E` в [4,5),
   gap [5,8), known `IJ` в [8,10), truncated [10,13).
   Known spans могут делиться дополнительно при смене набора источников.
   Gap/truncated не имеют вариантов bytes; нулей вместо пропусков нет.
6. Выберите любой source: GET `/packets/{packet_id}`. packet_index и смещения
   совпадают с packet record. file_offset указывает начало именно выделенного
   диапазона в оригинале; packet_payload_range — относительно TCP payload.
   GET bytes с offset=1,length=2 возвращает `BC`, с обрезанными source ranges.
7. POST `/projects/{project_id}/observations`, заменив stream_id:

   ```json
   {
     "text": "В перекрытии наблюдаются разные байты",
     "anchors": [{
       "stream_id": "ВАШ-UUID-ПОТОКА",
       "reconstruction_version": "tcp-v1",
       "byte_range": {"start": 2, "end": 5}
     }]
   }
   ```

   Ответ 201 содержит anchors и автоматически созданные sources обоих вариантов.
   GET `/projects/{project_id}/observations` показывает сохраненное наблюдение.
8. Повторите reconstruct с `{}`: outcome=already_reconstructed, IDs не меняются.
   Остановите/запустите API. Потоки, ranges и observations остаются доступны,
   jobs сбрасываются. Повторный импорт этого же capture также сохраняет его ID.
9. В тот же project импортируйте остальные эталоны и выполните reconstruct:

   | Файл в tests/fixtures/tcp | Ожидание |
   | --- | --- |
   | ordered.pcap | A→B HELLOWORLD, B→A OK |
   | reordered-retransmitted.pcap | HELLOWORLD без удвоения, все повторные источники |
   | wrap-fin.pcap | ABCD, extent=4, SYN/FIN не видны как bytes |
   | reused-tuple.pcap | Две разные сессии с OLD и NEW |
   | midstream.pcap | HELLOWORLD, start/roles неизвестны |
   | isolated-ambiguous.pcap | GOOD доступен; другая сессия имеет sequence диагностику |
   | syn-fin-retransmitted.pcap | Одна закрытая сессия, ONE без дублирования |

10. Для проверки отмены запустите повторный reconstruct большой записи и отмените
    queued/running через `/jobs/{id}/cancel`. После cancelled result=null, прежде
    сохраненные потоки остаются доступны. Маленькие fixtures завершаются слишком
    быстро для гарантированной ручной отмены; этот случай покрыт автоматическими тестами.

Политики, ограничения и неопределенности: [tcp-reconstruction](tcp-reconstruction.md).
Для независимой проверки при установленном локальном TShark:

```sh
uv run --project backend --frozen python scripts/check_tcp_with_tshark.py
```
