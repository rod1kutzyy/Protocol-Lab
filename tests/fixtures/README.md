# Детерминированные источники

Все записи синтетические, с адресами TEST-NET 192.0.2.1/2, TCP ports 41000/9000
и payload HELLO/WORLD. Личного трафика нет. Воспроизводимый генератор:
`backend/.venv/bin/python scripts/generate_capture_fixtures.py`.

| Fixture | Сценарий |
| --- | --- |
| ordered.pcap | Два Ethernet/IPv4/TCP пакета, корректные checksums |
| big-endian-nano.pcap | Big-endian PCAP и nanosecond timestamps |
| mixed-diagnostics.pcap | Good, invalid TCP checksum, truncated payload, malformed headers |
| vlan.pcap | Ethernet 802.1Q, payload offset 58 |
| raw-ip.pcap | Raw IPv4, payload offset 40 |
| unsupported-link.pcap | Неподдерживаемый linktype 999 |
| multi-interface.pcapng | Две секции с разным endian, два linktypes/tsresolutions и tsoffset |
| simple-packet.pcapng | SPB без timestamp |
| expected.json | Независимые ожидаемые байты/offsets/timestamps ordered.pcap |

Fixtures не игнорируются .gitignore и входят в исходный комплект проекта.
Тесты также создают malformed containers и binary timestamp fixtures в temp.
TCP-сессии/восстановление и action logs проверяются на следующих этапах.


## TCP — этап 4

`tcp/*.pcap` создаются `scripts/generate_tcp_fixtures.py`, ожидаемые результаты
описаны в `tcp/expected.json`. Только synthetic TEST-NET IPv4 traffic.
Сценарии: ordered/two directions, reorder и retransmissions, gaps/conflicts/truncation,
wrap/SYN/FIN, reused tuple, absent start, isolated sequence ambiguity, checksum,
delayed SYN, control retransmissions, simultaneous open и missing prefix.

## Журналы этапа 5

`actions/clock-offset.csv`: mapping when/operation/args, Unix seconds. Для tcp/ordered.pcap
поправка -1000000000 ns даёт кандидата строки 1; допуск 1 ms добавляет строку 2.
Строка 3 намеренно имеет некорректное время и сохраняется как диагностика.
`actions/exact.json`: ISO timezone, 9 дробных цифр и вложенные параметры для exact parsing.
Все данные синтетические.

## Фрейминг этапа 6

`framing/length-big.pcap`, `length-little.pcap`: uint16 payload length, total=raw+2,
три сообщения [0,5), [5,12), [12,15); первое поле длины пересекает границу пакетов.
`framing/markers.pcap`: start AABB/end CCDD, сообщения [5,12), [12,21),
prefix/suffix 5+4 bytes. `length-incomplete.pcap`: сообщение [0,5) и неполный
остаток [5,8). Генератор scripts/generate_framing_fixtures.py; все данные синтетические.

## Интерпретации (этап 7)

`interpretation/arrays-variants.pcap`: три сообщения с uint16 big endian длиной
тела, затем count, повторяющиеся tag и body. Tag=1 — signed int16 little endian,
tag=2 — два bytes. Count=2,1,0; значения -2, AB, 4660.
`arrays-new-parameters.pcap`: новая запись с count=1, tag=2, CD; та же модель.
Заголовки и поля пересекают TCP-пакеты, несколько сообщений находятся в одном пакете.
Генератор: `backend/.venv/bin/python scripts/generate_interpretation_fixtures.py`.

## CLI (этап 9)

`cli/length-model.json` — reusable length-field DSL с намеренной constant n=3.
`cli/expected.json` — ожидаемые full-capture message counts/stream bytes для
length-big, новой arrays-new-parameters записи и length-incomplete.
Модель показывает counterexamples на новых параметрах, без filename/action shortcuts.
Команда и output format: [portability](../../docs/portability.md).
