# Детерминированный корпус inference

Генератор: `scripts/generate_inference_fixtures.py`. Все источники синтетические;
PCAP headers, TCP tuples и timestamps задаются генератором framing fixtures.

A4 message: `AA BB`, uint16 little-endian полной длины, uint8 counter,
payload переменной длины, uint32 little-endian CRC-32/ISO-HDLC всех предыдущих
байтов сообщения. Payload = SHAKE-256 строки `a4:index:size`. CRC fixture
генерируется независимым `zlib.crc32`.

- `crc-discovery.pcap`: payload sizes 3,7,4,9,5,11; cuts 1,5,21.
- `crc-holdout.pcap` / `.pcapng`: sizes 13,8,17,6; cuts 3,26.
- `crc-counterexample.pcap`: sizes 15,6,12,10; последняя checksum XOR 1.
- `crc-resegmented.pcap`: те же application bytes discovery, cuts 4,16,37,61;
  это та же передача, а не независимое подтверждение.
- `a4-model.json`: executable interpretation-2 с length, CRC и corpus counter.

Каждое сообщение занимает `[cursor,cursor+payload_size+9)`. Counter — offset 4,
payload — `[5,message_length-4)`, checksum — последние четыре байта. TCP cuts
не являются границами сообщений; точные packet/payload ranges восстанавливаются
обычным shared engine. Правильная checksum должна попасть в первые пять своего
семейства. Holdout проходит без подбора; counterexample даёт ровно одну локальную
ошибку checksum. Счётчик начинается с 0 в каждом отдельном stream; первый переход
неизвестен, остальные +1.
