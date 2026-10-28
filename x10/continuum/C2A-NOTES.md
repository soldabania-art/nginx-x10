# C2a: предварительный контракт read-only probe

Статус на 2026-10-23: чтение выбранных upstream исходников и предложение
следующего эксперимента. Probe, pinned build, exporter и importer этим
документом **не реализованы**. Это дополнение к [OPENSSL-STATE.md](OPENSSL-STATE.md),
не полный inventory OpenSSL и не подтверждение переносимости соединения.

## Pin и первый профиль

Исследован upstream commit
[`85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c`][pin] (`openssl-3.0.13`).
Установленный Ubuntu binary имеет отдельные downstream patches; его private
layout нельзя считать соответствующим этому pin. C2a нужен отдельный build с
идентичностью source, patch, Configure/compiler flags, libcrypto/provider/config
и реально загруженного кода. Исторический pin — research reference.

Предлагаемый первый профиль: server, TLS 1.3/AES-128-GCM/SHA-256, fresh handshake,
один thread/I/O owner, один обычный socket BIO, read-ahead off, одна pipeline.
Нет resumption, early data, PHA, kTLS, async/engine, BIO filters и отправки tickets.
Probe вызывается вне SSL I/O call после успешной application read/write, до
следующей read. Источник приостановлен; probe не читает/flush socket и не вызывает
handshake. Байты в kernel queues допускаются только как сохранённое состояние
того же socket; это не доказательство отсутствия входящих данных.

## Что наблюдать внутри pinned library

Результат — allowlisted enums, lengths, boolean reasons и counters. Не копировать
структуры, pointers, EVP contexts, IV, traffic secrets или их fingerprints.

| Область | Точные поля/functions | Предлагаемая проверка и граница |
| --- | --- | --- |
| Ciphertext input | `rlayer.rstate`, `packet_length`, `rbuf.left/offset/len`; `RECORD_LAYER_read_pending()` | Нет partial packet и buffered input; состояние чтения на record header boundary. Проверять bounds отдельно. Одного `rbuf.left==0` недостаточно. |
| Processed records | `rlayer.numrpipes`, активные `rrec[i].type/length/off/read`; `RECORD_LAYER_processed_read_pending()` | Нет unread application **или control** record. Ненулевой `numrpipes` сам по себе не pending: прочитанный slot может сохраняться. |
| Output | `rlayer.numwpipes`, активные `wbuf[i].left/offset/len`, `wnum`, `wpend_tot/type/ret/buf`; `RECORD_LAYER_write_pending()` | Нет несданных BIO bytes и незавершённого API write. Для первого профиля запретить partial-write/moving-buffer modes. Сохранённые retry arguments не публиковать. |
| Handshake/control | `statem.state/hand_state/in_init/in_handshake/cleanuphand`, read/write substates/work, `enc_read_state/enc_write_state`; `init_num/init_off/init_buf`, `rlayer.handshake_fragment_len` | Требовать законченный основной flow (`MSG_FLOW_FINISHED`, `TLS_ST_OK`), действующие app ciphers, отсутствие активных fragments/work. Substates, offsets и `init_msg` могут быть остаточными: не объявлять любой ненулевой field обязательством. |
| Queued work | `key_update`, `s3.alert_dispatch`, `shutdown`, `ext.extra_tickets_expected`, `num_tickets/sent_tickets`, `post_handshake_auth`, `early_data_state` | Отклонять pending KU/alert/ticket/PHA/early-data и закрывающийся stream. Отключённые future tickets не отменяют уже построенные bytes. |
| Transport/retry | `rbio/wbio/bbio`, `rwstate`, `job/asyncrw`, pipeline/mode settings; wrapper ledger последнего SSL call | Подтвердить разрешённый BIO/profile и отсутствие конкурентного call или outstanding retry. BIO counters не описывают kernel queues; custom BIO здесь unsupported. |
| Record identity | `rlayer.read_sequence/write_sequence`, app-key installation events | Выводить next counters как fixed-width hex/decimal strings, без потери uint64 precision. Роль server связывает read с client traffic, write с server traffic. Generations требуют отдельной instrumentation ниже. |

Источники: [структуры SSL][ssl], [record structures][record],
[record predicates и read/write paths][layer], [state machine][statem].
Это список кандидатов для аудита gate, а не уже достаточное доказательство.

### Три важных ограничения на предикаты

1. В `ssl3_write_pending()` успешная запись обнуляет `wbuf.left`, но сохраняет
   `wpend_tot/wpend_buf/wpend_ret` и двигает `wbuf.offset`. Gate «всё равно нулю»
   отвергнет нормальное состояние. Различать активное обязательство и остаточные
   metadata; внешний API retry ledger не заменять проверкой pointer на NULL.
2. `tls_construct_key_update()` устанавливает `key_update=SSL_KEY_UPDATE_NONE`
   ещё при построении KU. Его send/flush и `tls13_update_key(s,1)` выполняются
   позднее. Getter NONE не подтверждает отсутствие KU obligation. Проверять
   state machine, pending buffers и retry вместе. При peer `update_requested`
   `tls_process_key_update()` планирует ответ и меняет read key отдельно.
3. `SSL_is_init_finished()` проверяет лишь `!in_init && hand_state==TLS_ST_OK`.
   `SSL_pending()` считает доступные app bytes, `SSL_has_pending()` использует
   read predicates. Ни один из этих getters не доказывает output/control/retry
   quiescence. Читать SSL ради получения «чистого» результата нельзя: это меняет
   наблюдаемое состояние.

Подтверждено в [write paths][layer], [KU processing][statem-lib],
[KU flush/update][statem-server], [init-state predicate][statem] и
[public pending wrappers][ssl-lib].

## Generations и независимое сопоставление

В выбранных структурах нет готового monotonic application-key generation counter.
`tls13_change_cipher_state()` и `tls13_update_key()` сбрасывают directional
sequence и меняют secret/cipher/IV. Предлагается monitor sidecar: initial app
installation и **успешный** KU отдельно для read/write, плюс mutation serial.
Сам probe только читает monitor и SSL metadata. Неизвестная история installation
или ошибка установки ключа означает отказ; epoch нельзя угадать по sequence.

Первый gate может поддержать только initial app generation 0 в каждом направлении,
отклоняя KU; монитор всё равно должен отличить завершённый update от initial
installation.
В [TLS 1.3 record cipher][record-tls13] sequence увеличивается до окончания AEAD
operation, а write encryption предшествует BIO delivery. Поэтому counter без
успешного call, error-state и buffer checks не равен числу подтверждённых records.
Сопоставлять metadata с C1 wire observer в приватной памяти; secret bytes не
добавлять в вывод probe, Git, stdout или artifacts. [Key installation][tls13].

## Предлагаемые независимые случаи, ещё не выполнены

- Positive: настоящий authenticated handshake и request/response; probe до
  следующего read, без нового connect. Next sequences сверить с wire records;
  повторный probe при замороженном I/O не меняет SSL state.
- Partial header и partial encrypted body: вызвать nonblocking read после
  доставки разных префиксов record. Получить реальный WANT_READ и отказ probe,
  в том числе при `SSL_pending()==0`.
- Unread plaintext: прочитать один byte из большего application record, отвергнуть
  оставшийся `rrec`; после полного drain проверить возврат к разрешённой границе.
- Output backpressure: остановить peer/relay reads, ограничить socket buffer,
  ограниченно писать до реального WANT_WRITE. Зафиксировать pending offset/left
  и отказ. Если fixture не создала backpressure, считать случай невыполненным.
- Retry без plaintext: пустой nonblocking read даёт WANT_READ; оба public pending
  getter могут быть нулевыми, но первый консервативный gate отвергает outstanding
  retry. Не очищать ledger только ради разрешения probe.
- KU: scheduled unflushed update; constructed/send-blocked KU при getter NONE;
  peer requested update с неотправленным ответом. Отдельно проверить fragments
  handshake message: transport split record не заменяет этот случай.
- Control: manual `SSL_new_session_ticket()` при disabled automatic tickets;
  pending outbound alert и полученный close_notify. Проверять реальные paths,
  не только вручную выставленные flags.
- Unsupported/changed identity, иной BIO/profile, неизвестная generation,
  state mutation после probe и concurrent SSL calls дают отказ без I/O transfer.

Остаются неизвестными полнота inventory, достижимость и воспроизводимость всех
control/retry states, provider/runtime correspondence, monitor coverage каждого
key installation и достаточность freeze protocol. C2a не проверяет importer,
cross-version continuation, retirement старого TLS-кода или NGINX integration.

[pin]: https://github.com/openssl/openssl/tree/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c
[ssl]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/ssl_local.h
[record]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/record/record.h
[layer]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/record/rec_layer_s3.c
[statem]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/statem/statem.c
[statem-lib]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/statem/statem_lib.c
[statem-server]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/statem/statem_srvr.c
[ssl-lib]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/ssl_lib.c
[record-tls13]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/record/ssl3_record_tls13.c
[tls13]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/tls13_enc.c
