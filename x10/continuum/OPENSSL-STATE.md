# C1: граница живого состояния OpenSSL

Это ограниченное чтение публичных headers, документации и выбранных upstream
исходников на 2026-10-23, а не полный аудит OpenSSL или реализованный exporter.
Реальный C/OpenSSL handshake с независимым Node TLS client — отдельный C1 gate.
Даже успешный handshake не подтверждает export/import, смену TLS-кода или NGINX.
Исследовательский профиль: Linux, одна машина, TLS 1.3,
`TLS_AES_128_GCM_SHA256`, один установленный TCP socket, один I/O owner.

## Версии и воспроизводимость

| Наблюдаемая часть | Локальная версия |
| --- | --- |
| `/usr/include/openssl/opensslv.h` | `OPENSSL_VERSION_STR=3.0.13` |
| `openssl version` и его runtime library | OpenSSL 3.0.13 |
| Установленные `openssl`, `libssl-dev`, `libssl3t64` | `3.0.13-0ubuntu3.6` |
| Независимый Node client | Node 24.19.0, `process.versions.openssl=3.5.7` |

Публичный upstream tag `openssl-3.0.13` разрешён через официальный GitHub API:
annotated tag object `5e7a8c3ed0db97f11c80557f33ec797bceeb4b30`, commit
**`85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c`**. Это проверка ref resolution,
не проверка подписи tag. Ссылки на исходники ниже фиксируют именно этот commit.
Ubuntu package revision `.6` содержит отдельную downstream историю; точный
source package и его patches здесь не получены и не сопоставлены с бинарником.
Поэтому upstream tag не даёт проверенного private layout установленной library.

Для C1 сохраняются compile-time headers, `OpenSSL_version()` реально загруженной
library, client runtime и hashes выбранных binaries. Для C2 нужен изолированный
build из зафиксированного source вместе с patch, libcrypto/provider/config и
build flags. Историческая версия здесь — research reference, не рекомендация
для production. Не читать установленную `SSL *` по предполагаемым offsets.

## Публичные наблюдения и недостающий контракт

`SSL` объявлен в публичном `types.h` как opaque `struct ssl_st`.
В исследованной публичной поверхности не найден полный active-state exporter
или importer. Наличие частичного getter не означает возможность восстановления.

| Состояние | Что даёт публичный API | Что остаётся для adapter |
| --- | --- | --- |
| Protocol/cipher/handshake | `SSL_version`, `SSL_get_current_cipher`, `SSL_is_init_finished`, `SSL_get_state` | Метаданные не описывают record/buffer obligations |
| Read/write sequence | Полного getter/setter пары здесь не найдено | Два независимых следующих record counters; private `rlayer.read_sequence/write_sequence` |
| Traffic secrets и key generation | Keylog callback наблюдает создаваемый material для debugging | Не snapshot/import: нужны текущие directional secrets, role mapping, key-install history и usage limits |
| Частичный ciphertext и plaintext | `SSL_pending` считает обработанные application bytes; `SSL_has_pending` сообщает buffered records | Точные buffers, offsets, record/handshake fragments, ownership и порядок |
| Pending output | `SSL_write_ex` и `SSL_get_error` задают retry semantics | Уже зашифрованные/отправленные bytes, write offset, pending call и его неизменные arguments |
| KeyUpdate | `SSL_key_update` планирует update; `SSL_get_key_update_type` показывает scheduled kind | Полученные fragments, направление установленного ключа, отправленные bytes и обязательный ответ |
| Read-ahead/BIO | `SSL_get_read_ahead`, `SSL_get_rbio/wbio`, BIO pending queries | Эти counters не сериализуют внутренние record buffers, BIO chain или kernel queues |
| Shutdown | `SSL_get_shutdown` возвращает flags; `SSL_set_shutdown` их меняет | Flags не доказывают отправку/получение `close_notify` и не переносят pending alert |

`SSL_pending()==0` может сосуществовать с необработанными records внутри SSL.
`SSL_has_pending()==1` возможен при неполном record без доступного plaintext.
Даже два нуля не проверяют pending output, post-handshake state или I/O ownership.
Чтение ради проверки может обработать control messages и изменить состояние.
При `WANT_READ/WANT_WRITE` write уже мог обработать данные; retry требует тех же
data/length, с отдельными условиями для moving-buffer/partial-write modes.

`i2d_SSL_SESSION`/`d2i_SSL_SESSION` сериализуют **SSL_SESSION**.
`SSL_set_session` задаёт session для установления соединения/resumption;
это не восстановление прежнего активного SSL на прежнем TCP stream.
`SSL_SESSION_get_master_key` также не заменяет текущие record keys/counters.
`SSL_export_keying_material` выводит application material из exporter secret,
а не экспортирует traffic state. Keylog callback не даёт import API, counters,
pending buffers или ownership; реальные secrets нельзя писать в logs/artifacts.

## Что подтверждено выбранными private исходниками

- [ssl_local.h][ssl-local] содержит `client_app_traffic_secret`,
  `server_app_traffic_secret`, отдельный `exporter_master_secret`, EVP contexts,
  IV, `key_update`, state machine и `rlayer`; это ещё не полный inventory.
- [record.h][record] содержит read/write sequences, `rbuf`, `wbuf`, `rrec`,
  packet length, handshake fragment, `wnum` и `wpend_*`, включая pointers.
- [tls13_enc.c][tls13] при key installation/update меняет directional secret,
  cipher/IV и сбрасывает соответствующий sequence. Поэтому нельзя выводить
  key generation только из counter или грубого handshake state.

Это private implementation, не стабильный ABI. Копирование `SSL`, EVP contexts,
BIO pointers или process memory через `memcpy` не является adapter.
Полный call graph key installation, post-handshake processing и retry paths
ещё не проверен; существующий synthetic IR нельзя объявлять полным SSL state.

## Самый маленький C2 эксперимент

1. **Read-only instrumentation gate.** Изолированный pinned OpenSSL build,
   один event-loop thread/socket BIO, read-ahead off; обычный authenticated
   handshake. Добавить внутренний semantic probe на объявленной record boundary,
   пока без import/owner change. Зафиксировать directional next sequences,
   текущие key-install generations и полный inventory pending obligations.
   Probe не вызывает SSL I/O и ничего не выводит из secret material наружу.
2. **Quiescence gate.** Приостановить source callbacks/I/O; подтвердить внутри
   library отсутствие partial records/plaintext/output/control fragments,
   pending retries/KeyUpdate/alerts и других неподдержанных состояний.
   Kernel receive bytes могут оставаться на том же socket: это не userspace
   snapshot, и source после проверки больше не вправе их читать.
3. **Только после inventory — минимальный importer.** Явная semantic capsule
   в защищённой RAM и свежие target library objects; восстановление через
   изученный library patch, без копирования opaque objects. Сначала один
   поддержанный quiescent state, затем отдельно KeyUpdate и adverse I/O.
   Если корректное established-state восстановление не определено — остановка,
   а не подмена переносом FD, session resumption или старым TLS helper.
4. **Независимый oracle.** Один client connect, тот же stream, source exit до
   target I/O, exact bytes обоих направлений и target после exit. Отдельно
   проверить новые code/binary identities: два PID одного TLS build не доказывают
   cross-version upgrade. Два изменённых layout требуют отдельных adapters.

До owner grant отклонять неизвестную source/target identity, role/cipher/profile,
недостоверные counters/usage budget, неоднозначный transport binding, изменение
state после probe, concurrent SSL calls и любой неописанный pending state.
Первый profile исключает 0-RTT, resumption, post-handshake authentication,
kTLS, async engines, pipelines и сложные BIO chains; отключение future tickets
не доказывает отсутствия уже pending ticket bytes. Peer KeyUpdate нельзя
объявить невозможным: его последующая обработка/ответ — отдельное обязательство.

Held-out negatives: неполный encrypted record при нулевом `SSL_pending`, unread
plaintext, backpressure с pending write, fragmented/queued KeyUpdate, pending
alert/ticket и mismatch directional generation. Они должны отказать **до**
передачи ownership. Положительный quiescent case не принимает эти состояния.
Секреты fixture не публикуются; memory lifetime/cleansing требуют своего review.

Блокеры C2: нет установленного полного public export/import контракта;
downstream source/binary correspondence не подтверждён; private-state inventory,
safe point, importer и независимая проверка ещё не реализованы этим документом.

## Первичные источники

[Tag ref][tag-ref], [annotated tag object][tag-object]; документы на том же pin:
[pending][pending], [session encoding][session], [set session][set-session],
[key update][key-update], [keylog][keylog], [exporter][exporter],
[read-ahead][read-ahead], [write retries][write], [shutdown flags][shutdown].
Протокольные обязательства: [RFC 8446 §§4.6.3, 5.2–5.5][rfc].

[tag-ref]: https://api.github.com/repos/openssl/openssl/git/ref/tags/openssl-3.0.13
[tag-object]: https://api.github.com/repos/openssl/openssl/git/tags/5e7a8c3ed0db97f11c80557f33ec797bceeb4b30
[ssl-local]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/ssl_local.h
[record]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/record/record.h
[tls13]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/ssl/tls13_enc.c
[pending]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_pending.pod
[session]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/d2i_SSL_SESSION.pod
[set-session]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_set_session.pod
[key-update]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_key_update.pod
[keylog]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_CTX_set_keylog_callback.pod
[exporter]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_export_keying_material.pod
[read-ahead]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_CTX_set_read_ahead.pod
[write]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_write.pod
[shutdown]: https://github.com/openssl/openssl/blob/85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c/doc/man3/SSL_set_shutdown.pod
[rfc]: https://www.rfc-editor.org/rfc/rfc8446.html
