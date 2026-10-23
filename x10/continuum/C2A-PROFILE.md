# C2a: профиль read-only OpenSSL probe

Первоначальный профиль build/probe/runner implementation `99a017e`.
Владелец runtime подтвердил локально
**8/8 PASS**, exit 0, без skips; 81,75 секунды вместе с одним свежим build.
Hosted research push/PR implementation `99a017e` завершились success;
оба подтвердили 21 core, 7 process, 22 C1 и 8 C2a без skips/failures.
Exact runs, отдельный whitespace отказ и граница native CI — в
[C2A-CHECKPOINT.md](C2A-CHECKPOINT.md).
Предварительное чтение upstream контрактов и первичные ссылки сохранены в
[C2A-NOTES.md](C2A-NOTES.md); граница публичных API — в
[OPENSSL-STATE.md](OPENSSL-STATE.md).

## Граница эксперимента

C2a наблюдает объявленную точку установленного TLS-соединения внутри отдельного
исследовательского OpenSSL build. Probe не переносит TLS state, не выдаёт
ownership token, не меняет I/O owner и не завершает source ради target.
Это не exporter/importer, обновление TLS-библиотеки или native NGINX integration.
Полнота inventory и безопасность production этим экспериментом не доказаны.

Первый профиль ограничен Linux x64 same-host server, TLS 1.3,
`TLS_AES_128_GCM_SHA256`, fresh handshake, одним I/O owner и initial application
key generation 0 в обоих направлениях. KeyUpdate не считается поддержанным
состоянием переноса; даже завершённый update нельзя спутать с initial keys
из-за сброшенного sequence. Gate использует monitor, а не выводит generation
только из публичного getter или counter. Это read-only observation profile.

«Read-only» относится к вызову probe: он не вызывает SSL read/write/handshake,
не flush-ит BIO и не читает socket ради очистки состояния. Сам fixture выполняет
handshake и application I/O, чтобы создать наблюдаемые состояния. Разрешённый
snapshot — наблюдение в этот момент; это не обещание неизменности будущего I/O.
Kernel queue остаётся частью того же socket, а не содержимым userspace capsule.

## Идентичность backend

Upstream reference — `openssl-3.0.13`, commit
`85cf92f55d9e2ac5aacf92bedd33fb890b9f8b4c`, tree
`4e48caeae2374ee4982c8e44b6a15cf4753229cb`. C2a использует отдельный pinned-source
build и ограниченный instrumentation patch; private layout системного Ubuntu
OpenSSL не принимается за этот source pin.

[openssl-build.mjs](openssl-build.mjs) предоставляет `buildOpenSSL({signal})`;
отдельного build CLI не требуется. Runner создаёт новый isolated build, получает
exact source commit/tree через shallow fetch официального OpenSSL repository,
применяет зафиксированный instrumentation patch и не использует installed DSO
fallback или persistent build cache. Общий build budget — 600 секунд, `make -j2`.

Configure target — `linux-x86_64`. Профиль использует static `libssl.a` и
`libcrypto.a`, builtin default provider, без external modules и config autoload.
Engine/async/kTLS/legacy/assembly/compression/zlib/DSO/FIPS отключены; точные flags
сохраняются в identity. `no-tests` означает, что upstream OpenSSL test suite не
выполняется: этот focused probe его не заменяет. Static libraries не означают
полностью static system runtime или pin всей ОС.

Identity различает source commit/tree/patched tree, patch SHA, compiler/tools,
Configure/build metadata, static library и OpenSSL CLI hashes/provider profile.
`verifyIdentity()` перепроверяет source, patch, tools и artifacts перед повторным
использованием; private paths не являются public identity. Итоговый probe
executable фиксируется отдельно runner. Владелец заморозил build и подтвердил
его identity checks: один полный локальный build занял
74,61 секунды, включая fetch/Configure/compile/identity checks. Это наблюдение
одной машины, не CI SLA или performance acceptance. Одна версия в runtime
string не заменяет перечисленные identity проверки.

C1 остаётся отдельным experiment с системным C/OpenSSL и Node TLS client.
Наблюдавшиеся там runtime version strings и executable hashes не pin-ят bytes
всех DSO. Успех C1 не подменяет identity C2a source/build/provider, а C2a не
распространяет acceptance на другие OpenSSL versions или provider profiles.

## Как читать gate

Контракт [probe header](openssl-probe.h) и [implementation](openssl-probe.c)
требует fresh server handshake, отключённые early data/PHA/tickets/padding,
read-ahead off и одну pipeline. Разрешён один общий built-in socket BIO для
read/write, без chains, custom methods и callbacks. Partial-write/moving-buffer
modes, kTLS, async и неподдержанный profile дают отказ.

Typed ledger привязан к наблюдаемому `SSL *`, не содержит активного call или
outstanding retry и показывает последний успешный actual read/write. Только
завершение той же операции может закрыть её retry. Ledger поддерживает fixture:
single-owner/thread — доверенный caller contract, не concurrent-call detector,
lock или ownership fence. Pointer binding не публикуется.

Probe обязан отличать активные обязательства от остаточной metadata.
Например, успешно завершённый write может оставить `wpend_*` и смещённый offset;
требование «каждый field равен нулю» отвергло бы допустимую границу.
И обратное: `SSL_pending()==0`, `SSL_has_pending()==0`, init finished или
KeyUpdate getter NONE по отдельности не подтверждают quiescence.

`read_next_sequence`/`write_next_sequence` — независимые 16-значные hex strings,
без потери uint64 precision. Привязка направления к server role обязательна.
Оба initial application generations равны 0; `mutation_serial==2` соответствует
двум initial key-install events. Этот serial считает **только установку ключей**,
не все мутации SSL, и не является snapshot-validity detector или fence.
Неизвестная key installation history, pending retry или неподдержанный control state означает
отказ, а не guessed generation. Список проверенных private fields и охват
instrumentation не объявляются полными по одному положительному snapshot.
Return value `1` означает, что observation заполнено, включая отказ;
решение gate отражает отдельное поле `allowed`, а не сам return value.

В public output допустимы только allowlisted counters/lengths/booleans/reasons
и build identities. Secret/IV/key bytes, fingerprints traffic secrets, pointers,
plaintext/ciphertext captures, private fixture paths и raw failure assertions
не должны попадать в Git, stdout или CI artifacts. Очищенный JSON не доказывает
очистку всех копий secret material в памяти или crash dump.

## Приёмка и CI

Первоначальные восемь случаев достигнуты в настоящих TLS connections, а не выставлением
private flags. CA/hostname проверяет Node TLS client; record observation
использует C1 oracle с теми же границами PKI/Finished MAC, описанными в README.

| Runtime case | Зафиксированный результат |
| --- | --- |
| Quiescent | `allowed=1`; повторные allowlisted metadata совпадают, sequences сверены с wire; нормальные `close_notify` и TCP closure |
| Partial header | После 3 bytes record получен WANT_READ; `SSL_pending()==0`, private input виден; отказ |
| Partial body | После 13 bytes record получен WANT_READ; `SSL_pending()==0`, private input виден; отказ |
| Unread plaintext | Непрочитанный остаток application record виден в private state; отказ |
| Empty read retry | Реальный WANT_READ при отсутствии plaintext не стирает outstanding retry; отказ |
| Write backpressure | Достигнут реальный WANT_WRITE с private pending output; отказ |
| Queued KeyUpdate | Запланированное, ещё не завершённое control work; отказ |
| Completed server KeyUpdate | Read generation 0, write 1, key-event serial 3, getter NONE; отказ только GENERATION (`64`). Wire oracle подтверждает KU и последующие records новым ключом, sequence comparison и нормальное TLS closure |

Последний случай подтверждает наблюдение завершённого key transition и отказ
initial-generation profile, а не перенос KeyUpdate state. Negative fixtures с
неполным I/O не объявляют graceful TLS closure; teardown проверяется отдельно.
Probe не выдаёт traffic grant и не устанавливает usage-limit admission policy.

### Дополнение: lifecycle незавершённого чтения

Два новых сценария расширяют проверку существующего typed ledger contract.
Они не исправляют ранее доказанный defect ledger: правило сохранения чужого
retry и снятия своего retry уже присутствовало в `invoke`. Владелец runtime
получил **10/10 PASS**, exit 0, без skips/cancellations/TODO, за 80,98 секунды
с одним свежим pinned build. Это первый полный author run новых случаев;
финальный coordinator aggregate на окончательных исходниках также прошёл
**10/10**, exit 0, без skips/cancellations/TODO. Независимые четыре held-out
TLS cases на точных окончательных исходниках также прошли, exit 0.
Hosted приёмка нового implementation SHA пока не получена.
Прежние 8/8 и hosted `99a017e` не принимают новый код автоматически.

Первая попытка нового набора остановилась в before hook с
`probe_build_failed`: TLS runtime cases не выполнялись. Причина исходного
build failure не установлена; последующая отдельная свежая сборка тем же
builder прошла с cleanup. Этот отказ не объявляется дефектом TLS и сохраняется
отдельно в evidence координатора. Дополнительная static build-stage диагностика
проверяется отдельно от реальных TLS cases, без публикации raw compiler logs.

Held-out положительные payloads 33 371 и 53 419 bytes подтвердили промежуточный
READ success/retry NONE на первых 16 384 bytes и последующий полный echo;
финальные next sequences совпали с wire 3/3 и 4/4, TLS closure нормальное.
Отрицательные payloads 2 293 и 49 807 bytes дали ровно RETRY `16` при WRITE
success и сохранённом READ retry; Node действительно получил payload до ACK
и raw close. Эти четыре дополнительных запуска не прибавляются к 10 тестам
aggregate как новые виды возможностей. Временные build/binary/PKI roots
независимого запуска удалены; исходные implementation files не изменены.

Отдельный sensitivity control на частной C-mutant копии намеренно стирал
retry после любого success. После настоящего handshake, WANT_READ и успешной
записи 1 379 bytes READ retry ошибочно стал NONE; guard fixture остановил
сценарий, а runner вернул `native_early_exit`. Это один отдельный actual TLS
контроль чувствительности caller contract, не пятый held-out case точного
кандидата и не доказательство защиты probe от лживого ledger.
Первоначальный implementation такой ошибки не имел. Четыре private no-build
контроля фиксированной build-error allowlist прошли отдельно; это не TLS tests.

| Новый runtime case | Проверяемая последовательность |
| --- | --- |
| `completed-read-retry` | Настоящий `SSL_read_ex` сначала получает WANT_READ при отсутствии application bytes; только после `retry-ready` клиент отправляет payload. Первый успешный retry использует исходные buffer pointer и length, а fixture проверяет READ success и снятый retry до следующих операций. Затем проверяются полный echo, повторные probe metadata, wire sequences и нормальное TLS closure. |
| `unrelated-write-read-retry` | После фактического WANT_READ выполняется успешный `SSL_write_ex` с отдельным outbound buffer. READ retry остаётся незавершённым при последнем WRITE success; probe должен отказать по RETRY (`16`). Node проверяет точный полученный plaintext перед bounded ACK, разрешающим raw teardown. Последующее чтение для искусственного снятия обязанности не выполняется. |

Фиксированное событие `retry-ready` содержит только scenario, call/outcome/
retryCall enums и нулевые applicationBytesRead/sslPending. Оно выдаётся после
проверки реального результата OpenSSL, а не заменяет его. Node runner должен
проверить эти поля и задержать клиентские application bytes в положительном
сценарии; отрицательный не отправляет их вообще.

В положительном случае отдельное `retry-completed` фиксирует READ success,
retry NONE, число прочитанных bytes и `sameReadArguments=true` до нового
READ/WRITE. Fixture ждёт второй bounded STEP ACK перед последующими reads
и echo. Сравнение исходных аргументов выполняет доверенный C fixture;
сам enum `retry_call` не является проверкой buffer arguments или их ownership.
Отдельный ACK в отрицательном случае отделяет stdout probe от доставки
application bytes и raw EOF; он не объявляет такой teardown graceful TLS close.

Один успешный READ может вернуть только первый record. Оставшийся payload
допускает последующие обычные reads; профиль fixture при этом завершает
исходный retry тем же buffer/length. Это дисциплина данного fixture, а не
заявление об общем требовании OpenSSL к аргументам retry чтения.
Negative fixture намеренно закрывает
transport без утверждения о graceful TLS close или полном wire transcript.
Успешная запись сама по себе не устраняет ранее возникшую обязанность чтения,
даже если public pending getters не показывают application data.
Это отказ по caller contract fixture, а не дефект публичных getters или
доказательство скрытого ciphertext в данном quiescent private state.

Это не поддержка переноса pending read, write retry completion, peer/read
KeyUpdate, полного control/alert/shutdown inventory или runtime cancellation.
Ни один новый сценарий не меняет TLS code version, I/O owner или соединение.
Публичные evidence и hosted результат нового implementation SHA фиксирует
координатор отдельно.

Aggregate entry point — `node x10/continuum/openssl-probe-check.mjs`.
Wrapper ограничен 650 секундами и 512 KiB суммарного child output, test process —
600 секундами; остановка process group имеет 4-секундный grace до SIGKILL.
Он удерживает raw TAP внутри процесса и публикует очищенные counts/exit facts.
Неполученное backpressure, недостигнутое control state, timeout, interruption или missing evidence не
превращаются в PASS. Независимые controls и повтор исправленного контрпримера
отделяются от первоначального набора автора.

Исследовательский job остаётся на обычном `ubuntu-24.04` с Node 22, минимальными
permissions и timeout 20 минут; отдельный C2a step ограничен 12 минутами.
Прежние 10 минут короче 650-секундного wrapper budget. Проектный предел 30 минут
сохранён. C2a добавляется после C0/C1; его изолированный build не меняет native
NGINX build/profile.
Git/Perl/Make/C compiler dependencies устанавливаются явно; `build-essential`
предоставляет также linker и archiver. Larger runners, GPU, платные ресурсы
и постоянно работающий service для C2a не требуются.

До отдельной приёмки C2b остаются неизвестными корректность semantic import,
перенос partial output/control obligations, смена actual TLS code, исключительное
право target I/O и retirement прежнего code path. Число tests или положительный
read-only snapshot этих свойств не устанавливают; novelty/10× claims отсутствуют.
