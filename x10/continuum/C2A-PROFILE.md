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
Hosted research push/PR и оба полных native workflows для retry implementation
`356f993ead12a1b827a0351f38143b7b14c8d18f` завершились success; exact runs
записаны в [C2A-CHECKPOINT](C2A-CHECKPOINT.md). Прежние 8/8 и hosted
`99a017e` сохранены отдельно и не подменяют приёмку нового кода.

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

Эти два retry-сценария не подтверждают перенос pending read, write retry
completion, peer/read KeyUpdate, полный control/alert/shutdown inventory
или runtime cancellation. Последний проверяется отдельно ниже.
Ни один новый сценарий не меняет TLS code version, I/O owner или соединение.
Публичные evidence и hosted результат нового implementation SHA фиксирует
координатор отдельно.

### Отдельные controls: обработанное прерывание TLS runtime

Десять обычных TLS scenarios остаются отдельным набором. Два дополнительных
controls отправляют `SIGTERM` и `SIGINT` частному launcher, вызывающему
неизменённый C2a module API, после настоящего
TLS handshake и успешного application READ. Условия и результаты этих controls
не считаются двумя новыми состояниями, разрешёнными probe к переносу.
Финальный локальный aggregate прошёл 13/13: 10 обычных TLS cases, два
handled-signal controls и один no-TLS source control. Exact hosted приёмка
нового implementation SHA ещё ожидается. Независимо пройдены один held-out
TLS case и два отдельных actual-TLS sensitivity controls; исходные отказы
и ограничения сохранены в [interruption evidence](../evidence/continuum-c2a-interruption.json).

Частный preload наблюдает существующее C-событие `retry-completed` в
`completed-read-retry` и задерживает его доставку runner. C уже сообщил
положительное число прочитанных bytes и снятый READ retry, затем ждёт
существующий bounded STEP ACK перед echo. Контроль не добавляет публичного
checkpoint API, не подменяет SSL calls и не изменяет C/probe/patch. Launcher
воспроизводит CLI try/finally cleanup и фиксированный error/exit контракт;
сам standalone CLI branch этим control напрямую не исполняется. Handshake
и исходный WANT_READ должны быть наблюдены до выбранного checkpoint;
готовность слушающего socket сама по себе не удовлетворяет этому условию.

Условие PASS требует обработанного отказа `fixture_interrupted`, exit code
143 для `SIGTERM` либо 130 для `SIGINT`, без успешного результата сценария.
После выхода runner отдельно проверяются завершение идентифицированного
C child, удаление принадлежащих запуску PKI, fixture binary и pinned-source/
build каталогов. Relay listener должен быть доступен до сигнала, а после
выхода — освобождать свой loopback port для нового bind. Отдельная попытка
TCP connect к прежнему native endpoint должна получить `ECONNREFUSED`.
У native C listener закрывается сразу после accept; его port не проверяется
повторным bind после установленного TLS-потока. Эти наблюдения не доказывают
отсутствие всех kernel socket states или graceful TLS closure. Проверки
выполняются до резервной cleanup самого control: удаление тестом оставшихся
файлов не превращает утечку runner в PASS.
Private IPC может передавать временные paths и PID только управляющему test
process; публичные результаты сохраняют counts/booleans и identities без
таких значений, payload, session material или raw runtime logs.

Первая авторская попытка `SIGTERM` с payload 4 097 bytes достигла нужного
READ checkpoint, обработанного exit и удаления временных каталогов, но
отказала на требовании повторного bind native port. Это требование control
было некорректным для port уже принятого соединения; причина фактического
отказа bind не установлена. Конкретный kernel state не объявляется
подтверждённым. Требование заменено описанными выше отдельными наблюдениями
native endpoint и relay listener; исходный отказ сохраняется в evidence,
не объявляется дефектом production cleanup и не считается PASS.

Проверяется одна объявленная application-read boundary и два обрабатываемых
сигнала. Это не graceful TLS `close_notify`, не доказательство полного стирания
секретов в памяти и не восстановление после `SIGKILL`, crash либо потери питания.
Остальные interrupt boundaries, полный control/shutdown inventory, смена TLS
code version, export/import, исключительное target I/O и native NGINX migration
остаются самостоятельными gates. Если неизменённый runner проходит эти
controls, результат означает новое покрытие, а не исправление доказанного
дефекта его cleanup.

Наблюдение process birth сопоставляет local PID с `NSpid`, тем же PID
namespace и UID; numeric local PID не принимается за имя каталога `/proc`.
Скан ограничен 10 000 entries и двумя секундами вокруг системных вызовов;
зависший kernel syscall принудительно не прерывается. Это проверка
принадлежащего helper child, не pidfd и не атомарный PID-reuse fence.

Отдельный no-TLS control импортирует частную копию helper, изменяет её bytes
и требует `interruption_helper_changed` до создания ресурсов или сборки.
Load-time hash и повторные проверки ловят cooperative live edits после
импорта; они не являются общей attestation исполняемого JavaScript.
Набор теперь содержит 10 обычных TLS scenarios, 2 runtime signal-controls
и этот 1 no-TLS source control; итоговые 13 проверок учитываются отдельно
от полноты TLS inventory.

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

## Peer-requested KeyUpdate: queued response и завершённый WRITE

Новые `peer-key-update-pending` / `peer-key-update-completed` используют
реальный C/OpenSSL client на той же pinned3.0.13 сборке, что и C server.
Client проверяет CA/hostname, выполняет SSL_key_update(REQUESTED), flush и
посылает application bytes под новым write key. Session resumption и early
application data не допускаются. Private fd3 переносит bounded keylog только
в память runner; raw secrets/captures не публикуются. Это не новая TLS release.

Server действительно читает весь payload и выдаёт READ-success checkpoint
до первого WRITE. Pending snapshot: read/write generation1/0, serial3,
queued NOT_REQUESTED, reasons32832=GEN64|KEY_UPDATE32768; public pending0 и
retry NONE не снимают refusal. После ACK обе стороны закрываются raw;
полный graceful wire transcript для pending не заявляется.

В completed реальный echo SSL_write_ex сам flushes queued response, затем
application bytes. Не вызывается повторный SSL_key_update для подмены response.
Snapshot: generation1/1, serial4, getterNONE, reasons64. Исходный probe/header/
patch/build не менялись, updated generations по-прежнему unsupported.
Standalone SSL_do_handshake после получения запроса не объявляется достаточным:
такое предположение скорректировано по pinned source до runtime проверки,
а не по выполненному неудачному тесту.

Observer дополнен optional expectedClientKeyUpdates0|1 (default0). REQUESTED
client KU и NOT_REQUESTED server response аутентифицируются старым ключом
своего направления; затем directional epoch увеличивается, а sequence
сбрасывается перед application records.
Сравниваются epoch-relative beforeCloseNotify sequences, lifetime application
record count не подменяет sequence. Close_notify расходует следующий номер.
C endpoint проверяет PKI/hostname/Finished; inherited comment observer про
Node относится к прежнему C1 caller, новый caller — authenticated C client.
Observer не проверяет PKI или Finished MAC независимо. Отдельные captures
не устанавливают cross-direction timing; это дисциплина trusted fixture.

Локально15/15 (12TLS+2signals+1source), независимые heldouts4/4. Два schedules
дробят relay write calls, но не гарантируют TCP segmentation. C1 aggregate27
состоит из18 synthetic oracle controls и9 runtime checks. Новые5 synthetic
controls не объявляются дополнительными actual handshakes. Evidence и hashes:
[peer update](../evidence/continuum-c2a-peer-key-update.json). Следующие gates —
реальный WRITE retry completion, overlaps/control/shutdown/limits. Экспорт,
import, distinct-version change и native continuation остаются unimplemented.

## Same-operation WRITE retry completion

`completed-write-retry` accepts only65536 authenticated application bytes.
Both Node client reads and relay backend reads pause before the initial C echo.
The existing direct socket BIO and SO_SNDBUF4096 must yield a real WANT_WRITE
with private pending output. Otherwise `state_not_reached` fails the case;
no synthetic retry, larger payload or observer-limit increase is substituted.

C emits write-retry-ready, then immutable refused samples1/2, and waits STEP.
The runner resumes both readers before STEP. C checks the original pointer,
full length and deterministic contents, retries the original SSL_write_ex
until actual success, checks the contents again and emits completion before
any later SSL operation. WRITE success clears only its matching retry.
Allowed samples3/4 must be immutable before the peer starts close_notify.
One client application write and one server echo are permitted. Failed API
write may already emit a prefix; its reported written count is not used to
advance a buffer or infer no delivery. Both moving-buffer and partial-write
modes remain disabled. Caller checks are not a general ownership fence.

Author smoke observed refusal1556, wbufLeft16406 and wnum32768, followed by
full65536 completion, reasons0 and post sequences4/4. These pre-call progress
values are measured facts, not fixed cross-platform invariants. After success
wbufLeft=wnum=0 and rwstate=SSL_NOTHING; stale wpendTot/Ret or allocation/offset
may remain and do not themselves imply a pending operation. Unchanged oracle
requires exact data, correct sequences and both close_notify/FIN. Its limits
remain65536 bytes per direction and262144 total captured bytes in the relay.

Local16checks separate13 ordinary actual-TLS cases,2 handled runtime signals
and1 no-TLS source control. The baseline runner rejects the new scenario before
building; that no-TLS capability control does not demonstrate an OpenSSL defect.
Independent actual-TLS heldouts and a private stale-WRITE-ledger sensitivity
are recorded separately in [evidence](../evidence/continuum-c2a-write-retry.json).
Native NGINX, probe/header/patch/build and oracle bytes are unchanged. Overlaps,
control/alert/shutdown/usage limits and other interruption boundaries remain
pending; this read-only case does not implement export/import or migration.

## Unsupported overlap: READ retained after WRITE completion

`overlapping-read-write-retry` permits only65536 outbound bytes. The Node
client sends no application payload. C obtains actual READ/WANT_READ using
an unchanged original read buffer, then attempts a distinct full-length WRITE
with client and relay backend readers paused. Real WRITE/WANT_WRITE and
private pending output are mandatory; state_not_reached remains failure.

The first-obligation enum retains READ rather than representing both retries.
Samples1/2 must be identical refused observations with last WRITE/WANT_WRITE,
READ retry and pending output. After both readers resume and bounded STEP,
only that original WRITE is retried with identical pointer/content/full length;
no READ/control/handshake/shutdown operation intervenes. This follows the exact
pinned SSL_get_error contract. Original READ buffer pointer/size and0xa5
sentinel are checked before/after WRITE; read completion is not attempted.

After actual WRITE success65536, samples3/4 still refuse with reasons16,
READ retry retained, last WRITE success, wbufLeft=wnum=0 and rwstate=SSL_NOTHING.
Node verifies exact outbound receipt before the final STEP permits raw close.
No SSL_shutdown is called; wire=null and graceful bidirectional closure is not
claimed. Metadata sequences are not independently wire-validated for this case.
The author observed pending1556/read-write next0/2/wnum16384 and completed
16/next0/4. Pre-write progress depends on scheduling and is not a portable
constant. Available counts/hashes and separate heldouts are preserved in
[overlap evidence](../evidence/continuum-c2a-overlap.json).

Generic invoke/probe/header/patch/build/oracle and existing limits are unchanged.
This is new refusal coverage, not a false-acceptance fix or complete obligation
history model. The overlap stays unsupported; no later admission is tested or
granted. Seventeen flat checks mean14 ordinary actual-TLS cases,2 runtime
signals and1 no-TLS source control. Control/alert/shutdown and sequence/key
usage admission remain separate gates before semantic export/import.

## Server-initiated normal shutdown refusal lifecycle

`server-shutdown-lifecycle` consumes and echoes the exact bounded payload,
then waits for Node acknowledgement before calling SSL_shutdown. Only this
client enables allowHalfOpen; its writable side must remain open until after
the first two immutable probes. Actual first return0 is sent/incomplete,
not an error: SSL_get_error(0) is never called. The unchanged fixture convention
records incomplete shutdown as WANT_READ with SHUTDOWN retry5. Raw0 is observed
via PEER.last_result; this field does not change ledger/probe semantics.

First probes retain SENT1, CONTROL and RETRY refusal bits. SENT1 alone says
nothing about peer receipt. Only after the pair does Node explicitly end;
bounded STEP then permits repeated SSL_shutdown until actual1, flags3 and
retry0. No application I/O or control call follows shutdown. Final immutable
probes still refuse: last SHUTDOWN is outside the READ/WRITE success gate and
CONTROL remains. Observed masks are4116 then4356, the latter also retaining
READ_RECORD256 and2 control bytes in private record metadata despite public
pending0. This does not establish an unprocessed alert or more application
data. No closed state is admitted for live continuation.

Unchanged wire observer checks exact bytes, both close_notify and FIN. Final
probe sequences include the alerts and match both directional finalNextSequence;
first-phase read matches client beforeCloseNotify and write server final.
Directional capture is not a general cross-direction timing proof; this fixture
uses explicit gates. Counts18 mean15 ordinary TLS cases,2 runtime signals,
1 no-TLS source control. Prior17 checks, caps and native source are preserved.
[Evidence](../evidence/continuum-c2a-shutdown.json) keeps actual reason masks,
identities, independent heldouts and cleanup facts separately.

Other peer-first/partial/fatal alerts and EOF states, control inventory and
sequence/key usage admission remain pending. Normal close_notify refusal does
not establish a complete shutdown model, single-writer fence, export/import,
actual TLS-code version change or native NGINX continuation.

## Unexpected transport EOF after completed echo

`unexpected-transport-eof` authenticates the independent Node client and verifies
exact bounded request/echo receipt. C must first observe the allowed quiescent
profile, no retry, IGNORE_UNEXPECTED_EOF off and quiet shutdown off. Only then
does Node destroy the TLS socket without end()/SSL_shutdown. Destroy alone is
not a FIN guarantee: actual relay frontend end observation and exact pinned
server EOF classification are both mandatory. RST/retry/clean close cannot pass.

After bounded POLLIN/HUP readiness, one actual READ must return0, SSL_ERROR_SSL1,
first queue SSL reason294 and zero application bytes. Error queue is cleared
before I/O, SSL_get_error classifies immediately, then ERR_peek_error inspects
the first entry. Fatal handling may emit an internal alert/secondary BIO error;
no raw queue is published. Two probes are immutable/refused with last READ ERROR
and no outstanding retry in this case. Existing terminal-error ledger behavior
is unchanged; it does not generally clear a previously outstanding retry.

No further TLS read/write/control/handshake/shutdown occurs after fatal error;
metadata and cleanup are separate. wire=null and graceful=false; no full capture
oracle, server FIN, post-fatal sequence acceptance or general truncation proof.
The scoped endpoint confirms payload receipt before raw close, not migration.
[Evidence](../evidence/continuum-c2a-eof.json) retains actual masks/metadata,
source/build identities, independent cases and cleanup. Counts19 mean16 ordinary
TLS scenarios,2 runtime signals and1 no-TLS source control. Existing18 tests,
probe/header/patch/build/oracle, ledger semantics and caps remain unchanged.

Partial/truncated records, RST, peer-first closure and other fatal/control states
remain separate inventory; sequence/key usage gates precede C2b. No complete
state model, concurrency fence, export/import or actual TLS-code change is proven.
