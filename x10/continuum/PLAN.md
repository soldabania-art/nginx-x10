# Continuum: поэтапный R&D-план

Этот план проверяет гипотезу переноса живого encrypted потока при смене процесса
и кода. Он не является обещанием сроков, совместимости всех версий, безопасности
или коммерческого выпуска. Архитектурные границы и prior art: [README](README.md).
Статус конкретных срезов указан в checkpoints ниже; остальные требования
остаются исследованием. Приёмка привязана к конкретному record, source/binary
hashes и контрпримеру, а не к общему названию этапа.

## Правила исследования

1. Один Linux same-host профиль: TLS 1.3 `TLS_AES_128_GCM_SHA256`, ограниченные
   состояния и явно названные adapters. Неподдержанное состояние не считается
   мигрированным и не превращается в reconnect без отражения в результате.
2. Главный неизвестный TLS state проверяется рано. FD-only transfer и один
   неизменный TLS helper не закрывают этот неизвестный.
3. Сначала established-record experiment, затем настоящий handshake/library
   bridge и только после него native NGINX. Результаты этапов не подменяют друг друга.
4. Сохранять source/binary identity, client connection count, точные bytes,
   ошибки, pause/retirement и cleanup. Изменение test assertion ради PASS
   запрещено; ожидаемый отказ записывается отдельным результатом.
5. Никто не выполняет data I/O на migrated socket до получения своего
   исключительного права. Неясный commit не разрешает оба owner.
6. Обычные NGINX semantics остаются прежними; новый путь opt-in и исследовательский.
   Изменение C требует отдельного чтения lifetime/event/buffer/module contracts.

## Этап 0: конкретный контракт и исходные контроли

Зафиксировать named update point, модель source/target/coordinator, минимальное
IR, направления adapters и точную семантику commit/abort. Записать, какие
неполные I/O и управляющие TLS состояния поддержаны, какие отклоняются.
Сопоставить механизм с Envoy, Kitsune, TALOS и другими найденными работами;
совпадение идеи не скрывать переименованием.

Исходные контроли: обычный restart обрывает выбранный поток; обычный drain
сохраняет поток, оставляя source обслуживать его. Выделить отдельный контроль,
в котором меняется только процесс/banner: он не считается сменой record code.

Выход: reviewable контракт и воспроизводимый baseline. Этот этап не обещает
ни TLS interoperability, ни закрытия старого процесса без обрыва.

## Этап 1: deterministic record core и checker

В изоляции реализовать synthetic established state, record protection,
переносимые counters/keys и проверяемый переход adapter между двумя schemas.
Показать различие исполняемого record/state code, а не только номера версии.
Изменённый layout не переносится через `memcpy` или сериализацию pointer values.

Целевой runner:

```sh
node x10/continuum/check.mjs
```

Матрица приёмки:

| Семейство | Положительный случай | Контрпример/отказ |
| --- | --- | --- |
| Record state | Последовательность байтов до/после преобразования совпадает с oracle | Неверные key/IV/sequence/role не принимаются |
| Формат | Допустимые точные counters и ограниченные длины | Overflow, truncation, неизвестный profile/schema и противоречия |
| Adapter | Явная source→target совместимость | Нерегистрированный переход и потерянное обязательное поле |
| Ownership | Единственный допустимый owner/переход | Повторный token, неверная generation, двукратный commit |
| Ресурсы | Ограниченные buffers/число шагов | Oversize input до большого allocation; exceeded budget |

Independent oracle должен разделять как минимум framing/AEAD assumptions;
одна реализация encoder/decoder, согласная с собой, недостаточна. Fixed vectors
и отрицательные мутации различаются от проверки полноценного handshake.

Стоп: неверный counter/nonce может приводить к принятому продолжению; checker
пропускает потерю существенного state; одинаковый код маскируется двумя именами.
Сначала исправляется модель, затем продолжается процессный эксперимент.

## Этап 2: настоящий TCP handover между процессами

Начальный fixture `v1`/`v2` использует один Node executable, общий worker-файл и
ручное преобразование application counter. Это полезный подготовительный
handover schemas; он не закрывает требование разных исполняемых TLS releases.
Отдельный процесс не означает отдельную TLS implementation.

Использовать один loopback client connect, source и target как отдельные
процессы с зафиксированными identities. Передать тот же TCP endpoint и
преобразованное synthetic established-record state; источник завершить и
продолжить обмен после его завершения.

Целевой entry point:

```sh
node --test x10/continuum/process-handover.test.mjs
```

Нужны ограниченное завершение children, закрытие sockets и отказ при прерывании.
Проверяются оба направления, последовательность application bytes, отсутствие
скрытого reconnect и старого TLS data-plane helper. Coordinator/fixture обязан
отдельно подтвердить конец source lifetime. Это всё ещё record-stage без
сертификатов и authenticated handshake.

Held-out читатель меняет fragmentation schedule, длины и положение handover.
Инструментировать overlap old/new I/O и negative control с намеренным
дублированием owner; обычный успешный обмен сам по себе overlap не исключает.

Стоп: source должен оставаться живым для успеха; plaintext проходит через
необновлённый helper; потерянные байты скрываются повторной отправкой приложения;
успех требует нового клиентского connect.

## Этап 3: неполные I/O и TLS control obligations

Этот этап расширяет заявленный профиль только после отдельных подтверждений.
До этого partial state, KeyUpdate и backpressure не объявляются поддержанными
по наличию полей в IR или по чтению исходника.

- Fragmented/coalesced input: неполный header, encrypted body, несколько records
  за одно чтение и данные, оставшиеся в kernel после capture.
- Частичный output: exact ciphertext remainder/offset, уже использованный
  sequence number и отсутствие повторного prefix/шифрования.
- KeyUpdate: независимые направления, update request/response, перенос до/после
  смены ключей и одновременные запросы peers. Отдельно — fragmented
  post-handshake message и смешение control/application records.
- Backpressure: paused reader, filled send queue, ограниченная память и deadline
  попытки quiesce. Неуспешная миграция оставляет подтверждённого source owner.
- Closure: alert/close_notify/EOF и порядок уже принятых данных; неподдержанный
  случай не превращается в обещание сохранения потока.

После target I/O старый snapshot не используется как automatic rollback.
Отдельно исследовать source death, target death, duplicate/reordered ACK,
commit timeout и потерю coordinator. До появления соответствующего протокола
эти случаи не являются crash-safe continuity.

Стоп: duplicate ownership, повтор key/nonce для разных plaintext, невидимая
потеря/дублирование данных или неограниченная память. Ресурсный отказ не должен
маскироваться как успешный перенос.

## Этап 4: настоящий handshake и TLS backend adapter

Этот этап разделён на gates C1, C2a и C2b. Настоящий handshake и наблюдение
records не означают наличие library exporter или доказанного update point.

**C1 — handshake interoperability.** C/OpenSSL server и Node TLS client
выполняют TLS 1.3 handshake с проверкой fixture CA/hostname, cipher и ALPN.
Relay имеет два TCP legs; миграции между процессами здесь нет. Record observer
проверяет AEAD, sequence, KeyUpdate и closure, но не независимые PKI/Finished MAC.
Два OpenSSL versions остаются одной implementation family. Runtime strings и
executable hashes не являются pin всех загруженных DSO bytes.

**C2a — read-only inventory и safepoint.** Начать с изолированного build из
точного source pin и исследовательского instrumentation patch, не с чтения
opaque layout установленного Ubuntu DSO. Прочитать record/buffer/KeyUpdate/
alert/shutdown lifetimes и составить полный inventory обязательств.
[OPENSSL-STATE.md](OPENSSL-STATE.md) фиксирует начальное чтение public/private
surface, version mismatch и минимальный semantic probe. Первый gate только
наблюдает поддержанную quiescent boundary: directional next sequence и key
generation, private buffered input/plaintext/output, retries и control state.
Неподдержанный или неизвестный state отвергается до ownership change.

**C2b — export/import после inventory gate.** Отдельный reviewed adapter создаёт
свежие target library objects из semantic capsule без `memcpy` SSL/EVP/BIO.
Клиент сохраняет прежний поток после выхода source и смены actual TLS code;
session serialization/resumption/new handshake не считаются переносом.
Изменённые source/target layouts требуют своих adapters и identities.
Нужны review обращения с secrets, допустимых backend updates, неподдержанных
transitions и held-out partial I/O/KeyUpdate/backpressure cases. Переход между
schemas одного research engine не доказывает произвольную OpenSSL совместимость.

Стоп/пересмотр: механизм требует бесконечно сохранять прежнюю TLS-библиотеку
на пути данных; экспорт невозможен без непроверяемого копирования внутренних
объектов; security/update цель исчезает при учёте старого helper.

## Этап 5: HTTP/WebSocket adapters и native NGINX

Сначала изучить affected native connection/request/pool/buffer/event/TLS и
module contracts. Для каждого adapter составить список скрытых state:
parser positions, content length/chunking, queued bytes, timers, rate limits,
WebSocket fragmentation/control/compression и связанные upstream sockets.
Downstream TLS transfer не означает перенос backend TLS или application state.

Первый native путь opt-in, с конкретным HTTP/1 либо WebSocket subset и
объявленным поведением при неподдержанном состоянии. HTTP/2 multiplexing, QUIC,
0-RTT, произвольные filters/dynamic modules и cross-host migration вне этого этапа.
Отдельная проверка подтверждает действительное завершение всех выбранных old
workers; одна неподдержанная connection не скрывается за успешными остальными.

Приёмка требует настоящего обновления binary/record code, внешнего клиента,
сохранившего соединение, и значимого изменения state representation через
reviewed adapter. Полный `node x10/test/all.mjs --official` остаётся gate для
изменений native NGINX; isolated research tests не заменяют его.

## Независимая приёмка и измерения

Перед held-out запуском замораживаются source, adapters, checker, fixtures,
dependencies и binaries. Автор не выбирает held-out seeds/schedules и не
считает исправленный по найденному случаю запуск новым независимым испытанием.
Review model, direct checker controls, record-engine tests, TCP process tests,
handshake interop и native integration публикуются как разные виды evidence.

Для каждого принятого профиля нужны сравнения с корректным drain и обычным
restart/resume: median/p95/p99 и максимум pause, errors, source retirement,
peak RSS, CPU, bytes/state per connection и число неподдержанных состояний.
Вариация одинаковых binaries, неблагоприятные результаты и cleanup failures
сохраняются. До воспроизводимого сравнения нет throughput/performance claim.

Общий hard stop: результат требует скрытого reconnect, фонового старого TLS
engine, принятия противоречивого state или ослабления протокола для PASS.
Исследовательский результат с узким профилем допустим; промышленный TLS server
из него автоматически не следует. Новизна проверяется отдельно по prior art.

## Bootstrap: денежный лимит

План начинается с **$0 дополнительных расходов**: существующая машина,
workspace, имеющиеся инструменты и стандартный публичный CI в доступных квотах.
**До $100 резерва суммарно** — плановый верхний предел возможных необходимых
проверок, а не разрешение автоматически покупать ресурсы или обещание уложиться
в бюджет. Сначала используются локальные reproducible fixtures. Нужда в платном
ресурсе оформляется конкретно перед его использованием.

В лимит не включены время основателя, уже оплаченные подписки, оборудование и
полноценное внешнее security review. Доступ к AI не считается безлимитным или
бесплатным. Начальный план не требует сотрудников, GPU, панели управления,
постоянного облачного fleet или обязательств 24×7. Production review, support,
TLS-library matrix и release maintenance потребуют отдельного решения.

Лимит денег не задаёт срок: при фундаментальном препятствии корректнее
зафиксировать отрицательный результат, чем расширять расходы или обещания.

## Checkpoint C0 от 23 октября 2026 года

Принят узкий подготовительный срез: record/state **21/21**, process **7/7**
локально и в отдельном hosted CI, без skips/TODO. Перечень, hashes и контрпримеры:
[continuum-c0 evidence](../evidence/continuum-c0.json). Это части этапов 1–3,
а не объявление завершёнными всех их требований или разных TLS releases.
Один shared worker и ручной layout adapter остаются явным ограничением.

## Checkpoint C1: локально и hosted 22/22

Добавлены C/OpenSSL server, Node TLS client/relay, record observer и bounded
`node x10/continuum/handshake-check.mjs`. Финальная матрица — **13 observer
controls + 9 runtime cases = 22**. Итоговый локальный запуск root подтверждён:
**22/22 PASS**, exit 0. Hosted push/PR research и native для implementation
`193afe99` завершились success; точные references — в [CHECKPOINT](CHECKPOINT.md).
Девять runtime cases: два положительных обмена с/без server KeyUpdate,
пять trust/profile отказов до application bytes и два фактических interrupt
cleanup после native listening (SIGTERM/SIGINT, child exit, private PKI removal).

Клиент проверяет CA/hostname; observer проверяет authenticated record continuity
и closure, но не заменяет PKI/Finished MAC verifier. Два TCP legs не мигрируют.
Наблюдавшиеся server OpenSSL 3.0.13 и Node OpenSSL 3.5.7 не означают две
независимые implementation families; exact DSO bytes не закреплены.
Ни state export/import, ни distinct TLS-release upgrade, ни NGINX integration
этим checkpoint не приняты. C0 counts сохраняются отдельно.

Первый C2a read-only probe реализован на изолированном pinned OpenSSL source.
[Профиль](C2A-PROFILE.md) и [evidence](../evidence/continuum-c2a.json) фиксируют
восемь реальных TLS cases, directional sequences, монитор initial application
keys/завершённого server KeyUpdate, private buffers и typed retry ledger.
Это узкий observation profile, локально и в research push/PR `99a017e`
проверенный без skips. Exact references и остальные CI состояния — в
[C2A-CHECKPOINT](C2A-CHECKPOINT.md).

Следующий bounded task — закрыть **C2a extended inventory**: peer-requested
KeyUpdate/read-key generation, завершение outstanding write retry,
control/alert/shutdown states, sequence/key usage limits и TLS-runtime
interruption cleanup. Format-policy и прежние отложенные native runs завершены.
READ retry completion и сохранение READ retry при постороннем WRITE теперь
имеют отдельные actual TLS cases; [retry evidence](../evidence/continuum-c2a-retry.json)
фиксирует новый implementation scope и pending hosted verification.
Неизвестные состояния не получают traffic grant.
Полнота inventory ещё не принята; решение о первом C2b exporter/importer
принимается после review этого gate. Public session APIs его не подменяют.

Не наращивать тысячи запусков toy fixture, панель, cluster или маркетинг
вместо проверки этого основного неизвестного. Source/binary/version changes
и ordinary drain/reconnect baseline остаются самостоятельными обязательствами.

## Окно самостоятельной разработки: 70 часов

Владелец 23 октября предоставил 70 часов самостоятельной разработки с
помощниками и сохранением в Git. Целевой срез к возвращению владельца —
**26 октября 2026, 14:16 UTC**. Это срок отчётного checkpoint, а не заранее
доказанная готовность полного продукта. Денежный bootstrap режим сохранён.

Порядок работы в этом окне:

1. Завершить hosted приёмку C1 именно на implementation SHA, сохранив отдельно
   пропуски, inherited repository checks и результаты разных test families.
2. Реализовать C2a в изолированной закреплённой сборке OpenSSL: read-only probe,
   inventory и bounded safepoint с отказом при неполном/неизвестном state.
3. После этого gate реализовать C2b semantic export/import и показать тот же
   поток после завершения source. Проверять nonce/sequence, key generations,
   pending bytes и unsupported states; не подменять перенос reconnect/resumption.
4. После успешного library gate начать узкий opt-in native NGINX adapter.
   Завершить окно независимыми отрицательными проверками, identity/evidence
   и ясным списком того, что пока не поддержано.

Каждая следующая часть зависит от доказательств предыдущей. Неудача gate
означает исследование причины и сохранение контрпримера; она не разрешает
сократить обязательное TLS state или объявить промышленную готовность.

## Коммерческий критерий разработки

[COMMERCIAL](COMMERCIAL.md) фиксирует первый ICP: B2B realtime SaaS с Linux
NGINX и измеримой ценой reconnect/долгого retirement. Предлагаются открытое
ядро и будущая подписка на проверенные релизы, управление и ограниченную
поддержку. $1 000/$3 000 в месяц — гипотезы для unit economics, не текущие тарифы.
Исторический сценарий $8 000 сохранён отдельно и не используется как цена запуска.

Следующий технический task — C2a extended inventory. Продажи или пилот не
являются условием продолжения самостоятельной разработки. Billing, новая панель и реклама не
подменяют реальный TLS bridge, native/application integration и независимое
сравнение с бесплатным drain/reconnect. Приёмка продукта должна измерить
полный вывод старого кода, сохранение потока, pause/overhead и стоимость поддержки.

## C2a: runtime interruption и source-change gate

Локально пройдены13 проверок: прежние10 TLS scenarios, два handled signals
после реального authenticated application READ и один no-TLS cached-import
source control. [Evidence](../evidence/continuum-c2a-interruption.json)
сохраняет независимый held-out case, два actual-TLS sensitivity refusals,
исходные неуспехи и ограничение private launcher вместо прямого CLI branch.
Native20/20, C0 core21/process7 и C1 tests22 пройдены отдельно. Новый exact
hosted SHA ещё ожидается. Это покрытие одной interruption boundary; прочие
crash/interrupt границы и полный TLS inventory не закрыты.
Следующий ограниченный task — actual peer-requested KeyUpdate/read generation
и response obligation, затем WRITE retry/control/shutdown/limits до C2b.

## Continuum C2a: входящий KeyUpdate

Добавлены два настоящих TLS scenarios с C-клиентом на той же закреплённой
OpenSSL3.0.13: REQUESTED update, READ generation и ожидающий ответ до WRITE;
затем реальный echo WRITE отправляет queued response без повторного запроса.
Probe неизменён: pending1/0 отказывает по32832, completed1/1 по64, повторное
наблюдение не меняет state. Epoch-relative sequences сверены до close_notify.

Финальный локальный aggregate —15/15:12 обычных TLS scenarios,2 handled
runtime signals,1 no-TLS source control. Независимо пройдены4 held-out cases.
C0 core21/process7, C1 **27=18 synthetic oracle controls+9 runtime checks**,
native20/20 пройдены. Official1083 strict PASS/25SKIP/1expectedTODO/0FAIL.
[Peer evidence](../evidence/continuum-c2a-peer-key-update.json) сохраняет hashes, build identities и ограничения.
Hosted85bc255 принят ранее; новый exact implementation SHA ожидает своей CI.

Оба C endpoint используют одну OpenSSL3.0.13; две relay TCP legs не являются
перенесённым соединением. Pending case закрывается raw; completed проверяет
точные данные, оба close_notify и FIN. PKI/hostname и Finished проверяет C
endpoint; observer не является независимым PKI/Finished verifier. Далее —
WRITE retry completion, overlap/control/shutdown/usage limits, затем C2b.
Semantic export/import, actual TLS-code update и native migration ещё не готовы.

## Continuum C2a: завершение той же WRITE retry

Новый actual-TLS case действительно получает WANT_WRITE, наблюдает две
неизменные refusal snapshots, возобновляет оба paused readers и завершает
исходный SSL_write_ex с тем же буфером, содержимым и полной длиной65536.
После success retry снят; две allowed snapshots предшествуют shutdown.
Неизменённый observer проверяет точный двунаправленный payload, sequences,
оба close_notify и FIN. Исходный probe, лимиты и native NGINX не менялись.

Локальный aggregate16/16:13 обычных TLS scenarios,2 runtime signals,1 no-TLS
source control. Независимые heldouts и negative sensitivity учтены отдельно
в [write evidence](../evidence/continuum-c2a-write-retry.json). C0 core21/process7, C1 27=18 synthetic+9 runtime,
native20/20 прошли; official1083 strictPASS/25SKIP/1expectedTODO/0FAIL.
Новый exact implementation SHA ожидает hosted CI;2fac5b5 принят ранее.
Далее — пересекающиеся retry obligations, control/alert/shutdown и usage limits.
Полнота inventory, semantic export/import и actual TLS-code migration не приняты.

## Continuum C2a: пересечение READ/WRITE retry

Добавлен actual-TLS case: READ/WANT_READ, затем отдельный WRITE/WANT_WRITE.
После возобновления обоих readers завершается исходный WRITE65536 с теми же
аргументами. READ остаётся незавершённым: повторные snapshots отказывают по16
при уже пустом active output. Оригинальный READ buffer не меняется; клиент
подтверждает точные65536 outbound bytes перед намеренным raw close.

Локально17/17:14 обычных TLS scenarios,2 runtime signals,1 no-TLS source
control; независимые heldouts учтены отдельно в [evidence](../evidence/continuum-c2a-overlap.json).
C0 core21/process7, C1 27=18 synthetic+9 runtime и native20/20 прошли.
Official1083 strictPASS/25SKIP/1expectedTODO/0FAIL сохраняются отдельно.
Новый exact SHA ожидает hosted CI; ea64ec1 принят ранее. Это проверка отказа
для unsupported overlap: wire=null, graceful closure и admission не заявляются.
Далее — control/alert/shutdown и sequence/key usage gates перед C2b.

## Continuum C2a: lifecycle TLS shutdown

Добавлен один actual-TLS server-shutdown-lifecycle: exact request/echo ACK,
первый фактический SSL_shutdown0/SENT1, две неизменные refusal snapshots,
затем explicit peer end и повторный SSL_shutdown1/SENT|RECEIVED3. Собственная
retry снимается, но закрытое состояние всё равно отвергается. Нулевой return
не является ошибкой: WANT_READ здесь только прежняя fixture-ledger convention.
После начала shutdown нет application I/O. Wire observer проверяет оба
close_notify, точные данные, FIN и final sequences с учётом alerts.

Локально18/18=15 ordinary actual-TLS scenarios+2 runtime signals+1 no-TLS
source control. Независимые heldouts и identities — в [evidence](../evidence/continuum-c2a-shutdown.json).
Core21/process7, C1 27=18 synthetic+9 runtime, native20/20 прошли.
Official1083 strictPASS/25SKIP/1expectedTODO/0FAIL учитываются отдельно.
Exact новый SHA ожидает hosted CI;996e997 принят ранее. Полный alert/control/
EOF/shutdown inventory и usage gates ещё не закрыты; далее эти границы доC2b.
Semantic export/import, смена TLS code и native NGINX continuation не готовы.

## Continuum C2a: unexpected transport EOF

Добавлен один actual-TLS case после exact request/echo ACK: клиент уничтожает
transport без TLS end/close_notify. Требуются фактический relay FIN и C READ
raw0/SSL_ERROR_SSL1/first-error reason294. RST, retry или clean close не PASS.
Две неизменные metadata snapshots отказывают; после fatal error нет TLS I/O
или SSL_shutdown. IGNORE_UNEXPECTED_EOF/quiet shutdown не включаются.
wire=null: full wire, server FIN и graceful closure этим case не заявляются.

Локально19/19=16 ordinary actual-TLS scenarios+2 runtime signals+1 no-TLS
source control. Независимые heldouts/cleanup/identities — в [evidence](../evidence/continuum-c2a-eof.json).
Core21/process7, C1 27=18 synthetic+9 runtime и native20/20 прошли;
official1083 strictPASS/25SKIP/1expectedTODO/0FAIL учитываются отдельно.
Exact новый SHA ожидает hosted CI;1f92d82 принят ранее. Другие alert/partial/
EOF/control states и usage gates остаются перед C2b. Semantic export/import,
смена TLS code и native NGINX continuation ещё не реализованы.

## Alpha: исчезновение процесса во время проверки идентичности

Исправлен контролируемый race чтения `/proc`: после `runtime_identity`
в `findMasters` выполняется одна немедленная проверка той же записи. Только
`ENOENT` позволяет пропустить исчезнувшего кандидата; отдельная проверка
записанного PID остаётся. Существующие Z/X, чужие/повторно использованные
PID и ошибки доступа не считаются подтверждённым завершением. CLI stop,
проверки перед сигналом и все 499 native source files не изменены.

Baseline даёт контролируемый `runtime_identity`; candidate проходит 28/28
синтетических тестов, независимые controls — 15/15. Native aggregate: 20/20
групп, включая реальный alpha lifecycle; official: 1083 strict PASS, 25 SKIP,
1 ожидаемый TODO, 0 FAIL. Core21/process7 также прошли. Counts synthetic
и настоящего lifecycle учитываются отдельно; исходники и identities — в
[evidence](../evidence/alpha-stop-identity.json).

Первоначальный сбой CI `d4bb2bc` сохранён: причина его точного interleaving
не доказана, повтор на том же SHA не был исправлением. Новый implementation
ожидает exact-SHA CI. Далее — сначала его результаты и возможные повторные
сбои, затем C2a alert/partial/control и sequence/key usage inventory. Атомарный
снимок `/proc`, pidfd fencing и перенос NGINX/TLS этим изменением не реализованы.

### Exact CI: alpha disappearance fix

Implementation `95fb43bb2f7c5795d341e638f7b287f7dd443214`: native push
`40045814679` и PR `40045819101` завершены success со всеми основными steps.
Research PR `40045819013` перепроверил неизменный C2a; research push
`40045814644` завершён success только scope, дорогой job skipped. Это
не новая TLS-проверка в push. [Очищенная CI-квитанция](../evidence/alpha-stop-hosted.json).
Первоначальный stop-сбой `d4bb2bc` и недоказанность его точной причины
сохранены. Далее — один ограниченный C2a state/usage case перед C2b;
перенос TLS/NGINX и pidfd fencing не реализованы.

## Continuum C2a: peer-first close_notify

Добавлен один actual-TLS case: после exact echo клиент явно завершает TLS.
Сервер обязан получить реальный READ raw0/ZERO_RETURN6/received2; это
чистый close_notify, не fatal SSL_ERROR_SSL. Прежний coarse ledger хранит
ERROR4; он не менялся. Две immutable snapshots запрещают перенос. Только
после STEP разрешён SSL_shutdown: actual1/flags3 и ещё две refusal snapshots.
IGNORE_UNEXPECTED_EOF/quiet shutdown выключены. Отказ4356 включает сохранённые
2 control bytes; это не доказательство непроцессированного alert.

Неизменный wire oracle проверяет exact data, оба close_notify/FIN и final
sequences. Relay FIN/end callback не объявляется remote delivery или
гарантированной TCP segmentation. Один READ с WANT_READ/fatal EOF не PASS.
Локально20/20=17 ordinary actualTLS+2signals+1noTLS control; независимые
actualTLS heldouts2. Core21/process7/C1 27 и native20/20 прошли. Native
исходники499 и alpha guards сохранены. Counts/identities/cleanup и initial
beforeguard smoke — в [evidence](../evidence/continuum-c2a-peer-close.json). Exact implementation CI pending.
Далее — truncated/partial closure и sequence/key usage gates перед C2b.
Export/import, actual TLS-code change и native NGINX migration не реализованы.

### Exact CI: peer-first closure

Implementation `2ca7892a7e1f448a98679da59e57e9a0023da2e8`: research push
`40050023137` и PR `40050026763`, native push `40050023101` и PR
`40050026739` завершены success. Оба research logs подтверждают21/7/27/20;
все основные native steps, включая feature-off и alpha package/checksum,
прошли. [Очищенная квитанция](../evidence/continuum-c2a-peer-close-hosted.json) сохраняет exact SHA/run IDs,
границы и отдельные checkout identities. Это read-only refusal observation,
не state migration. Далее — truncated/partial closure и sequence/key usage.

## Continuum C2a: truncated record body EOF

Добавлен один actualTLS case: authenticated handshake, одна ciphertext record
от Nodeclient, relay передаёт только body prefix и удерживает хвост. Первый
реальный READ даёт WANT_READ с partialbuffer и две immutable refusal snapshots.
Затем relay отбрасывает хвост и делает FIN только backendTCPleg. Повторяется
тот же READ с прежними buffer/length/sentinel: raw0/SSL_ERROR_SSL1/reason294,
plaintext0; ещё две refused snapshots. После fatal возврата только metadata
и cleanup, без TLS I/O/shutdown. RetryREAD остаётся bookkeeping, не разрешением
повтора после fatal. IGNORE_UNEXPECTED_EOF/quiet shutdown выключены.

Relay проверяет exact ciphertext record size и tail counts; только новый
case ограничен payload<=16384. Клиент остаётся жив, backend reads paused
изолируют fatalalert/RSTrace без подавления ошибок. Усечённый record сервером
не аутентифицирован. wire=null: fullwire/gracefulclosure/serverFIN не заявлены;
sequence metadata не wirevalidated. Это relay faultinjection, не прямой
обрыв клиентского соединения и не migration.

Локально21/21=18ordinaryTLS+2signals+1source; независимые actualTLS heldouts2,
ещё2 noTLS optioncontrols отдельно. Core21/process7/C127 и native20/20 прошли.
Prior20bytes, generic ledger/probe/oracle и499 native files сохранены.
[Очищенные evidence](../evidence/continuum-c2a-truncated-body.json) сохраняют identities/cleanup/границы и
setup corrections. Exact implementation CI pending. Далее — ограниченный
sequence/key usage gate для quiescent profile перед C2b; остальные
truncation/RST variants unsupported. Export/import и TLS-code change не готовы.

### Exact CI: truncated body EOF

Implementation `6cee2384e91e9fda4251c53dbeddce9cc951f473`: research push
`40054592561` и PR `40054596847`, native push `40054592543` и PR
`40054596722` завершены success. Оба research logs подтверждают21/7/27/21;
все основные native steps, включая feature-off и alpha package/checksum,
прошли. [Очищенная квитанция](../evidence/continuum-c2a-truncated-body-hosted.json) сохраняет exact SHA/run IDs,
artifact hashes и отдельные checkout identities. Это relay-injected refusal,
wire=null; не migration/full inventory. Далее — quiescent sequence/key usage.

## Continuum C2a: ограниченный допуск использования ключей

Probe теперь независимо отвергает read/write next sequence от `2^24`.
Это консервативная политика наблюдения initial application-key epoch,
а не контроль бюджета последующего I/O. Восьмибайтные counters сравниваются
точно; прочие ledger/buffer/control/generation guards сохранены.

Локально22/22:18 обычных actualTLS scenarios,2 runtime signals,1 noTLS
source control и1 synthetic predicate test с192 counter inputs. Независимо:
2 actualTLS low-counter heldouts,8527 pure-C synthetic vectors и отдельные
full-probe synthetic metadata controls. Большие counters не выдаются за
реальные TLS exchanges. Core21/process7/C1 27 и native20/20 прошли;
official1083 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL.
[Evidence](../evidence/continuum-c2a-usage.json) сохраняет исходные отказы setup и hashes. Exact implementation
CI pending; прежний6cee238 принят отдельно. Полнота inventory, semantic
export/import, runtime budget enforcement и TLS-code migration не реализованы.
Далее — exact CI, затем review C2a readiness для первого узкого C2b capsule;
остальные alert/EOF/partial variants остаются unsupported/fail-closed.

### Exact CI: directional record key usage

Implementation `b05ee33160b218854da4cac5710125b90e5ee8ac`: research push
`40058848933` и PR `40058853171`, native push `40058848929` и PR
`40058853120` завершены success. Оба research logs подтверждают21/7/27/22;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. Очищенная [квитанция](../evidence/continuum-c2a-usage-hosted.json) сохраняет
artifact digests, counts и отдельные checkout/build identities. Hosted official:
1105 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL; local1083 отдельно.
Это read-only admission policy, не future I/O budget enforcement или migration.
Далее — review C2a readiness для первого bounded C2b semantic capsule.

## Continuum: capsule metadata preflight

Добавлен metadata-only checker: строгие snapshot/source-identity поля и
точный directional budget для application/handover/closure records.
Closure резерв обязателен; сравнение использует BigInt и не сбрасывает
sequence. Eligibility означает только допуск к inventory review, без
traffic grant, экспорта secrets или runtime enforcement будущего бюджета.

Локально23/23 C2a:18 обычных actualTLS scenarios,2 runtime signals,
1 noTLS source control и2 synthetic groups. Новый checker:174 authored
controls; независимо6144 synthetic budget vectors и2 actualTLS snapshots.
Последние получены после cleanup и не являются live-hold proof.
Core21/process7/C1 27 и
native20/20 прошли; official1083 strictPASS/25SKIP/1expectedTODO-fail,
0unexpectedFAIL. Отдельные authored/independent controls и их исходные
отказы находятся в [evidence](../evidence/continuum-capsule-preflight.json).

Readiness review выявил конкретный blocker: возвращённый result.probe
получен после cleanup соединения, это не живой удерживаемый safepoint.
Следующий шаг — bounded C STEP после immutable probe pair и до любого
TLS READ/control/shutdown, затем runner decision/nonce/reobservation barrier
перед любым exporter. Остальные adapters/import/ownership/retirement
gates остаются отдельными. [Inventory readiness](C2B-READINESS.md) фиксирует
конкретные поля и code boundaries. Exact implementation CI pending.

### Exact CI: metadata capsule preflight

Implementation `deecc35825a706ac8b58d728f8f8a6e35b9d0986`: research push
`40062408179` и PR `40062412144`, native push `40062408165` и PR
`40062412125` завершены success. Оба research logs подтверждают21/7/27/23;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. [Очищенная квитанция](../evidence/continuum-capsule-preflight-hosted.json) сохраняет artifact
digests и отдельные event-head/checkout/build identities. Hosted official:
1105 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL; local1083 отдельно.

Это приёмка metadata/budget arithmetic, не живого safepoint или exporter.
Возвращённые snapshots являются post-cleanup историей. Далее — bounded C
STEP после immutable pair до любого TLS READ/control/shutdown и runner
decision/nonce/reobservation barrier, с abort/cleanup перед экспортом.

## Continuum: bounded live C hold

Новый opt-in `quiescent-live-hold` после настоящего TLS exchange получает
immutable probe pair и явно ждёт решения в C до следующего TLS I/O.
Bounded callback runner видит только metadata/identity и свежий challenge.
Продолжение требует корректного решения и неизменной повторной metadata;
abort/timeout/наблюдённая активность peer ведут к cleanup без TLS shutdown.
Старые scenarios и native NGINX сохранены.

Локально30/30 C2a:24 ordinaryTLS,2 OS signals,1 programmatic cancel,
1 noTLS source control и2 synthetic groups; прежние23 tests сохранены.
Независимо9 actualTLS cases:2 delayed continue и7 refusal controls,
включая отдельные C timeout/duplicate-control fault injections и peer close.
Исходный author smoke с ранним runner считается только diagnostic:
его3 PASS не приписаны final bytes; final fresh3 author cases прошли.
Pre-runtime deadline/schema corrections отделены от runtime failures.
Counts, cleanup и hashes записаны в [evidence](../evidence/continuum-live-hold.json). Core21/process7/C1 27 и native20/20 прошли;
official1083 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL.
Exact implementation CI pending. Наблюдение socket activity является
выборочным, не transport/ownership fence; caller ledger доверяет одному
владельцу. Result после возврата остаётся историей, live phase доступна
только внутри bounded callback.

Это source-side fixture barrier, не exporter/importer или migration.
Metadata preflight пока принимает только прежний `quiescent`: новый
snapshot нельзя переименовать ради admission. Далее — явно reviewed
held-profile admission и контракт protected-RAM source capsule capture;
секреты/cleansing, future budget, target ownership и retirement требуют
отдельной проверки. [Readiness](C2B-READINESS.md) сохраняет эти границы.

### Exact CI: bounded source-side C hold

Implementation `2debcc30101a72b1e5b08b22dd2ac9b0d040c401`: research push
`40065524807` и PR `40065527979`, native push `40065524846` и PR
`40065528012` завершены success. Оба research logs подтверждают21/7/27/30;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. [Очищенная квитанция](../evidence/continuum-live-hold-hosted.json) сохраняет artifact
digests и отдельные event-head/checkout/build identities. Hosted official:
1105 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL; local1083 отдельно.

Принят узкий opt-in source fixture hold: только bounded callback видит
удерживаемый source; returned result после cleanup является историей.
Это не exporter/importer, transport/ownership fence или migration.
Далее — combined reviewed live preflight binding и первый protected-RAM
read-only source capture после inventory/secret lifetime contract gate.
Held scenario не переименовывается в quiescent ради старого checker.


## Continuum: transient protected source record material

Добавлен opt-in CAPTURE внутри настоящего source C hold: отдельный held-profile
preflight связывает immutable pair, текущий nonce/serial и identity без
переименования scenario. C копирует только directional application secrets,
IV и next sequence в guarded mlock/DONTDUMP/DONTFORK страницу, переводит её
в read-only, сверяет subset/probe/ledger и очищает/unmap до release. Native
NGINX и прежние scenarios сохранены. Полный semantic capsule/API inventory,
reusable lifetime, importer, ownership и migration остаются отдельными gates.
[Контракт и ограничения](SOURCE-CAPTURE.md) не распространяют защиту копии на исходный SSL heap.

Локально35/35 C2a:28 ordinaryTLS,2 OS signals,1 programmatic cancel,
1 noTLS source control и3 synthetic groups. Прежние30 tests сохранены.
Независимо4 actualTLS:2 captures, actual mlock-limit refusal и stale CAPTURE;
ещё4096 synthetic controls:342 eligible/3754 refused плюс revoked Proxy.
Первый C capture отказал из-за очищенного handshake scratch; исправлен
переходом к digest negotiated cipher с прежними SHA256/cipher guards.
Исходные отказы и недоступный ptrace сохранены, syscall tracing не заявлен.
Core21/process7/C1 27 прошли. Native сначала17/20:2 отсутствующих HTTP3
clients и controller expectedB/actualA; после11 pinned wheels/2 venv —20/20.
Последний PASS не исправляет и не объясняет controller timing observation.
Official1083 strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL.
[Очищенный evidence](../evidence/continuum-source-capture.json) содержит source hashes, обе попытки и cleanup.
Exact implementation CI pending. Далее сначала controller counterexample/
contract review, затем reusable capsule inventory/lifetime; importer/migration
не реализованы. Это защищённая дополнительная копия, не whole-process защита.


### Exact CI: transient protected source sample

Implementation `fc7161945a5855e7c650609bef33cd4a66f2e448`: research push
`40071366794` и PR `40071371690`, native push `40071366797` и PR
`40071371664` завершены success, attempt1. Research logs подтверждают
21/7/27/35; оба full native workflows и artifacts сверены с точным SHA.
Hosted official1105 strictPASS/25SKIP/1expectedTODO-fail; local1083 отдельно.
[Очищенная квитанция](../evidence/continuum-source-capture-hosted.json) сохраняет digests, отдельные event-head/PR-merge
checkout/build identities и counts; raw artifacts/keys/logs не публикуются.

Это transient record-material sample, который очищается до release, не
reusable semantic capsule/exporter/importer или TLS-code migration.
Локальный исходный controller expectedB/actualA сохранён: последующие local
и hosted PASS не считаются его исправлением. Далее deterministic contract
review/counterexample, затем fuller capsule API inventory/protected lifetime.
