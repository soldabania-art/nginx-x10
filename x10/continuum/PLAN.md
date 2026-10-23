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
