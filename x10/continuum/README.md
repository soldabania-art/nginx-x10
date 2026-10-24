# Continuum: исследование переноса живого TLS-соединения

Continuum исследует перенос уже установленного зашифрованного соединения между
двумя версиями процесса на одной Linux-машине. Цель — продолжить тот же поток
после завершения старого процесса, сохранив порядок и содержимое данных.
Это отдельный R&D-модуль; существующий native NGINX и его reload пока не получают
новый механизм переноса. Текущая реализация и её независимая проверка находятся
в разработке. Успешные проверки следует связывать с конкретными файлами,
профилем и hashes, а не с этим описанием целевой архитектуры.

Новизна гипотезы не установлена. Этот каталог не объявляет безопасный TLS-продукт,
промышленную готовность, поддержку произвольных обновлений или ускорение 10×.
Поэтапная приёмка и условия остановки: [PLAN.md](PLAN.md).

[Коммерческая стратегия](COMMERCIAL.md) задаёт будущую модель открытого продукта
с подпиской на проверенные релизы, управление и поддержку. [Экономика](ECONOMICS.md)
отделяет сценарные цены/COGS/CAC от фактических продаж и расходов.

В начальном process fixture варианты `v1`/`v2` используют общий worker-файл,
один Node executable и ручной adapter application state. Это подготовительный
эксперимент с разными процессами/представлениями состояния, а не две независимые
версии TLS-библиотеки или доказанное обновление native TLS-кода. Более сильная
цель ниже остаётся отдельным gate.

## Проверенный подготовительный срез C0

[Очищенный результат](../evidence/continuum-c0.json) фиксирует **21/21** core
тестов (11 records и 10 state) и отдельные **7/7** process тестов без пропусков.
Использованы буквальные публичные RFC 8448 records/keys/IV и RFC 5869 vector,
независимый peer, один client connect, завершение source до target I/O,
13 байт неполного encrypted KeyUpdate и 54 точных application bytes.
Перед PASS проверены нормальный TCP FIN, отсутствие trailing ciphertext и
ошибок AEAD. Loss of pending, неверный commit digest и четыре вида лишнего
хвоста должны отвергаться. Первоначальный false PASS для повреждённого хвоста
сохранён как контрпример и исправлен.

Это один Node executable и одна TLS library, общий worker-файл и ручной
application-layout adapter. Сам C0 не выполняет TLS `close_notify` или handshake
и не реализует смену библиотеки, автоматический compiler или native NGINX. Полный перенос
состояния C/TLS между независимыми releases этим срезом не доказан. Hosted CI
проверяет опубликованный commit отдельно; локальные результаты его не заменяют.

## C1: настоящий handshake и наблюдение records

Добавлен отдельный fixture: [C/OpenSSL server](handshake-server.c),
[Node TLS client и relay](handshake.mjs), [record observer](handshake-oracle.mjs)
и bounded [aggregate runner](handshake-check.mjs). Итоговая матрица содержит
**22 проверки**: 13 observer controls и 9 runtime cases. Итоговый локальный
запуск root подтверждён: **22/22 PASS**, exit 0. Hosted push/PR C1 и native
проверки implementation `193afe99` завершились success; точные runs и
границы приёмки — в [CHECKPOINT](CHECKPOINT.md).
Это отдельный набор, его counts не прибавляются к C0 как доказательство миграции.

Runtime cases: два положительных обмена, без KeyUpdate и с server KeyUpdate;
пять отказов до application data — unknown CA, wrong hostname, TLS 1.2 only,
cipher mismatch и ALPN mismatch; два фактических прерывания SIGTERM/SIGINT
после native listening с проверкой child exit и удаления private fixture PKI.
Клиент аутентифицирует server через fixture CA и hostname; согласуются TLS 1.3,
`TLS_AES_128_GCM_SHA256` и ALPN `continuum-c1`, без session resumption.

Relay сохраняет capture между **двумя TCP legs**: client→relay и relay→server.
Он не переносит socket или TLS state. Observer использует временные fixture
traffic secrets в RAM, независимо разбирает framing, проверяет AEAD, directional
sequence/KeyUpdate, exact application data, оба `close_notify`, отсутствие
trailing ciphertext и завершение TCP. Он не является независимым PKI verifier
и не проверяет Finished MAC: certificate/hostname и handshake authentication
остаются обязанностью Node/OpenSSL client. Observer controls на synthetic
records отдельно проверяют отказы при повреждениях и неоднозначных boundaries.

Локально наблюдались C/OpenSSL 3.0.13 и Node/OpenSSL 3.5.7: разные endpoints и
версии одной OpenSSL family, а не две независимые implementation families.
Source/executable hashes и runtime strings не фиксируют точные bytes всех DSO;
такой library pin здесь не заявлен. [OPENSSL-STATE.md](OPENSSL-STATE.md) отделяет
публичные getters от private record state. Следующий C2 начинает с read-only
instrumentation/inventory/safepoint pinned source; exporter/importer следует
только после этого gate. C1 не завершает перенос live OpenSSL state, обновление
TLS binary или native NGINX integration.

## C2a: read-only probe закреплённого OpenSSL

Новый [C2a probe](C2A-PROFILE.md) наблюдает private state отдельной pinned-source
сборки OpenSSL 3.0.13. В исходном checkpoint восемь реальных TLS scenarios прошли: quiescent,
partial header/body, unread plaintext, empty read retry, write backpressure,
queued и completed server KeyUpdate. Начальная quiescent metadata разрешена;
остальные состояния отклонены. Completed KeyUpdate подтверждён wire oracle,
а initial-generation gate отвергает его даже при getter NONE.

Команда `node x10/continuum/openssl-probe-check.mjs` выдаёт очищенные counts.
Исходники, статические библиотеки, compiler/tools и build metadata проверяются
по identity. Это read-only observation, а не полный inventory, допуск traffic,
semantic export/import или миграция. Следующий task расширяет inventory и
контрпримеры перед C2b. Hosted C2a требует результата именно implementation SHA.

Текущий набор дополнен `completed-read-retry` и `unrelated-write-read-retry`:
реальный WANT_READ завершается исходным READ, а посторонний WRITE success не
снимает эту caller obligation. Отдельные progress events и bounded ACKs
исключают подмену завершения чтения последующим echo. [Retry evidence](../evidence/continuum-c2a-retry.json)
учитывает 10-case набор и отдельные controls; прежний hosted checkpoint не
принимает новый код автоматически. Полнота состояния и перенос не следуют
из этих двух новых проверок.

## Проверяемая гипотеза переноса

Для явно поддержанного состояния можно определить переносимое представление,
адаптер между версиями и небольшой checker протокольных обязательств.
Новый процесс восстанавливает вычисление, продолжает читать/писать тот же
TCP socket и позволяет завершить старый процесс. Состояние переносится как
данные с явной семантикой, а не как дамп адресного пространства C.

Первый профиль намеренно узкий:

| Свойство | Исследовательская граница |
| --- | --- |
| ОС и размещение | Linux, одна машина, доверенный локальный coordinator и процессы одного оператора |
| Транспорт | Одно уже установленное TCP-соединение; без смены адресов, reconnect и нового socket к клиенту |
| Криптографический профиль | TLS 1.3, `TLS_AES_128_GCM_SHA256` (`0x1301`), одна согласованная семантика record state |
| Первая точка переноса | Объявленная безопасная граница record processing; неподдержанное состояние даёт отказ переноса |
| Изменение версии | Отдельный новый процесс с отличающимся record/state code; разные banners или PIDs сами по себе недостаточны |
| Приложение первого этапа | Ограниченный двунаправленный поток fixture-данных; HTTP/WebSocket state adapters — последующие этапы |
| Сбои | До commit возможен согласованный abort; восстановление после произвольного crash не обещается |

Linux/одна машина — ограничение этого эксперимента, не свидетельство того,
что проблема решена для containers, namespaces, Windows или другого kernel.

## Три разных уровня доказательств

1. **Established-record experiment.** Fixture явно задаёт synthetic traffic
   secrets и проверяет TLS record framing, AEAD и переход состояния. Он может
   доказать свойства record engine и конкретного handover. Он не выполняет
   authenticated TLS handshake, не проверяет сертификаты и не становится
   обычным TLS endpoint для произвольного клиента.
2. **Handshake и backend bridge.** C1 проверяет настоящее TLS-соединение с
   отдельным клиентом и наблюдение records. Следующий C2 изучает полный inventory
   и safepoint, затем adapter извлечения/восстановления established state
   закреплённого backend. Handshake не завершает этот adapter. Наличие session
   ticket либо успешной resumption не доказывает перенос прежнего соединения.
3. **Native NGINX integration.** Изучены connection/request/buffer/event/module
   lifetimes, добавлен opt-in adapter и перенесены реальные HTTP/WebSocket
   connections при обновлении native кода. Успех первых двух уровней не
   подтверждает этот уровень.

Для record-этапа не допускается подменять цель постоянным старым TLS helper,
который продолжает шифровать трафик после номинальной смены worker. Coordinator
может управлять передачей дескриптора и escrow, но не скрывать старый record
engine на пути данных. Завершение старого процесса проверяется отдельно.

Целевые исследовательские entry points:

```sh
node x10/continuum/check.mjs
node --test x10/continuum/process-handover.test.mjs
node x10/continuum/handshake-check.mjs
```

Первая команда относится к deterministic core checks, вторая — к synthetic TCP
process fixture, третья — к настоящему handshake/record observation. Третья
выводит очищенный JSON с counts и exit facts, без raw TAP или session material.
Ни одна команда не подтверждает OpenSSL export/import или NGINX integration.
Точные выполненные случаи и неподдержанные состояния перечисляются отдельно.

## Переносимое представление и адаптеры

Ниже — требования к проектируемому IR, а не обещание уже реализованного формата.

| Часть | Что должно иметь однозначное значение |
| --- | --- |
| Envelope | Версия формата, профиль, идентичности source/target code и adapters, connection/migration ID, номер переноса и ожидаемый owner |
| Transport binding | Проверенный переданный socket того же соединения, направления, флаги закрытия; одного числового FD недостаточно |
| Read state | Текущая traffic-key generation, нужный секрет/ключевой материал и следующий sequence number; состояние неполного входа, если профиль его разрешает |
| Write state | Независимая traffic-key generation/sequence, pending output и точный offset уже отправленных байтов |
| Protocol state | Отложенные KeyUpdate/alerts/закрытие, если они поддержаны; отсутствие такого поля не считается отсутствием обязательства |
| Application adapter | Порядок и ownership plaintext buffers, parser position, downstream/upstream связи и очереди соответствующего протокола |
| Resource limits | Ограниченные длины, размеры очередей, deadline и допустимое число переходов; проверка до выделения по недоверенной длине |

У IR нет указателей, callbacks, pool addresses, TLS backend objects или
предположения об одинаковом C layout. `source → target` — явно зарегистрированная
совместимость; обратный переход не следует из прямого. UInt64 сериализуются
без округления через JavaScript Number. Неизвестные версии, поля с неясной
семантикой и неподдержанные adapters отклоняются.

Адаптер переводит state representation. Checker отдельно проверяет профиль,
полноту обязательных полей, размеры, допустимые состояния, соответствие
transport и переход ownership. Успешный checker устанавливает лишь проверенные
условия в своей модели. Он не доказывает отсутствие ошибки в adapter, честность
уже скомпрометированного процесса или безопасность всего C/TLS backend.

## Handover и единственный владелец

Предлагаемый протокол требует отдельного изучения failure boundaries:

| Фаза | Разрешённое действие | Отказ и неопределённость |
| --- | --- | --- |
| Preflight | Target загружает совместимый код и adapter, не читая/изменяя клиентский поток | Неизвестный профиль оставляет соединение source |
| Quiesce | Source достигает объявленного update point и приостанавливает read, write, callbacks и мутации связанных timers/queues | Deadline не разрешает принудительно объявить состояние безопасным |
| Prepare | Переданы socket/capsule; target валидирует и резервирует ресурсы без data I/O | До commit возможен только подтверждённый abort с единственным source owner |
| Commit | Coordinator однозначно закрепляет право data I/O за target; source теряет это право до начала target I/O | Потерянный ACK не разрешает одновременно возобновить source и target |
| Continue | Target обслуживает тот же поток; проверены данные и исполнение нового code path | После target read/write нельзя восстановить source из старого snapshot без отдельного протокола |
| Retire | Source не владеет потоком и действительно завершён; временные references/секреты очищены | Живой старый TLS helper либо оставшийся source worker не считается полным переносом |

Факт наличия двух FD references к одному socket не создаёт эксклюзивность.
Протокол должен отдельно запрещать конкурентное потребление входа и повторную
отправку. Escrow reference может удержать socket открытым, но не восстанавливает
потерянное после commit userspace state. Crash, потеря coordinator или питание
между commit и ACK сначала остаются явно неподдержанными случаями.

Native NGINX generation/birth metadata и listener observation не являются
ownership fence Continuum. Их нельзя использовать как доказательство этой
передачи без нового, отдельно проверенного контракта.

## TLS и границы I/O

[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) задаёт independent read/write
sequence numbers, nonce construction, key changes и record limits. В частности,
§5.3 запрещает wrap sequence number; §4.6.3 требует правильного порядка
KeyUpdate, а §§5.1–5.5 задают framing/AEAD и ограничения ключей. Перенос должен
сохранять эти обязательства, а не начинать counters заново.

Первая безопасная граница не обязана совпадать с TCP packet, `read()` или
WebSocket frame boundary. Часть TLS record может находиться в userspace, другая
— в kernel receive queue. Неполная encrypted output запись также может уже
изменить состояние отправителя. Возможность переноса таких случаев **пока не
объявляется выполненной**. Для первого профиля допустим bounded отказ/ожидание
без смены owner; последующее расширение требует явных полей и новых проверок.

Если частичный output будет поддержан, target обязан продолжать именно остаток
того же ciphertext с известного offset. Повторное шифрование уже начатого
record или повтор его префикса недопустимы. Нельзя одновременно считать record
неотправленным для sequence state и уже частично отправленным для transport.

KeyUpdate рассматривается как переход направления и очереди обязанностей.
Его нельзя выключить только в миграционном checker и назвать профиль полноценным
TLS 1.3. Переходы до, во время и после переноса требуют отдельных случаев;
fragmented/coalesced post-handshake messages остаются отдельной границей.
Неподдержанный переход должен быть виден как неподдержанный, а не PASS.

Backpressure не разрешает неограниченно копить данные ради update point.
Нужны caps входа/выхода, сохранение порядка и bounded время попытки. Отказ
перенести одну connection может оставить старый worker живым; завершение всех
старых workers обещать нельзя, пока не определено поведение для каждой их
connection. HTTP request parsing, WebSocket fragmentation/control frames,
compression state и upstream TLS требуют самостоятельных adapters.

В C0 используются synthetic secrets; C1 создаёт временные локальные PKI и TLS
session secrets для своего fixture. Traffic secrets, private keys и capsules
не должны попадать в stdout, git, обычные logs или публичные artifacts. Работа
с памятью и очисткой secrets требует отдельного review; отсутствие их в JSON
не доказывает отсутствие копий в процессе или crash dump.

## Как отличать результат от демонстрации

Минимальный положительный результат содержит один клиентский connect, тот же
поток до/после update, проверенные новые source/binary identities, точные данные
обоих направлений, завершённый source и работу target после его завершения.
Число тестов, смена banner или передача FD без TLS state этого не заменяют.

Held-out проверки выполняет независимый читатель после freeze: другие
fragmentation schedules, сочетания направления/размера, порядок управляющих
сообщений и negative capsules. Корпус автора и held-out результаты хранятся
раздельно. Обнаруженная ошибка фиксируется вместе с исходным контрпримером;
после исправления нужен новый, ранее не использованный held-out набор.

Сравниваются три границы: корректный обычный drain, намеренный restart/reconnect
и Continuum в поддержанном профиле. Измеряются pause distribution, ошибки,
retirement time, peak RSS, CPU и стоимость состояния на connection. Локальная
демонстрация не подтверждает production scale или выигрыш throughput.

## Prior art и источники

- [Envoy hot restart](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart)
  описывает сохранение прежних connections в draining процессе, без передачи
  их новому процессу. Это конкретная граница для сравнения, не обзор всех proxy.
- [Kitsune, TOPLAS 2014](https://www.cs.umd.edu/~mwh/papers/hayden14kitsune-journal.html)
  исследует обновление C-программ и преобразование состояния по явным
  specifications. Общая идея смены кода с сохранением состояния уже известна.
- [TALOS, arXiv:2509.05150v1](https://arxiv.org/abs/2509.05150v1)
  исследует проверяемую миграцию состояния в TEE, включая replay/rollback и
  cloning. Это не утверждение о готовом TLS/NGINX adapter. Речь об этой работе,
  а не об одноимённых Talos Linux или TaLoS TLS termination проектах.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) — TLS 1.3;
  §§4.6.3, 5 и 7.2–7.3 — обязательные входные контракты record-исследования.

Возможный исследовательский вклад — практичный ограниченный cross-version
state contract и проверка его обязательств для живого encrypted потока.
Оригинальность, полнота и полезность такого вклада ещё требуют исследования.

## C2a: обработанное прерывание после настоящего TLS READ

[Interruption evidence](../evidence/continuum-c2a-interruption.json) отделяет
10 обычных TLS scenarios, два SIGTERM/SIGINT runtime controls и один no-TLS
cached-source control. Финальный локальный aggregate —13/13 без skips/failures.
Частный launcher вызывает неизменённый module API; после authenticated
handshake и первого успешного READ до echo проверяются handled failure,
завершение C child и удаление собственных PKI/сборок до fallback cleanup.
Это новое покрытие одной границы, не исправление доказанного production leak,
не graceful close и не перенос. Независимые held-out/negative controls,
промежуточные отказы и source identities сохранены отдельно. Hosted приёмка
нового SHA ожидается; затем продолжается peer/read KeyUpdate inventory.

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


## Continuum: bounded buffer-only keylog ingestion
В C2a Node keylog handler секреты и random больше не переводятся в
неизменяемые JS strings. Bounded parser разбирает NSS line из Buffer;
только public label становится строкой. Input event Buffer очищается при
успехе и отказе; decoded temporaries очищаются при ошибке/отсутствии передачи
владения. Exact framing допускает один optional LF, без trim/CRLF/padding.
Это явная очистка доставленного Buffer и parser-owned копий, не всех
Node/OpenSSL/V8 allocations или всей памяти процесса.

Synthetic baseline выполняет exact historical handler и сохраняет
неочищенный input как воспроизведённый дефект. Новый unit:14 accept/36 refuse,
2 partially decoded allocations очищены; independent lifetime review:
11 synthetic controls/16 временных Buffers. Эти случаи не TLS handover.
Два настоящих TLS heldouts прошли: quiescent и transient capture;10/10
доставленных keylog Buffers наблюдались нулевыми после synchronous handler.
Все43 наблюдавшихся child завершены,4/4 temporary roots отсутствуют.

Локально core21/process7/C1 27/C2a36, предыдущий35-test prefix сохранён.
Native --official20/20 и controller77/77;499 native inputs, LICENSE и
verification harness неизменны. Official1083 strictPASS/25SKIP/
1expectedTODO-fail/0unexpectedFAIL. Exact CI нового implementation pending.
Для прежнего47515734 оба native workflow/artifacts успешны; research push
runtime skipped, PR фактически выполнил21/7/27/35. Исторический expectedB/
actualA не переписан; исправлялся fixture contract, не controller/runtime.

Текущее прямое поручение —60 часов с24.10.2026 07:17:36UTC;
code stop26.10.2026 19:17:36UTC (23:17 Europe/Samara). Прежние70 часов
сохранены только в истории. После code stop — остановка собственных fixtures,
чтение результатов и итоговый отчёт без изменений кода.
Следующий gate: source-only reusable protected lifetime/API allowlist,
expiry/revocation и cleanup-before-release; importer/migration не реализованы.

[Очищенный evidence](../evidence/continuum-keylog-buffer.json) сохраняет точные проверки и границы.


### Exact CI: bounded keylog Buffer lifetime

Implementation `787f5f69e1f793b1b34e6d9b0acaa74381e059b8`: research push
`40074320805` и PR `40074324467`, native push `40074320788` и PR
`40074324454` завершены success, attempt1. Actual research logs:21/7/27/36;
оба native artifacts:20/20 групп, controller77TAP, alpha37TAP (28 synthetic
плюс9 original entries с parents), official1105 strictPASS/25SKIP/
1expectedTODO-fail/0unexpectedFAIL. Local official1083 учтён отдельно.
[Очищенная квитанция](../evidence/continuum-keylog-buffer-hosted.json) сохраняет ZIP digests и отдельные event-head,
PR merge checkout/build identities; source runtime files в receipt не менялись.

Это Buffer-lifetime hardening только C2a runner, не full-process erasure,
reusable semantic capsule, importer или migration. Следующий gate — C-owned
protected lifetime/opaque generation-bound handle, expiry/revocation и
cleanup acknowledgement before release; SIGTERM после реально заполненной
копии и late-after-timeout authority refusal требуют отдельных controls.
Полный semantic/API inventory, exclusive reader/writer ownership, distinct
TLS code и actual old-code exit остаются отдельными условиями приёмки.


## Continuum: retained protected source-copy lifetime

Opt-in `capture-held` сохраняет защищённую read-only копию record-material
между C-вызовами. Opaque C-slot связывает generation, исходные SSL/ledger,
nonce/serial и прежний monotonic deadline; terminal slot не открывается снова.
READY → DISCARD/ABORT → CLEARED подтверждает уничтожение до release либо
отказа. Истечение срока и SIGTERM после реально заполненной копии очищают
её без дальнейшего TLS I/O; поздний JS callback не восстанавливает authority.
SIGKILL остаётся explicit-wipe-unknown. Старый transient CAPTURE сохранён.

Локально финальный C2a43/43: прежние36 плюс7 actualTLS controls, из них
6 ordinary и1 SIGTERM-after-filled. Независимо5 actualTLS heldouts и11
synthetic cleanup-ACK controls прошли. Core21/process7/C1 27 и native20/20,
controller77/77; official1083 strictPASS/25SKIP/1expectedTODO-fail/0FAIL.
Первый42-case PASS — diagnostic: после его старта дополнены тестовые assertions
и native-expiry case; для final bytes выполнен отдельный43-case прогон.

[Evidence](../evidence/continuum-retained-capsule.json) сохраняет identities, baseline refusal,
независимые controls, cleanup и различие JS-timeout/native expiry. Это только
retained source record-material subset, не полный semantic capsule, importer,
ownership transfer или migration. Защита исходного SSL heap и полный syscall
fault matrix не заявлены. [Контракт](SOURCE-CAPTURE.md) задаёт source API allowlist
во время READY. Exact implementation CI pending. Далее — его приёмка, полный
узкий established-state API/inventory и оставшиеся protection-failure gates
до target reconstruction/import; distinct TLS code и old-code exit отдельно.


### Exact CI: retained protected source-copy lifetime

Implementation `f2f9684abf59064ec10c39ad1195b6d075b990a5`: research push
`40078352816` и PR `40078356587`, native push `40078352804` и PR
`40078356557` завершены success, attempt1. Оба actual research jobs
выполнили core21/process7/C1 27/C2a43 без FAIL/skip/TODO. Оба native
artifacts:20/20 групп, controller77TAP, alpha37TAP; official1105 strictPASS,
25SKIP,1expectedTODO-fail,0unexpectedFAIL. Local official1083 учтён отдельно.
[Очищенная квитанция](../evidence/continuum-retained-capsule-hosted.json)
содержит проверенные ZIP digests, отдельные event-head/PR merge checkout
identities и независимое static review без новых runtime reruns.

Это приёмка restricted retained source record-material lifetime/cleanup,
не полного semantic capsule, importer или migration. Полный established-state
semantic/API inventory и protection-syscall failure matrix остаются следующими
gates. LSan unavailable не считается PASS; SIGKILL/crash wipe неизвестен.
Exclusive ownership, distinct TLS code, actual old-code exit и native NGINX
continuation по-прежнему не реализованы. Runtime sources в receipt не менялись.


## Continuum: защита памяти при отказах

Source-only capture теперь повторяет уничтожение FAILED mapping без
восстановления authority и не снимает lock с неочищенных copied bytes.
[Контракт](SOURCE-CAPTURE.md) и
[проверки](../evidence/continuum-capture-protection.json)
отделяют synthetic production-TU fault controls от настоящих TLS exchanges.
Локально C2a44,18 synthetic fault cases, independent2 actualTLS и native20
прошли; неблагоприятные попытки сохранены, exact hosted CI нового кода pending.
Semantic/API inventory остаётся следующим gate,
не разрешением на importer, ownership transfer или migration.
