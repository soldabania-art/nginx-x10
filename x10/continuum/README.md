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
