# NGINX X10: проверенное состояние

Состояние на **23 октября 2026 года**: полный native fork NGINX дополнен локальным контроллером конфигурации, закреплённой официальной выборкой тестов, реальным HTTP/3 interop и генерируемыми QUIC-проверками под санитайзерами. Последний единый локальный прогон завершился **15/15 успешных групп**: [milestone-5 JSON](evidence/native-checks-milestone-5.json). Этот этап меняет контроллер и проверяющие инструменты; native C и ранее собранный бинарник не изменены. Это development-кандидат; performance acceptance и готовность к production остаются открытыми.

## Основа и чтение исходников

База — upstream commit `148c75678cd4171338c31d4ed4c02411736d5fe9`, версия из `nginx.h` — `1.31.9`, ветка при получении — `master`. Закрепление этой development-версии записано в [upstream.json](upstream.json); исходные LICENSE и copyright сохранены.

[Первый проход чтения](review/coverage-summary.json) выполнен семью читателями: **533 текстовых файла кода и поддержки, 273 702 строки**. Ещё 10 исторических документов, 33 283 строки, находятся вне этого прохода; одна бинарная иконка учтена структурно. Диапазоны и хэши записаны в coverage-ledgers, агрегатор сообщает ноль ошибок согласованности. Это учёт прочитанного, а не формальное доказательство полного понимания, безопасности или проверки всех сочетаний платформ и модулей. Исходный [inventory](review/inventory.json) отражает начальное распределение; итоговые статусы находятся в coverage-summary.

[Механический каталог](feature-catalog.json) содержит **125 определений модулей, 783 записи директив и 3340 определений функций**. Счётчики включают варианты препроцессора и повторения по контекстам; они не обозначают столько уникальных возможностей, включённых модулей или выполненных тестов. Архитектурные выводы и инварианты находятся в [отчётах review](review/), включая [event/TLS/QUIC](review/event-tls-quic.md) и [независимую проверку parser patch](review/quic-cross-review.md).

## Конкретное изменение C

В [ngx_event_quic_transport.c](../src/event/quic/ngx_event_quic_transport.c) изменены три строки: тип ID в объявлении и определении helper расширен с `uint16_t` до `uint64_t`; числовое значение теперь должно полностью потреблять своё declared value поле (`p == end`). Исправлены **два класса дефектов**, воспроизведённые тремя контрпримерами:

- Неизвестный широкий ID больше не превращается в известный параметр, изменяя его значение или вызывая ошибочный отказ.
- Лишние байты после числового varint внутри declared value больше не принимаются. Допустимые неминимальные кодировки varint по-прежнему проходят.

Политика дубликатов не изменена: два случая принятия дубликатов явно записаны в `policyObservations`. Отклонение полученного дубликата — рекомендация SHOULD в RFC 9000; её ужесточение отложено. Эти наблюдения не считаются успешными строгими проверками. Parser harness включает настоящий production translation unit, заменяет только logging и не использует сеть; это проверка C-парсера, а не полного QUIC handshake или эксплуатируемости.

## Первый baseline: 22 октября 2026 года

[Профиль сборки](BUILD.md) проверен на Linux x86_64, GCC 13.3.0, OpenSSL 3.0.13; версии заголовков PCRE2 — 10.42, zlib — 1.3. Исходная и исправленная сборки содержат по **105 зарегистрированных compiled modules** в этом профиле. Установка в систему не выполнялась. Наличие исходника или модуля в бинарнике не означает runtime-проверку каждой его возможности.

| Проверка | Исходная версия | Исправленная версия | Evidence |
| --- | --- | --- | --- |
| Native build и `nginx -V` | Собрана | Собрана; `0755`, executable | [reference](evidence/build-reference.json), [fixed](evidence/build-fixed.json) |
| HTTP/TLS/HTTP2/reload | 11/11 | 11/11 | [reference](evidence/http-reference.json), [fixed](evidence/http-fixed.json) |
| Stream/mail | 12/12 | 12/12 | [reference](evidence/stream-mail-reference.json), [fixed](evidence/stream-mail-fixed.json) |
| QUIC parser strict | 8/11, exit 1: три воспроизведённых ошибки | 11/11, exit 0 | [reference](evidence/quic-reference.json), [fixed](evidence/quic-fixed.json) |
| Duplicate policy observations | Два принятых дубликата | Те же два наблюдения | Отдельный массив в parser JSON |

Итого исправленный кандидат: **11 + 12 + 11 = 34 strict PASS**, плюс два отложенных policy-наблюдения. Parser JSON содержит 13 случаев: 11 strict и два policy. Разные наборы проверяют разные границы; это не 34 проверки полного QUIC-соединения.

SHA-256 исходного бинарника: `adf05f3088bf8ee1ed7c886e424a2d92258323dd78e036276b41e009fbaf634e`.

SHA-256 исправленного бинарника: `66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`.

После сборки обнаружен режим `0644` при неизменном содержимом исправленного бинарника. Режим точечно восстановлен до `0755`, проверены `-V` и отказ manifest writer для неисполняемого файла. Затем HTTP и stream/mail повторно прошли на исправленном бинарнике. [Build evidence](evidence/build-fixed.json) фиксирует `built`, `0755`, `executable: true` и хэш; это снимок состояния, а не гарантия будущего состояния файла.

HTTP-набор проверяет native `-t`, два реальных loopback upstream, сохранность POST и отсутствие повторной отправки при транспортном отказе, доверенный CA/hostname и отрицательные TLS-контроли, downstream HTTP/2, streaming, успешный reload с живым старым потоком и отказ reload с синтаксической ошибкой. Stream/mail-набор проверяет TCP/UDP binary payload, SMTP/IMAP/POP3 greeting/capability, отказ и успех синтетического `auth_http`, backend handshake и tunnel. Его process mode — один native процесс без master; HTTP reload-набор использует master и worker. Это локальные синтетические fixtures, не реальные почтовые аккаунты.

## Разработка и проверка 23 октября

[Общий runner](test/all.mjs) сначала сверяет pin upstream, source diff, build manifest, бинарник, `-V` и generated headers; после выполнения сверяет их снова. Он отвергает непроверенные native source files, устаревший manifest и несовпадающий бинарник. [Отрицательные проверки runner](evidence/checker-verification.json) включают отказ до запуска suites при неверной provenance. Режим `--provenance-only` не считается функциональным прогоном.

Полный локальный запуск: `node x10/test/all.mjs --official`. [JSON результата](evidence/native-checks-fixed.json) фиксирует семь успешных групп; разные виды проверок не складываются в число улучшенных функций.

| Группа | Результат | Граница |
| --- | --- | --- |
| HTTP/TLS/HTTP2/reload | 11/11 | Реальные loopback upstream, CA/hostname, POST, streaming и два reload-сценария |
| Stream/mail | 12/12 | TCP/UDP, три почтовых протокола и auth/tunnel; single-process fixture |
| Дополнительные native features | 19/19 на обеих сборках | Static/HEAD/ranges/304/gzip, route/map/rewrite, Basic auth, Real-IP, limits и proxy cache |
| Первый QUIC parser regression | 11/11 strict | Два policy-наблюдения о дубликатах остаются отдельно |
| Генерируемые QUIC-свойства | 6 свойств, 8923 входа; расширенный прогон 18667 | ASan+UBSan без диагностик; это связанные входы, не столько независимых protocol tests |
| Локальное управление native master | 16 сценариев, 17 TAP checks с parent test | Init/bind/apply/revert/recover, отказы, конфликтующие изменения и прерывание CLI |
| Официальная выборка nginx-tests | 1083 strict PASS, 25 SKIP, 1 ожидаемый upstream TODO, 0 strict FAIL | 35 files: 32 PASS, 3 dependency skips; одинаковый результат upstream и X10 |

Официальные тесты закреплены на `47e78403ba756629adc3a8421bab700f344b7e3b` и не изменены. [Reference](evidence/official-reference.json), [candidate](evidence/official-fixed.json), [описание CI](CI.md). Пропущены FastCGI/SCGI/uWSGI files из-за отсутствующих optional clients; пропуски не считаются PASS. Upstream TODO относится к нормализации порядка значений `Accept-Encoding` в cache Vary и не объявляется новым исправлением. [Проверка timeout/SIGTERM cleanup](evidence/official-runner-verification.json) оставила 0 живых fixture-процессов и 0 временных корней.

Generated parser использует production translation unit. На исходном коде те же 8923 входа дают 940 расхождений ровно двух уже исправленных классов; остальные группы остаются успешными. [Fixed](evidence/quic-generated-fixed.json), [reference](evidence/quic-generated-reference.json), [extended](evidence/quic-generated-extended-fixed.json). LSan отключён из-за ограничения среды; [неуспешная попытка](evidence/quic-generated-leak-check-unavailable.json) сохранена как diagnostic-only, утечки не проверены.

Features fixtures имеют реальные отрицательные контроли: при `proxy_cache_lock off` проверка concurrent fill падает, а при включённой блокировке шесть клиентов дают один origin request. [Positive](evidence/features-fixed.json), [negative control](evidence/features-negative-control.json).

## Локальный контроллер

[CLI и пример](control/README.md) управляют одним self-contained loopback HTTP server fragment внутри явно указанного оператором include. Контроллер не меняет остальные байты `nginx.conf`, проверяет native `-t`, связывает master с PID namespace/UID/exe/start ticks, использует отдельный activation ID, свежие revision/health probes, exclusive lock и журнал ревизий. Apply, revert и подтверждённый rollback работают на настоящем native процессе. [16 проверенных сценариев](evidence/control-fixed.json).

Во время review исправлены обработка конфликтующих файлов при rollback, quoted/escaped directive names, наследование cache/POST в health route, trickle-response deadline и очистка изолированных fixture-процессов. Контроллер ограничен Linux и доверенным локальным оператором; удалённого admin API и TLS/RBAC пока нет.

Кандидат уже может обслуживать трафик во время health gate. Native handover допускает краткое обслуживание старым поколением после наблюдения нового; это не мгновенный общий cutover. Rollback не отменяет выполненные запросы. Известный разрыв между history append и state replacement теперь согласуется только при точном durable event intent и подтверждённом runtime; старый mismatch без intent и произвольное повреждение журнала требуют ручной проверки.

## Укрепление восстановления и протоколов

Полный локальный `node x10/test/all.mjs --official` после пересборки и восстановления execute-bit: **9/9 PASS**, controller **33/33 TAP**, official sample — прежние **1083 strict PASS / 25 SKIP / 1 expected TODO / 0 strict FAIL**. [Результат](evidence/native-checks-milestone-3.json) содержит неизменные до/после binary/source/manifest/generated identities. Этот прогон выполнен на замороженных файлах текущего рабочего дерева до публикации; результаты нового hosted CI проверяются отдельно по commit.

Третий development-этап добавляет durable event intent: `before/after` снимки
состояния и точный hash-linked event записываются до history append. Explicit
`recover` согласует только известные границы intent/history/state, проверяя
связи ревизий, неизменные файлы, master identity и свежий health. Завершённый
terminal event с оставшимся pending очищается без повторного reload. Формат
старых schema-1 records сохранён. Старый mismatch без intent, частичная история,
повреждение или противоречие остаются отказом с ручной проверкой.

[Новый recovery report](evidence/control-recovery-fixed.json) содержит **15
сценариев**, включая действительный SIGKILL предыдущего controller из
`29746068bfca299b85062e981df250aa3e12abb8`, воспроизводящий `history_integrity`.
Кандидат проверен на intent/history/state/intent-removal boundaries, повторном
прерывании самого recover, stale master, health regression и конфликтующих
файлах. При review исправлены present-but-falsy pending/intent и hash-valid
record с неверным типом `at`; такие входы теперь отвергаются до записи durable
данных. Полный controller TAP: **33/33** — 16 прежних и 15 новых сценариев,
плюс два parent tests. Все 15 masters recovery-набора завершились SIGQUIT exit 0.
Это проверка гибели процесса после fsync, не симуляция отключения питания.
На этом этапе `initialized_unbound` reconciliation был прочитан без отдельного crash-case; проверки инициализации добавлены в следующем этапе ниже.
Stale lock по-прежнему снимается только оператором после проверки процесса.

| Дополнительная группа | Candidate / pristine baseline | Что реально проверено |
| --- | --- | --- |
| [Mail TLS](test/MAIL-TLS.md) | 15/15 / 15/15, без skips | SMTP/IMAP/POP3 STARTTLS/STLS, implicit TLS, plaintext auth policy, capabilities/state reset, synthetic auth/tunnel, точный отказ неверного CA/hostname |
| [FastCGI/SCGI/uWSGI](test/ADAPTERS.md) | 21/21 / 21/21, без skips | Настоящий adapter wire framing/metadata, бинарный POST 71 687 bytes, chunked input, fragmented responses, invalid/truncated headers, incomplete body, preheader timeout |

JSON: [mail fixed](evidence/mail-tls-fixed.json), [mail reference](evidence/mail-tls-reference.json),
[adapters fixed](evidence/adapters-fixed.json), [adapters reference](evidence/adapters-reference.json).
Все fixtures используют loopback и синтетические backends. Это дополнительные
проверки сохранения возможностей; новых production C fixes в этих модулях нет.
Они не превращают skipped upstream tests в PASS и не заменяют реальные
mailbox/application-runtime interoperability проверки.

[Независимый protocol review](review/milestone-3-review.md),
[проверки validator и adapter CLI](evidence/protocol-runner-verification.json) и
[mail interruption](evidence/mail-tls-runner-verification.json) разделяют прямые
проверки функции validator и реальные запуски CLI. Прерывания после настоящего
старта native процесса возвращают неуспех и очищают процессы, сокеты и prefix.

Build manifest теперь записывает SHA-256, размер и полный permission mode трёх
generated inputs: `ngx_auto_config.h`, `ngx_auto_headers.h`, `ngx_modules.c`.
Runner сверяет их до и после suites. [16 проверок](evidence/build-identity-verification.json)
отвергают предшествующую запуску подмену, symlink, неверный тип/режим и изменение
во время записи manifest. Старый checker действительно пропускал pre-check
header change; контрпример сохранён отдельно от успешных новых проверок.
Manifest без новых identities требует реальной пересборки. Это локальная
согласованность build records, не signed/reproducible-build attestation.

Реальная пересборка сохранила SHA-256 candidate `66ba1756…` и 105 modules.
[Build snapshot](evidence/build-milestone-3.json) записал mode `0755`, однако
в следующем preflight файл оказался `0644`: ctime позже manifest, bytes и mtime
не изменились. [Отказ до запуска suites](evidence/native-checks-milestone-3-preflight-failure.json)
сохранён. [Точечное восстановление execute-bit](evidence/executable-mode-milestone-3.json)
вернуло `0755` при том же SHA и `-V`; причина смены режима не установлена.
Это наблюдение и ремонт состояния файла, не новое исправление C и не гарантия
будущих permissions. Полный прогон запускается после повторной проверки identity.

[Source review native handover](review/handover-boundaries.md) разобрал порядок
старта/остановки workers, TCP listener closure, активные потоки, respawn и QUIC.
Новый ответ может предшествовать закрытию старых TCP listeners. Контроллер
продолжает подтверждать sampled readiness; полный generation/listener fence
не добавлен и не заявляется.

## Storage failures, HTTP/3 и нативные инструменты: четвёртый этап

[Storage report](evidence/control-storage-fixed.json) содержит **32 новых сценария**.
На предыдущем контроллере воспроизведены две ошибки: caught I/O failure мог
испортить ещё восстанавливаемую pending stage; повторный recover мог принять
полную строку history без повторного успешного fsync. Теперь durable event и
terminal cleanup failures сохраняются для explicit recover, который повторяет
нужные fsync history/state/directory до удаления intent. Добавлены SIGKILL на
четырёх границах initialization, ошибки append/fsync/rename/directory sync,
повторного recover и terminal cleanup. Полный controller: **66/66 TAP checks**
(63 поведенческих сценария и три parent tests). [Независимый review](review/storage-failures-review.md)
подтверждает ограниченную crash/storage matrix; отключение питания, полная ACID
семантика и общий traffic cutover не доказаны. Partial history и противоречия
по-прежнему требуют ручной проверки.

[HTTP/3 fixture](test/HTTP3.md): **7/7 на candidate и pristine**, настоящий UDP
QUIC v1/TLS 1.3, ALPN `h3`, native `$http3=h3` и `HTTP/3.0`, без TCP fallback.
Проверены точные binary GET/range/fragmented POST, шесть одновременно
удерживаемых streams, отмена с завершением другого и нового stream в том же
соединении, точные отказы неверного CA и hostname. Все семь UDP transports на
каждом прогоне подтвердили закрытие; native SIGQUIT exit 0, без оставшихся
сокетов и fixtures. [Candidate](evidence/http3-fixed.json),
[reference](evidence/http3-reference.json), [hashed dependencies](evidence/http3-client-dependencies.json).
Client lock — aioquic 1.3.0 и девять зависимостей для CPython 3.12/Linux x86_64.
[Неуспешный HEAD diagnostic](evidence/http3-client-head-diagnostic.json) сохранён
для обоих бинарников: pinned client проверяет body length без исключения HEAD.
HEAD не входит в успешный scope этого aioquic-набора; fixture не обходит
клиентскую проверку и не объявляет это дефектом native NGINX. Отдельный
независимый клиент добавлен в пятом этапе ниже.

[QUIC frame boundaries](review/quic-frame-boundaries.md): **6579/6579 входов**
по шести свойствам на обеих версиях, ASan/UBSan без диагностик. Проверяются
field values, усечённые префиксы, длины и borrowing boundaries, разрешённость
frame types в типах packet и parser-local limits. Три наблюдения о неминимальном
frame type отделены от strict PASS. [Candidate](evidence/quic-frames-fixed.json),
[reference](evidence/quic-frames-reference.json),
[отдельный sensitivity control](evidence/quic-frames-negative-control.json).
Новый production C defect не подтверждён; semantic ACK/flow/final-size state,
полная connection state machine и 32-bit build не проверены. LSan отключён.

[Нативный C HTTP/1 client](bench/NATIVE-LOAD.md) прошёл **41/41** functional,
negative, interruption и ASan/UBSan проверок: [JSON](evidence/native-load-verification.json).
Он проверяет один фиксированный 1024-byte response profile и поддерживает
partial I/O, absolute deadlines, bounded concurrency и полное request accounting.
Это ограниченный fixture client, не общий HTTP conformance tool. Сам load client
и pristine native proxy-origin вынесены из Node hot path в
[новый comparison driver](bench/NATIVE-COMPARE.md).
[Независимый interop/load review](review/interop-load-review.md) отдельно
фиксирует 9 runtime controls, 32 direct aggregate controls и 15 synthetic driver
controls; они не выдаются за повтор полного owner suite.

Единый локальный прогон **12/12** сохраняет прежние 1083 official strict PASS,
25 SKIP, один expected TODO и ноль strict FAIL. Native source diff, binary,
build manifest и generated inputs совпали до/после. Это прогон замороженных
файлов рабочего дерева до публикации; hosted CI проверяется отдельно по commit.

## Диагностика listeners и независимый HTTP/3 HEAD: пятый этап

Финальный локальный aggregate после исправления HEAD cancellation: **15/15 PASS**,
controller **68/68 TAP**, observer **29/29 TAP**. [Полный JSON](evidence/native-checks-milestone-5.json)
содержит совпавшие native source/binary/manifest/generated identities до/после.
Official sample сохранил **1083 strict PASS / 25 SKIP / 1 expected TODO / 0 strict FAIL**.
Это прогон замороженных файлов до публикации; hosted CI нового commit проверяется
отдельно. [Controller JSON](evidence/control-listeners-fixed.json) сохраняет
18 сценариев первого parent, CLI snapshot/inspection и pre/post source hashes.

Добавлены ручные команды `snapshot-listeners` и `inspect-listeners` в
[локальный контроллер](control/README.md). Они записывают конкретные
идентифицированные native child processes и проверяют их владение одним
управляемым IPv4 TCP LISTEN inode. Команды используют обычные lock, file и
master identity guards, не посылают сигналов и не меняют apply/recover gates.
Успешное наблюдение возвращает `ok:true`, а отдельное `observation.state`
показывает `pending` или `closed`. Неизвестное состояние остаётся ошибкой.
[API и ограничения](control/LISTENERS.md), [разбор native generation contract](review/handover-generation-design.md).

Scope всегда `captured-processes-only`: это не complete generation fence.
Проверяются PID/NSpid/PPid/start ticks/UID/exe, PID и network namespaces,
до/после чтения собственных fd links. Повторные scans выявляют наблюдаемый
churn, но не доказывают его отсутствие. Поддерживается один loopback IPv4
LISTEN inode; wildcard, same-port TCP6, неоднозначность и недоступные данные
отвергаются. `/proc/.../task/.../children` отсутствует в локальном kernel;
bounded PPid scan служит явным fallback. Трёхсекундный elapsed budget
проверяется вокруг I/O; Node не может принудительно прервать зависший kernel
syscall. **29/29 TAP** observer controls включают границы ресурсов, PID reuse,
ошибки доступа, ENOENT races и закрытие ресурсов при истечении budget.
[Независимый review](review/listener-observer-review.md) отдельно выполнил
15 native/I/O controls, прерывание после фактически наблюдённого SIGSTOP и
36 direct aggregate-validator controls. Исходный отказ отсутствующего kernel
child-list интерфейса сохранён в [review JSON](evidence/listener-observer-review-controls.json).

[Живой handover fixture](test/HANDOVER.md) удерживает настоящий старый ответ,
останавливает только его worker через SIGSTOP и наблюдает ответ новой ревизии,
пока старый worker ещё владеет LISTEN fd. После SIGCONT тот же живой worker
теряет listener, сохраняя старый поток; второй reload не мешает точному
завершению `first:old\nlast:old\n`. Проверяется также реально отклонённый reload.
Observer и независимые fd/inode проверки записываются раздельно. Это разделяет
три события: новый ответ, закрытие captured listeners и завершение старого
потока. Новая конфигурация всё ещё может обслужить запросы до health gate.
[Candidate](evidence/handover-fixed.json) и [reference](evidence/handover-reference.json)
прошли по **7/7** case groups. [Реальный SIGTERM control](evidence/handover-runner-verification.json)
после SIGSTOP требует неуспеха, SIGCONT перед shutdown и отсутствия оставшихся
процессов, sockets и prefix.

[Независимый HTTP/3 HEAD fixture](test/http3-head.md): **4/4 candidate и pristine**,
отдельный curl_cffi 0.16.3/libcurl/ngtcp2 client с четырёхпакетным hashed lock.
Проверены точный GET размером 65 810 bytes, HEAD status/headers/representation
Content-Length и пустое API-visible тело, точные certificate failures неверного
CA и hostname. Обязательны `V3ONLY`, actual HTTP version 30 и native
H3/protocol/method headers. TCP fallback и отключение проверки TLS не допускаются.
[Candidate](evidence/http3-head-fixed.json), [reference](evidence/http3-head-reference.json),
[dependencies](evidence/http3-head-dependencies.json). Каждый запрос идёт в
отдельном ограниченном процессе, который закрывает Curl handle и проверяет
отсутствие принадлежащих ему sockets. API-visible empty HEAD body не доказывает
отсутствие DATA frames на raw wire. Старый aioquic diagnostic сохранён без изменений.
[Независимый HEAD review](review/http3-head-review.md) выполнил семь runtime
controls, 35 direct schema controls и четыре filesystem identity guard controls.
При проверке исправлена отмена: Python `InterruptedError` мог поглощаться
selector как EINTR и позволять запросам продолжиться после SIGTERM.
Теперь отдельное исключение `FixtureInterrupted` прерывает workflow, убивает
и reap-ит незавершённый request child, затем закрывает native process и prefix.
[Raw review controls](evidence/http3-head-review-controls.json) сохраняют прежнее
неверное поведение и финальную проверку реальной остановки запросов отдельно.

## Производительность: измеритель и открытый результат

[Driver](bench/README.md) проверяет одинаковые build profiles, SHA-256 и `-V`, точные 1024-byte ответы, ошибки, cleanup, AB/BA порядок, latency и Linux CPU/RSS. [Проверки самого driver](evidence/benchmark-verification.json) включают несовместимый профиль, SIGTERM и подмену manifest.

Сырые результаты сохранены без удаления неблагоприятных данных:

- [Первый A/B](evidence/benchmark-local.json): 16 samples, 0 request errors; candidate/baseline throughput для static C16 — **0,484**.
- [Одинаковый baseline под двумя метками](evidence/benchmark-identical-control.json): static C16 — **0,684**, proxy C16 — **1,623**, хотя SHA обоих бинарников одинаков.
- [Повтор A/B с четырьмя повторами по 2 секунды](evidence/benchmark-confirmation.json): static C16 — **0,826**, proxy C16 — **0,804**. Сам baseline изменялся от 812 до 12607 req/s между samples.

Эти контроли показывают существенную нестабильность измерения. Причина первого неблагоприятного результата не установлена; регрессия не исключена. Отношения не доказывают эффект C patch, который не исполняется в этих HTTP1 workloads. Node clients/upstream и общий хост ограничивают интерпретацию; наблюдение cgroup сохранено [отдельно](evidence/benchmark-observer.json). Ускорение и отсутствие регрессий не установлены. Для performance acceptance нужен более стабильный генератор/хост и дополнительные воспроизводимые workloads.

После завершения functional suites и остановки всех project fixtures выполнены
последовательные короткие замеры новым C client/native-origin driver: C16,
четыре повтора на метку и workload, 1000 ms admission и 250 ms warmup.
Каждый JSON содержит 16 samples, ноль request errors, совпавшие identities,
native SIGQUIT exit 0 и пустые cleanup errors. Node используется только для
оркестрации. Хост не выделен и не изолирован от других tenants.

| Новый замер | Static, отношение средних throughput | Proxy, отношение средних throughput |
| --- | --- | --- |
| [A/A, один pristine SHA под обеими метками](evidence/native-benchmark-identical-control.json) | 0,996 | 1,111 |
| [A/B, candidate / pristine](evidence/native-benchmark-comparison.json) | 1,068 | 1,028 |

Расхождение одинаковых бинарников остаётся существенным, особенно для proxy.
Это наблюдения работоспособного нового измерителя, без confidence intervals и
статистического acceptance gate. Они не устанавливают ускорение, не снимают
предыдущую неопределённость о регрессии и не относятся к QUIC hot path.
Сырые latency histogram bounds, CPU/RSS front/origin/client и контекст хоста
сохранены в JSON. Исторические Node evidence не изменены.

[Независимый review](review/milestone-2-review.md) перечисляет исправленные замечания и оставшиеся ограничения. Workflow [x10-native.yml](../.github/workflows/x10-native.yml) использует read-only permissions и закреплённые actions. Для milestone commit `cba2f9c9b94d6c0947d86e6290062803f07ae507` hosted native CI действительно завершился успешно: [PR run 39895867783](https://github.com/soldabania-art/nginx-x10/actions/runs/39895867783) и [push run 39895867104](https://github.com/soldabania-art/nginx-x10/actions/runs/39895867104). Эти результаты относятся к указанному commit; оформление последующих commit messages и fork CI policy проверяются отдельно. Старый milestone сохранён в ветке `checkpoint/milestone-2-before-style`. Проверка оформления commit messages на `ebb693ea8ae0b2833550991d7e59a4ec26973da6` прошла. Унаследованный F5 CLA workflow всё ещё падает из-за отсутствующей publisher integration: default branch остаётся исходным `master`, поэтому guard на development/integration ветках пока не используется этим событием. Подробности и ссылки — в [CI.md](CI.md); это не native test failure.

## Оставшиеся границы

- HTTP/3 получил семь aioquic interop cases и четыре независимых libcurl GET/HEAD/certificate cases. Raw-wire HEAD DATA absence, сетевые потери/миграция, browser/client matrix, QUIC connection-state matrix, полная TLS-library matrix и 32-битные сборки не проверены.
- Mail TLS/STARTTLS и FastCGI/SCGI/uWSGI получили описанные выше bounded fixtures. Расширенные TLS/protocol state matrices, upstream HTTP/2/multiplexing, остальные adapters/optional modules, ОС и аварийные ветки ещё требуют отдельных тестов. Проверка отказа reload охватывает синтаксис, а не все поздние side effects и ошибки инициализации.
- Полная официальная suite, длительный fuzzing, полноценная crash matrix и стабильная performance matrix ещё не выполнены. Генерируемые свойства и короткие loopback measurements не заменяют эти работы; преимущество «10x» не установлено.
- Публичный native gateway не развёрнут. Ранее размещённая на Vercel консоль относится к Node-прототипу; она не запускает и не подтверждает доступность native NGINX X10.

Следующие шаги и обязательства совместимости: [PLAN](PLAN.md). Команды сборки и локальных проверок: [README](README.md) и [BUILD](BUILD.md). Принимать следующие изменения следует по отдельным воспроизводимым baseline/candidate доказательствам.
