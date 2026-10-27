# NGINX X10: проверенное состояние

Состояние на **23 октября 2026 года**: полный native fork NGINX дополнен локальным контроллером конфигурации, закреплённой официальной выборкой тестов, реальным HTTP/3 interop и генерируемыми QUIC-проверками под санитайзерами. В седьмом этапе добавлены изолированная Linux alpha, читаемый operator status и явная проверка native поколений. Финальный локальный `--official` прогон завершился **20/20 успешных групп**, exit 0: [milestone-7 JSON](evidence/native-checks-milestone-7.json). Новый профиль содержит 19 обычных / 20 с official групп. Hosted native CI `0b6a87e` завершился успешно; новый Continuum checkpoint проверяется отдельно. Это development alpha; performance acceptance и готовность к production остаются открытыми.

## Основа и чтение исходников

База — upstream commit `148c75678cd4171338c31d4ed4c02411736d5fe9`, версия из `nginx.h` — `1.31.9`, ветка при получении — `master`. Закрепление этой development-версии записано в [upstream.json](upstream.json); исходные LICENSE и copyright сохранены.

[Первый проход чтения](review/coverage-summary.json) выполнен семью читателями: **533 текстовых файла кода и поддержки, 273 702 строки**. Ещё 10 исторических документов, 33 283 строки, находятся вне этого прохода; одна бинарная иконка учтена структурно. Диапазоны и хэши записаны в coverage-ledgers, агрегатор сообщает ноль ошибок согласованности. Это учёт прочитанного, а не формальное доказательство полного понимания, безопасности или проверки всех сочетаний платформ и модулей. Исходный [inventory](review/inventory.json) отражает начальное распределение; итоговые статусы находятся в coverage-summary.

[Первоначальный механический каталог закреплённого snapshot](feature-catalog.json) содержит **125 определений модулей, 783 записи директив и 3340 определений функций**. Счётчики включают варианты препроцессора и повторения по контекстам; они не обозначают столько уникальных возможностей, включённых модулей или выполненных тестов. Архитектурные выводы и инварианты находятся в [отчётах review](review/), включая [event/TLS/QUIC](review/event-tls-quic.md) и [независимую проверку parser patch](review/quic-cross-review.md).

## Первый parser patch C

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

## Native поколения конфигурации: шестой этап

JSON этого этапа публикуются как `public-evidence-summary`: результаты,
имена проверок и хэши без внутренних путей, runtime process/namespace IDs,
сырых конфигураций, сведений о сертификатах и логов. Полные исходные records
сохранены локально; в каждой сводке указан их SHA-256. Сводки не являются
входом для aggregate validator, который проверял полные результаты suites.

Добавлен read-only `GET /1/control/generations` в явно включённый native control
API. Начальная конфигурация получает generation `"1"`; каждый успешно принятый
HUP/PATCH cycle — следующий ID. Каждый успешный parent fork получает новый
birth serial, включая respawn и повторное использование slot. Старый worker
с активным ответом сохраняет прежнее поколение. Отклонённый reload ничего не
прибавляет. IDs передаются decimal strings, без потери uint64 precision;
неизвестные и exhausted состояния не превращаются в достоверные значения.
[Контракт](review/native-generation-contract.md), [per-file ledger](review/native-generation-ledger.json).

Изменения ограничены четырьмя Unix C/H files; `ngx_cycle_t` и `ngx_process_t`
layouts и старые поля `/1/control/processes` не изменены. Новое поле discovery
аддитивно. Без активного control socket hooks не ведут identities; без
`NGX_CONTROL_API` feature не компилируется. Worker ACK/listener fence и обычные
условия apply/recover не добавлены. `available:true` означает классификацию
master bookkeeping, а не worker readiness, health или завершение старых потоков.
Master PID требует внешней привязки к namespace/start ticks: IDs не глобальны
между restart/exec. Реальный binary upgrade ещё не проверен.

| Проверка | Результат | Evidence |
| --- | --- | --- |
| Существующий control API | 9/9 candidate и pristine; явный ephemeral IPv4 loopback | [candidate](evidence/control-api-fixed.json), [reference](evidence/control-api-reference.json) |
| Native generations | 10/10 candidate; reference 3/3 с ожидаемым 404 нового endpoint | [candidate](evidence/generations-fixed.json), [reference](evidence/generations-reference.json) |
| Counter/serialization boundaries | 20/20, 18 реально rendered JSON records, ASan/UBSan без диагностик | [JSON](evidence/generation-boundaries-fixed.json) |
| Control feature выключен | 4/4, реальная отдельная сборка, 105 modules и остальные flags сохранены; `-l` отклонён | [JSON](evidence/control-disabled-build.json) |
| Runtime interruption | 2/2 после живого старого ответа, неуспех и полная cleanup | [JSON](evidence/control-api-runner-verification.json) |
| Единый локальный profile | 18/18; controller 68 TAP, observer 29 TAP; official 1083 PASS/25 SKIP/1 TODO/0 FAIL | [milestone-6](evidence/native-checks-milestone-6.json) |

[Независимый review](review/native-generation-review.md) также проверил реальный
пакет из двух принятых PATCH до одного нового worker spawn sweep: поколение
перешло с 1 на 3, новые workers получили поколение 3. Отдельные 137 direct
контролей validator включают три положительных record и 134 отклонённых
мутации; это не 137 runtime-сценариев. [Доказательства](evidence/native-generation-review-controls.json).
Реальные отказы fork/памяти/отправки, неуспешная worker initialization и binary
upgrade остаются source-reviewed путями без соответствующей fault injection.

[Реальная пересборка](evidence/build-milestone-6.json) записала candidate SHA-256
`e150b0a6e15c3799384e141ea548c658f1ce126ad2eb996a3965ab6791e0a139`,
105 compiled modules и прежний профиль зависимостей. Default binary/manifest и
три generated input остались неизменны при отдельной feature-off сборке.
Все suites проверены на замороженных файлах до публикации; hosted CI нового
commit проверяется отдельно.

Локальный kernel отклоняет AF_UNIX `socket()` с EPERM; [неуспешный Unix diagnostic](evidence/control-api-unix-unavailable.json)
сохранён и не считается PASS. Основной local aggregate явно использует
`127.0.0.1` ephemeral TCP без fallback. Hosted CI отдельно обязан пройти Unix
control API и generations, затем feature-off build. Никакой постоянный или
внешний management listener в проекте не развёрнут.

Это новая наблюдаемость native процессов, не увеличение throughput.
[Срез продукта и этапы выпуска](ROADMAP.md) отделяет готовое от будущего:
локальная alpha, измеренная beta и кандидат промышленного релиза.

## Локальная Linux alpha и operator status: седьмой этап

[Quickstart](QUICKSTART.md) описывает установку проверенного native build в новый
личный каталог, foreground `run`, явный `bind`, применение/откат, `stop`, новый
запуск и guarded `uninstall`. Системная установка и `sudo` не нужны. HTTP и
комплектный self-check слушают только loopback; этот self-check проверяет демо,
а не внешнее приложение. Обычный запрос обрабатывается native C-бинарником.
Новый `run` создаёт отдельную сессию `runs/<session>` с последним подтверждённым
содержимым; прежние controller histories сохраняются отдельно. Это не перенос
старой привязки на новый master и не непрерывная история между master lifetimes.

`status --human` показывает подтверждённую revision, привязку master, результат
существующего revision-header probe, изменённые файлы и pending transaction с
подсказками оператору. JSON и exit semantics прежнего `status` сохранены:
`ok:true` означает успешное получение состояния, включая unbound или stale
runtime, а не готовность приложения. Health и listener drain этой командой
не проверяются.

Новая read-only команда `inspect-generations --state PATH --control-socket PATH`
обращается только к явно выбранному API. Для прямых локальных проверок доступен
явный `--control-address 127.0.0.1:PORT`. До и после GET проверяются bound master
lifetime, PID/network namespaces, ownership LISTEN inode, зарегистрированные
файлы и бинарник. Native PID сопоставляется с PID внутри namespace master;
путь `/proc` использует отдельный proc PID. Ответ ограничен по времени HTTP,
размеру и числу процессов; uint64 остаются decimal strings. Достоверно полученное
`native.available:false` сохраняет reason/null identities, а не превращается
в readiness. Endpoint не открывается автоматически, условия apply/recover
не изменены. Procfs guards являются выборками; checked I/O budget не может
прервать зависший kernel syscall.

Целевой TCP-набор operator status прошёл **30/30 TAP**, включая actual native
generation 1→2, foreign endpoint без отправки HTTP, отказы схемы/размера/deadline,
закрытие выбранного endpoint во время наблюдения и stale master. Независимый
runtime review прошёл **9/9** отдельных контролей. [Независимый review](review/local-alpha-review.md)
отдельно подтвердил **8/8** package controls на замороженных файлах.
Эти проверки не складываются с aggregate в число независимых функций.
Наблюдалось различие local/proc PID в одной
реальной procfs-конфигурации; произвольная namespace matrix не проверена.

Alpha package собирается из подтверждённого build manifest, содержит native
бинарник, Node CLI, примеры и лицензии. Bundle допускает установку без исходного
checkout и сборки, но требует Node.js 22+ и совместимые динамические библиотеки.
Это не универсальный Linux binary и не Windows-порт. `stop` использует SIGQUIT
только для установленной идентичности; abnormal exit и неизвестные файлы
препятствуют автоматическому продолжению/удалению. Полная crash/update matrix
упаковки ещё не проверена.

Обычный alpha `run` не включает native control API. Опция `--control-socket`
принимает новый private Unix path непосредственно внутри установки; TCP
management listener и fallback при запуске пакета не включаются. Локальный
kernel по-прежнему запрещает AF_UNIX; обязательный hosted gate отдельно запускает
control API, generations и operator-status по Unix, затем feature-off build.
CI настроен готовить tar и SHA-256 sidecar: [описание проверок](CI.md).

Финальный локальный [milestone-7 aggregate](evidence/native-checks-milestone-7.json)
прошёл **20/20**, exit 0: operator-status **30/30 TAP**, alpha lifecycle **9/9**,
controller **68/68**, observer **29/29**. Official sample: 35 files, 32 PASS и
3 dependency skips; **1083 strict PASS / 25 SKIP / 1 expected TODO / 0 strict FAIL**.
У новых operator/alpha групп нет skips, TODO или cancellations. Native C на
этом этапе не менялся; SHA-256 бинарника остался
`e150b0a6e15c3799384e141ea548c658f1ce126ad2eb996a3965ab6791e0a139`.
Это локальный прогон замороженных файлов до публикации. Hosted run `0b6a87e` позднее прошёл обязательные Unix проверки; см. уточнение ниже.

Hosted CI commit `6467be3bd8efcfb70050181ce2d4a031a543a933` выявил
ошибку отрицательного alpha fixture: проверка с системным Node получила код
отказа вне ожидаемых вариантов; конкретный код старый fixture не сохранил.
Fixture теперь использует собственную копию native binary с другим путём и
требует именно `build_identity`. Установка в том hosted прогоне работала;
полный aggregate оставался failed, а Unix/package gates не запускались.
Новый локальный [milestone-8 aggregate](evidence/native-checks-milestone-8.json)
после поправки прошёл **20/20**, exit 0; alpha **9/9 TAP**, official sample —
**1083 strict PASS / 25 SKIP / 1 expected TODO / 0 strict FAIL**. Hosted Unix, feature-off и package gates позднее прошли на commit `0b6a87e`; см. уточнение ниже.

## Guard: первый исследовательский срез

[Детерминированное ядро](proof/README.md) выполняет две последовательности
запросов synthetic tenants на отдельных пустых native caches. В проверенном
профиле ключ без tenant воспроизводит получение чужого marker; ключ с tenant
сохраняет изоляцию и реальные cache HIT. Отключение cache отклоняется по
отдельному требованию его эффективности. Некорректный ответ fixture является
ошибкой проверки, а не найденной утечкой. Targeted suite прошла **8/8 TAP**,
без skips/TODO; включает действительный SIGTERM во время живого native запроса.
Она запускается в CI отдельным обязательным шагом, сверх aggregate из 20 групп.

Это специально подготовленные конфигурации и synthetic labels, не проверка
настоящей авторизации или произвольного клиентского nginx.conf. Интеграция LLM,
автоматический поиск исправлений и преимущество перед существующими подходами
ещё не реализованы/не установлены. [Исследовательский проект](review/guard-research.md)
задаёт prior art, контрольные сравнения и критерии будущего AI-эксперимента.
Полная совместимость, production isolation и доказательство всех запросов
из этого результата не следуют. Native C и бинарник этого среза не менялись.

[Независимый review](review/guard-kernel-review.md) отдельно прошёл семь групп,
включая шесть отказов до запуска выбранного binary. Он не суммируется с TAP.
[Cache dependency compiler](review/cache-dependency-research.md) — отдельная
концепция нового ядра; её checker/native adapter, новизна и экономический эффект
ещё не реализованы и не доказаны.

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

## Подтверждённый hosted checkpoint перед Continuum

[Native run 39971890181](https://github.com/soldabania-art/nginx-x10/actions/runs/39971890181)
для commit `0b6a87eac9af93607f47bba874007901b8125b30` завершился success.
Aggregate прошёл 20/20, отдельные Guard 8/8, operator-status Unix 30/30,
обязательные Unix API/generations, feature-off build и alpha tar/checksum —
успешно. Hosted official sample: 1105 strict PASS, 25 SKIP, 1 expected TODO,
0 strict FAIL. Это обновляет прежние ожидания CI, сохраняя историю отказа
первого alpha negative fixture и последующего исправления.

При разработке Continuum штатный local aggregate повторён без изменений C:
[20/20 групп](evidence/continuum-c0-native-regression.json), прежний native
binary SHA сохранён; official sample — 1083 strict PASS, 25 SKIP,
1 expected TODO, 0 strict FAIL. Continuum проверяется отдельными наборами
и не добавляет этим результатам performance или production acceptance.

## Continuum C0: ограниченный record/process эксперимент

[Концепция](continuum/README.md), [план](continuum/PLAN.md),
[экономика](continuum/ECONOMICS.md) и [регламент команды](continuum/OPERATIONS.md)
записаны в Git по поручению владельца. Часовая hosted automation включена;
фактический следующий успешный проход ещё не наблюдался. Она заново собирает
доступную команду по свежему Git checkpoint и кооперативному branch lease,
а не сохраняет постоянно живые сессии помощников.

[Core/process evidence](evidence/continuum-c0.json): **21/21** records/state
и отдельно **7/7** process TAP. Клиент сохраняет одно TCP-соединение, source
завершён до target I/O, 13 байт partial encrypted KeyUpdate перенесены,
54 application bytes совпадают, terminal FIN/pending0 проверены.
Независимая проверка нашла и исправила прежний false PASS при повреждённом
или неполном ciphertext после ожидаемого payload; контрпример сохранён.

Один Node binary/TLS library и shared worker с ручным v1/v2 layout adapter
не доказывают cross-release TLS upgrade. На этапе C0 handshake/OpenSSL bridge,
native NGINX, automatic adapter compiler, partial-output/backpressure/crash
matrix и TLS close_notify ещё не реализованы. Нативная основа не менялась. Новый hosted
результат относится только к опубликованному SHA и проверяется отдельно.

## Continuum C1: настоящий TLS handshake и наблюдение records

[C1 evidence](evidence/continuum-c1.json): локальный aggregate прошёл **22/22** —
13 проверок отдельного wire observer и 9 проверок реального C/OpenSSL↔Node TLS
стенда. Клиент проверяет CA и hostname. Проверены TLS 1.3 / AES-128-GCM / ALPN,
точные challenge-bound application bytes, server KeyUpdate и двусторонний
authenticated `close_notify` с FIN. Пять отрицательных профилей отклонены до
application I/O. Observer проверяет AEAD, границу handshake/application,
sequence и завершение; PKI и Finished MAC проверяет TLS endpoint.

Независимый review отдельно подтвердил 7 wire/trust/crash controls на runner
до lifecycle patch и 2 прерывания уже после реального application echo на
финальном runner. Найдены и исправлены false PASS при аварии C child во время
ALPN reject и остаток временных PKI-файлов при SIGTERM. Последний контрпример
воспроизведён до исправления; после него временный каталог удаляется и child
завершается. Авторские SIGINT/SIGTERM controls также проверяют освобождение порта.

Это recording relay с **двумя TCP-соединениями**. Он не переносит живое TLS
состояние. OpenSSL export/import, native NGINX migration и смена TLS release
остаются следующими этапами. Версии backend наблюдаются, но shared library
bytes не закреплены. Сертификаты/traffic secrets/wire captures не публикуются;
полное стирание памяти managed runtime не доказано.

Нативная регрессия повторена: [20/20 групп](evidence/continuum-c1-native-regression.json),
1083 strict PASS, 25 SKIP, 1 expected TODO, 0 strict FAIL в official sample.
Native binary и C0 source hashes сохранены. CI classifier теперь проверяет
delta события, пропускает дорогие jobs при metadata-only изменении и при
неопределённости запускает проверки; SHA в concurrency сохраняет предыдущий
implementation run. Hosted C1 принят на `193afe99`; exact runs записаны в
[checkpoint](continuum/CHECKPOINT.md).

Следующий bounded task C2 — read-only instrumentation закреплённого OpenSSL:
инвентаризация sequences, key generations, pending buffers и control obligations,
затем проверяемый safepoint. Semantic exporter/importer разрабатывается после
этого контракта; opaque context copying не используется.

## Continuum C2a: read-only probe закреплённого OpenSSL

Реализованы изолированный build OpenSSL 3.0.13 из exact source/tree, узкий
key-install monitor, private-state probe, C fixture, независимый Node TLS client
и очищенный aggregate. [Профиль](continuum/C2A-PROFILE.md),
[evidence](evidence/continuum-c2a.json) и per-file ledger сохраняют identity,
контрпримеры и ограничения. Реальные TLS cases локально прошли **8/8** без skips.
Quiescent metadata совпадает при двух наблюдениях; directional next sequences
сверены с wire. Partial header/body, unread plaintext, empty retry, реальный
WANT_WRITE, queued и completed KeyUpdate отвергнуты. Completed server update
имеет read generation 0/write 1, key-event serial 3 и getter NONE; wire oracle
подтвердил KU/new-key records и нормальный TLS close.

Публичный `SSL_pending()==0` не показывает полноту TLS obligations. Probe
не делает SSL/BIO I/O. Typed caller ledger доверяет одному владельцу; он не
является lock или detector конкурентных вызовов. Key-event serial не отслеживает
все мутации SSL. Read-only `allowed` не выдаёт traffic grant, не доказывает
полноту inventory и не подтверждает перенос. Негативные partial-I/O fixtures
завершают transport без заявления graceful TLS closure.

Нативный код сохранён. [Регрессия](evidence/continuum-c2a-native-regression.json)
повторена: **20/20 групп**, official 1083 strict PASS / 25 SKIP /
1 expected TODO / 0 strict FAIL; binary SHA прежний. C0: 21 core и 7 process;
C1: 22/22. Research push/PR для implementation `99a017e` завершились success:
21 core, 7 process, 22 C1 и 8 C2a без skips/failures в обоих runs.
Оба native push/PR implementation также завершились success.
Exact CI references и отдельные проверки repository — в
[C2a checkpoint](continuum/C2A-CHECKPOINT.md).

Whitespace CI первого implementation отверг пять single-space context markers
в unified patch. Baseline воспроизведён; точный `.gitattributes` path сохраняет
их как синтаксис diff, не меняя patch или правила C/native files. После этого
полный PR history `git log --check` локально имеет exit 0 и пустые diagnostics.
Hosted проверка этой metadata/policy поправки принимается отдельно.

Независимый reviewer дополнительно проверил четыре TLS cases с новыми
размерами/фрагментацией и два отказа при подмене build identity. Семь synthetic
monitor boundary controls учитываются отдельно от реального TLS. Исходные
C/probe/patch bytes сохранены; в частную JS-копию добавлен доступ к harness.
Точные root 8/8 используют неизменённый runner. Временные build/binary/PKI
каталоги независимого прогона удалены.

Следующий task — extended inventory: peer/read KeyUpdate, retry completion,
control/alert/shutdown, usage-limit admission и actual TLS-runtime interruption.
Semantic export/import, разные TLS code releases и native integration ещё
не реализованы. Коммерческая модель и бюджет сохранены без новых покупок.

## Continuum C2a: lifecycle незавершённого чтения

Добавлены два настоящих TLS cases в C fixture и Node runner. В
`completed-read-retry` клиент ждёт фактический WANT_READ, затем отправляет
данные. Отдельное событие фиксирует READ success и снятие retry до echo;
после bounded ACK проверяются остаток payload, wire sequences и TLS close.
В `unrelated-write-read-retry` успешная запись с отдельным буфером сохраняет
первоначальный READ retry. Probe отказывает по RETRY (`16`) даже при нулевых
public pending getters и последнем успешном WRITE. Отрицательный fixture
закрывается после подтверждённого получения payload, без graceful-close claim.

Это проверка существующего caller-ledger контракта, а не исправление
доказанной ошибки OpenSSL. Одинаковые READ pointer/length — дисциплина этого
доверенного fixture; enum ledger не обеспечивает argument identity или lock.
Финальный aggregate координатора прошёл 10/10 TLS scenarios, exit 0, без
skips/cancellations/TODO. Независимо пройдены четыре held-out TLS cases и
одна отдельная проверка чувствительности с намеренно неверным private ledger.
Точные executed counts,
source/build identities, независимые controls и неблагоприятный первый
build-hook результат сохранены в [retry evidence](evidence/continuum-c2a-retry.json).
Новый hosted результат относится к implementation SHA отдельно.

Для диагностики сборки runner передаёт только 28 явно разрешённых кодов этапа;
неизвестные значения и сообщения остаются generic. Четыре private controls
отделены от реального TLS. Первый build hook отказал до всех TLS cases;
его причина неизвестна, последующая неизменённая pinned сборка прошла.

Свежая native сборка и official aggregate прошли 20/20 групп. Native C source
сохранён; новый checkout/prefix имеет отдельный binary hash, совпадение с
прежним бинарником не заявляется. [Native evidence](evidence/continuum-c2a-retry-native-regression.json)
сохраняет 1083 strict PASS, 25 SKIP, 1 expected TODO и 0 strict FAIL.
Peer/read KeyUpdate, write retry completion, control/shutdown/usage limits,
TLS-runtime cancellation и semantic export/import остаются следующими работами.

## Continuum C2a: прерывание runtime и идентичность helper

Финальные локальные проверки —**13/13**:10 прежних TLS scenarios,2 обработанных
SIGTERM/SIGINT после authenticated handshake и первого успешного C READ до echo,
1 no-TLS cached-source control. [Interruption evidence](evidence/continuum-c2a-interruption.json)
отделяет новый test helper от неизменённых production module API/C/probe/build.
Сигнал принимает частный Node launcher; непосредственно standalone CLI branch
и прямой C SIGINT этим не проверены. Требуются handled отказ, завершённый
C child, удалённые собственные PKI/сборки и освобождённый relay listener до
fallback очистки. Graceful TLS close и memory zeroization не заявляются.

Независимый held-out TLS case и два намеренно неблагоприятных actual-TLS
controls подтвердили отказ при оставшихся PKI и реально занятом relay port.
Исправлены две ошибки нового стенда: numeric PID/proc assumption и позднее
снятие hash, способное приписать cached module изменённым disk bytes. Private
контрпримеры, первый неверный native-port rebind критерий, provisional10/12
aggregate и ограничения identity сохранены; production cleanup defect не
установлен. Хэш при импорте — cooperative edit detector, не execution attestation.

Свежая native регрессия —**20/20**; official1083 strict PASS/25 SKIP/
1 expected TODO/0FAIL,105modules. Новый checkout имеет собственный binary hash;
совпадение с предыдущим не заявляется. C0 core21/process7, C1 tests22 пройдены.
Hosted приёмка новых source bytes ещё ожидается. Далее — peer/read KeyUpdate,
WRITE retry и оставшиеся control/shutdown/usage-limit состояния до export/import.

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
[Peer evidence](evidence/continuum-c2a-peer-key-update.json) сохраняет hashes, build identities и ограничения.
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
в [write evidence](evidence/continuum-c2a-write-retry.json). C0 core21/process7, C1 27=18 synthetic+9 runtime,
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
control; независимые heldouts учтены отдельно в [evidence](evidence/continuum-c2a-overlap.json).
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
source control. Независимые heldouts и identities — в [evidence](evidence/continuum-c2a-shutdown.json).
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
source control. Независимые heldouts/cleanup/identities — в [evidence](evidence/continuum-c2a-eof.json).
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
[evidence](evidence/alpha-stop-identity.json).

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
не новая TLS-проверка в push. [Очищенная CI-квитанция](evidence/alpha-stop-hosted.json).
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
beforeguard smoke — в [evidence](evidence/continuum-c2a-peer-close.json). Exact implementation CI pending.
Далее — truncated/partial closure и sequence/key usage gates перед C2b.
Export/import, actual TLS-code change и native NGINX migration не реализованы.

### Exact CI: peer-first closure

Implementation `2ca7892a7e1f448a98679da59e57e9a0023da2e8`: research push
`40050023137` и PR `40050026763`, native push `40050023101` и PR
`40050026739` завершены success. Оба research logs подтверждают21/7/27/20;
все основные native steps, включая feature-off и alpha package/checksum,
прошли. [Очищенная квитанция](evidence/continuum-c2a-peer-close-hosted.json) сохраняет exact SHA/run IDs,
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
[Очищенные evidence](evidence/continuum-c2a-truncated-body.json) сохраняют identities/cleanup/границы и
setup corrections. Exact implementation CI pending. Далее — ограниченный
sequence/key usage gate для quiescent profile перед C2b; остальные
truncation/RST variants unsupported. Export/import и TLS-code change не готовы.

### Exact CI: truncated body EOF

Implementation `6cee2384e91e9fda4251c53dbeddce9cc951f473`: research push
`40054592561` и PR `40054596847`, native push `40054592543` и PR
`40054596722` завершены success. Оба research logs подтверждают21/7/27/21;
все основные native steps, включая feature-off и alpha package/checksum,
прошли. [Очищенная квитанция](evidence/continuum-c2a-truncated-body-hosted.json) сохраняет exact SHA/run IDs,
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
[Evidence](evidence/continuum-c2a-usage.json) сохраняет исходные отказы setup и hashes. Exact implementation
CI pending; прежний6cee238 принят отдельно. Полнота inventory, semantic
export/import, runtime budget enforcement и TLS-code migration не реализованы.
Далее — exact CI, затем review C2a readiness для первого узкого C2b capsule;
остальные alert/EOF/partial variants остаются unsupported/fail-closed.

### Exact CI: directional record key usage

Implementation `b05ee33160b218854da4cac5710125b90e5ee8ac`: research push
`40058848933` и PR `40058853171`, native push `40058848929` и PR
`40058853120` завершены success. Оба research logs подтверждают21/7/27/22;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. Очищенная [квитанция](evidence/continuum-c2a-usage-hosted.json) сохраняет
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
отказы находятся в [evidence](evidence/continuum-capsule-preflight.json).

Readiness review выявил конкретный blocker: возвращённый result.probe
получен после cleanup соединения, это не живой удерживаемый safepoint.
Следующий шаг — bounded C STEP после immutable probe pair и до любого
TLS READ/control/shutdown, затем runner decision/nonce/reobservation barrier
перед любым exporter. Остальные adapters/import/ownership/retirement
gates остаются отдельными. [Inventory readiness](continuum/C2B-READINESS.md) фиксирует
конкретные поля и code boundaries. Exact implementation CI pending.

### Exact CI: metadata capsule preflight

Implementation `deecc35825a706ac8b58d728f8f8a6e35b9d0986`: research push
`40062408179` и PR `40062412144`, native push `40062408165` и PR
`40062412125` завершены success. Оба research logs подтверждают21/7/27/23;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. [Очищенная квитанция](evidence/continuum-capsule-preflight-hosted.json) сохраняет artifact
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
Counts, cleanup и hashes записаны в [evidence](evidence/continuum-live-hold.json). Core21/process7/C1 27 и native20/20 прошли;
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
отдельной проверки. [Readiness](continuum/C2B-READINESS.md) сохраняет эти границы.

### Exact CI: bounded source-side C hold

Implementation `2debcc30101a72b1e5b08b22dd2ac9b0d040c401`: research push
`40065524807` и PR `40065527979`, native push `40065524846` и PR
`40065528012` завершены success. Оба research logs подтверждают21/7/27/30;
полные native workflows, включая Unix/tenant gates, feature-off и alpha
package/checksum, прошли. [Очищенная квитанция](evidence/continuum-live-hold-hosted.json) сохраняет artifact
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
[Контракт и ограничения](continuum/SOURCE-CAPTURE.md) не распространяют защиту копии на исходный SSL heap.

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
[Очищенный evidence](evidence/continuum-source-capture.json) содержит source hashes, обе попытки и cleanup.
Exact implementation CI pending. Далее сначала controller counterexample/
contract review, затем reusable capsule inventory/lifetime; importer/migration
не реализованы. Это защищённая дополнительная копия, не whole-process защита.


### Exact CI: transient protected source sample

Implementation `fc7161945a5855e7c650609bef33cd4a66f2e448`: research push
`40071366794` и PR `40071371690`, native push `40071366797` и PR
`40071371664` завершены success, attempt1. Research logs подтверждают
21/7/27/35; оба full native workflows и artifacts сверены с точным SHA.
Hosted official1105 strictPASS/25SKIP/1expectedTODO-fail; local1083 отдельно.
[Очищенная квитанция](evidence/continuum-source-capture-hosted.json) сохраняет digests, отдельные event-head/PR-merge
checkout/build identities и counts; raw artifacts/keys/logs не публикуются.

Это transient record-material sample, который очищается до release, не
reusable semantic capsule/exporter/importer или TLS-code migration.
Локальный исходный controller expectedB/actualA сохранён: последующие local
и hosted PASS не считаются его исправлением. Далее deterministic contract
review/counterexample, затем fuller capsule API inventory/protected lifetime.


### Controller fixture: sampled-generation observation

Исправлено завышенное ожидание fixture, не controller/runtime: первый обычный
GET после apply/recovery может ещё попасть в прежнюю native generation.
Durable outcome/pending/revision/history проверяются немедленно; только HTTP
наблюдения ожидаются ограниченно. Body требует HTTP200 и точное содержимое;
reserved revision отдельно требует HTTP200, точные body и header. Это разные
fresh samples, не same-worker или all-traffic atomic cutover.

Детерминированный synthetic counterexample сохраняет отказ прежнего one-shot
assertion после двух успешных candidate revision/health rounds; новый helper
дожидается разрешённого A→B. Неверные body/status/revision, transport reset и
trickle остаются отказами. Независимое ревью и synthetic9/9 прошли. Каждый
request имеет absolute1s и idle timeout; loop budget может превыситься на
in-flight request плюс scheduling/cleanup, не hard wall-clock SLA.

[Очищенный evidence](evidence/control-observation-contract.json) и
[per-file ledger](review/control-observation-ledger.json) сохраняют исходный
native17/20 и controller66/68 без исправления задним числом. Точный interleaving
прежнего сбоя не доказан; manager и native C не менялись. Exact implementation
hosted CI — отдельная приёмка, не прежний source-capture PASS.

Локальный полный aggregate20/20; controller77/77 TAP без skips/TODO.
Official35 files:32 passed/3 skipped,1083 strictPASS/25SKIP/
1expectedTODO-fail/0unexpectedFAIL. Source/manifest/binary guards сохранились.

Следующий блок: source-only reusable protected capsule lifetime и явный API
allowlist, без importer. Cleanup-before-release, expiry/revocation и actual-TLS
abort barrier ещё не реализованы; SIGKILL не считается доказанным wipe.


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

[Очищенный evidence](evidence/continuum-keylog-buffer.json) сохраняет точные проверки и границы.


### Exact CI: bounded keylog Buffer lifetime

Implementation `787f5f69e1f793b1b34e6d9b0acaa74381e059b8`: research push
`40074320805` и PR `40074324467`, native push `40074320788` и PR
`40074324454` завершены success, attempt1. Actual research logs:21/7/27/36;
оба native artifacts:20/20 групп, controller77TAP, alpha37TAP (28 synthetic
плюс9 original entries с parents), official1105 strictPASS/25SKIP/
1expectedTODO-fail/0unexpectedFAIL. Local official1083 учтён отдельно.
[Очищенная квитанция](evidence/continuum-keylog-buffer-hosted.json) сохраняет ZIP digests и отдельные event-head,
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

[Evidence](evidence/continuum-retained-capsule.json) сохраняет identities, baseline refusal,
независимые controls, cleanup и различие JS-timeout/native expiry. Это только
retained source record-material subset, не полный semantic capsule, importer,
ownership transfer или migration. Защита исходного SSL heap и полный syscall
fault matrix не заявлены. [Контракт](continuum/SOURCE-CAPTURE.md) задаёт source API allowlist
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
[Очищенная квитанция](evidence/continuum-retained-capsule-hosted.json)
содержит проверенные ZIP digests, отдельные event-head/PR merge checkout
identities и независимое static review без новых runtime reruns.

Это приёмка restricted retained source record-material lifetime/cleanup,
не полного semantic capsule, importer или migration. Полный established-state
semantic/API inventory и protection-syscall failure matrix остаются следующими
gates. LSan unavailable не считается PASS; SIGKILL/crash wipe неизвестен.
Exclusive ownership, distinct TLS code, actual old-code exit и native NGINX
continuation по-прежнему не реализованы. Runtime sources в receipt не менялись.


## Continuum: отказы защиты памяти и повторная очистка

В source-only capture исправлен воспроизведённый отказ повторного уничтожения:
после failed munmap прежний FAILED slot больше не пропускает cleanup оставшейся
mapping. При combined restore-RW/unmap failure неочищенная копия остаётся
locked. Успешный unlock отмечается, поэтому повторный unmap не повторяет его.
Любой прежний отказ навсегда запрещает успешный discard/resume, даже если
следующая bounded cleanup попытка действительно очистила и освободила память.

Авторские контрпримеры на неизменённом production TU:2/2 FAIL, кандидат2/2 PASS;
независимые5 synthetic heldouts прошли plain и ASan/UBSan, leak detection off.
Это не actualTLS admission и не перенос. Публичная матрица:18 synthetic cases,
plain18/18 и ASan/UBSan18/18 (те же cases),4 вложенных guard/fork controls.
Финальный frozen C2a44/44, core21/process7/C1 27; independent2 actualTLS
heldouts прошли с отдельной fresh binary identity. Native в изолированной
копии20/20, controller77, official1083 strictPASS/25SKIP/1expectedTODO-fail.
Три прежних workspace native отказа12/20,12/20,13/20 из-за observed execute-mode
drift сохранены; isolated PASS не объясняет причину и не исправляет native код.
Exact implementation CI нового cleanup fix pending. Результаты и границы — в
[evidence](evidence/continuum-capture-protection.json).
Persistent failure через final free требует terminal source exit; explicit wipe
не гарантирован. Full semantic/API inventory, importer и migration не реализованы.


## Continuum: наблюдение established-state API metadata

Новый opt-in `inspect-api` использует прежний genuine live hold и наблюдает
ALPN `continuum-c1`, длины local/peer Finished, роль/версию, no-client-auth class
и присутствие non-resumed session. Два metadata snapshots, ledger и probe
сверяются до release; original nonce/serial и трёхсекундный deadline сохранены.
Finished bytes не копируются: non-NULL dummy/count0 получает только длины.
Это не API-value preservation, semantic capsule, exporter/importer или migration.

Локально финальный frozen C2a48/48: прежние44 +4 actualTLS environments
(positive, native stale serial, malformed и duplicate public receipts).
Core21/process7/C1 27 и fresh isolated native20/20 прошли; official1083
strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL. Авторские25 synthetic
production-probe-backed cases и independent21 прошли plain и ASan/UBSan:
те же cases, не50/42 unique. LSan off; dependencies uninstrumented.
Независимо4 actualTLS heldouts:2 positives, native stale nonce и unknown-field
refusal. Все75 наблюдавшихся children закрыты,6 private roots отсутствуют.

Сохранены baseline missing-action refusal и initial2/4 diagnostic: два новых
теста ошибочно требовали normal exit при corrupted channel, где прежняя policy
использует SIGKILL. Изменена только классификация теста; strict FAIL сохранён.
C source мог уже release; no-I/O/explicit-wipe claim для этих fault cases нет.
[Evidence](evidence/continuum-api-inventory.json) разделяет эти границы и identities.
Exact CI нового metadata code pending. Прежний `ad5351f4` принят по двум actual
research21/7/27/44 и native20 workflows/artifacts, не metadata-only success:
[hosted receipt](evidence/continuum-capture-protection-hosted.json).
Далее — actual values/state contract в protected capsule после exact CI,
а не target reconstruction из одних длин и booleans.


### Exact CI: held-source API metadata only

Implementation `c0c4e308eca839049de4b64aa2fd2493d0b8865c`: research push
`40087194488` и PR `40087198661`, native push `40087194477` и PR
`40087198675` завершены success, attempt1. Оба actual research jobs
выполнили core21/process7/C1 27/C2a48 без FAIL/skip/TODO. Оба native
artifacts:20/20 групп, controller77TAP, alpha37TAP; official1105 strictPASS,
25SKIP,1expectedTODO-fail,0unexpectedFAIL. Local official1083 учтён отдельно.
[Очищенная квитанция](evidence/continuum-api-inventory-hosted.json)
сохраняет ZIP digests, event-head/PR merge checkout identities и независимое
static review; в receipt нет новых runtime reruns или изменений исходников.

Приёмка относится к read-only metadata наблюдениям held source, не сохранению
actual ALPN/Finished values или полному semantic capsule. Public channel-fault
отказы, иногда после native release, сохранены: SIGKILL не доказывает explicit
wipe/no-I/O. Далее — protected lifetime actual required values и restricted
authentication class с явным unsupported API contract. Exporter/session/
resumption/PHA, future budget/KeyUpdate, exclusive target I/O ownership,
distinct TLS code, actual old-code exit и native continuation остаются gates.


## X10 Production V1: G0–G1 contract and release-record checks

The bounded [release contract](release/RELEASE-CONTRACT.md) and
[declared profile](release/profile.json) now distinguish supported V1 intent,
ABI/threat model, service target, config versus package rollback and prospective
60-minute normal/slow-client acceptance budgets. These are declarations before
measurement: the current root/Node24 environment does not accept the nonroot
Ubuntu24.04/Node22 service target. G2–G8 and permanent Production V1 remain open.

The release-record schema/checker and independent refusal controls check bounded
shape and internal source/build/artifact/evidence/gate consistency only. They do
not authenticate evidence, run a package or authorize a release. Review fixes
and adverse observations are retained in [evidence](evidence/v1-release-contract.json).
A required native CI step now runs authored and held-out release-record checks;
exact new implementation CI is pending. Prior Continuum C2a48 exact acceptance
is preserved separately and does not accept this new validator.

Next verify that exact CI, then G2: corrected pinned Quickstart, real upstream
and application readiness, independent extracted-bundle lifecycle and permanent
versioned Local Alpha. Alpha alone does not close V1 or activate AVERKRON. The
full native compatibility matrix and deferred Continuum remain preserved.


### Exact CI: G1 contract and release-record declarations

Implementation `80629638e1d1c7635f76e655760c9db987ea82ea` passed both
required native CI runs. Each actually executed35 authored/held-out release-record
checks on Node22 and20 native aggregate groups. Actual native artifacts and
ZIP digests were checked; counts and checkout/event identities are separate in
[evidence](evidence/v1-release-contract-hosted.json). Research push runtime was
SKIPPED (scope-only success), not a new48-case acceptance; PR research actually
executed21core/7process/27C1/48C2a. No runtime sources changed in this receipt.

This verifies G1 definitions and structural declaration checks, not evidence
authenticity or target service/runtime acceptance. Profile remains
DECLARED_NOT_ACCEPTED. G2 permanent Local Alpha and G3–G8 proxy/TLS/service,
package rollback/recovery, security, frozen60minute soak and independent
Production V1 acceptance remain open. Next G2 implements a real application
upstream/readiness and independently replayed, permanently published package.


## G2 partial: explicit application upstream and extracted package checks

The local alpha now has an explicit opt-in loopback application-upstream mode,
with a separately launched bounded example application included in the checked
package. The default native demo stays unchanged. Application `/ready` status
is distinguished from native self-check and from full business readiness;
configuration alone does not establish that an application is healthy.

Local changed HTTP/extracted-bundle controls and independent review are recorded
separately from complete native/Unix acceptance in [evidence](evidence/g2-upstream.json). The
current root/Node24 environment does not accept the declared nonroot Node22
target. Local AF_UNIX stream/seqpacket socket creation returned EPERM; actual
Unix acceptance is blocked. Prechecks and successful HTTP controls are not Unix
runtime PASS. The full aggregate and supplemental Unix outcomes are recorded separately, including refusals.
The Quickstart uses the active development ref and records its exact
checkout; it does not invent a permanent release or accepted download URL.

G2 remains partial: first verify exact new implementation CI, then publish and
independently replay an accepted permanent versioned Local Alpha. G3–G8 service,
TLS, config/package rollback/recovery, security, frozen60minute soak and
Production V1 remain open. The full native matrix and deferred Continuum are
preserved. No other product is activated by this subcheckpoint.


### Exact CI: G2 application upstream and extracted bundle

Implementation `eb4e2de3026edb7a59e877fff8971c8d039e8143` is exact-hosted
verified for the opt-in application-upstream and expanded alpha40 checks. Both
actual native runs executed required Unix checks and native20 aggregate groups;
actual artifacts and ZIP digests were verified. [Receipt](evidence/g2-upstream-hosted.json)
keeps exact jobs, event/build identities, counts and research runtime skips
separate. No runtime sources changed in this receipt.

Local AF_UNIX socket EPERM remains an unresolved environment observation; hosted
Unix success is not a local permission or native-code fix. G2 remains partial:
permanent versioned alpha distribution and independent published-file nonroot
Node22 replay are pending. G3–G8, service/TLS, package rollback/recovery, security,
frozen soak and Production V1 are not accepted. Deferred Continuum is preserved.


## G2 partial: alpha archive verification before extraction

A bounded checksum-first gzip/tar checker now validates the exact packaged alpha
inventory, record and payload hashes/sizes/modes without extraction or execution.
[Evidence](evidence/g2-archive.json) separates authored and independent controls
from the required CI check of an actual newly packed native archive. Exact new
implementation CI is pending; the earlier application-upstream eb4e2de3 hosted
acceptance is preserved separately. No native/controller/alpha runtime changed.

A matching checksum establishes consistency with the supplied hash, not publisher
authenticity, binary safety, target ABI or permission to run it. G2 remains partial:
the current connector exposes no Release/asset publication mutation operation,
so permanent versioned distribution and published-file nonroot Node22 replay
remain blocked. Continue independent permitted G3 preparation with dependency
limits; do not bypass credentials/permissions or switch products. G3-G8 and
Production V1 remain unaccepted, with full native and deferred Continuum scope
preserved. The receipt also retains the coordinator's lease-message validation
protocol failure; exit0 with diagnostics was incorrectly allowed to publish.


### Exact CI: G2 archive consistency; G3 readiness contract

Implementation `783de7994f0af0ea9d4d1129be28c31c57227f8d` passed both
actual native CI runs, including archive refusal controls and verification of
the newly packed native archive. The PR evidence ZIP was downloaded and its
GitHub digest matched; event head, PR merge build, internal archive and binary
identities remain separate in [the receipt](evidence/g2-archive-hosted.json).
This closes the pending archive implementation CI check, not permanent
distribution, publisher authentication or clean published-file acceptance.

The next bounded G3 preparation adds an optional paired expected readiness
status/body contract. New application-mode alpha installs declare HTTP 200 and
exact `ready` plus newline; a wrong-body HTTP 200 cannot bind or confirm that
application. Explicit responses are compared as raw UTF-8 bytes with a 4096-byte
cap. Existing candidates without the pair keep their exact two-field canonical
records and previous status-only behavior. Native C and Continuum are unchanged.

[Readiness evidence](evidence/g3-readiness.json) separates the observed baseline
counterexample, candidate tests and independent review from exact future CI.
This is still G3 preparation: TLS and an operated systemd-user service remain
open, as do G2 permanent distribution and G4–G8. Local UID0/Node24 fixtures and
the absent user manager do not satisfy nonroot Node22 or service acceptance.
No product transition, performance claim or Production V1 acceptance occurs.

Final frozen local native aggregate passed20/20 groups; controller86 TAP,
alpha40 TAP and operator30 TAP passed separately. Official35files:32passed,
3dependency skips;1083strict PASS,25SKIP,1expected TODO-fail,0unexpected FAIL.
Release checks50 and independent HTTP-function checks12 are separate units.
Earlier failed preparation/bookkeeping runs are retained in the evidence.
Exact resulting hosted CI is pending; these UID0/Node24 fixtures are not target
service, TLS or Production V1 acceptance.


### Exact CI: explicit readiness status/body

Implementation `6abc888388b2e45c0986c3c9b043aa03324fd77e` passed both actual
native push and PR jobs on Node22. Both downloaded evidence ZIPs matched their
GitHub digests: native20/20 groups, controller86 TAP, alpha40 TAP, operator30 TAP,
required private Unix and feature-off checks, and actual pack/archive verification.
Official35files:34passed/1dependency skip;1105strict PASS,25SKIP,
1expected TODO-fail and0unexpected FAIL. These are separate counting units.

[Hosted receipt](evidence/g3-readiness-hosted.json) preserves event versus actual
PR merge build, archive/binary identities and the earlier local failures.
Unchanged research push runtime was skipped; PR research steps actually ran.
The inherited F5 CLA publisher failure remains separate and unhidden.

This accepts only implementation compatibility for the explicit readiness
contract. G2 permanent release and independent published-file replay, G3 service
and TLS, G4-G8 and Production V1 remain open. The next task is the bounded
TLS/systemd-user service package, with guarded failed-start/drain/orphan behavior.
The local AF_UNIX refusal and absent target user manager are not fixed by hosted
Unix success. Full native and deferred Continuum scope remain preserved.


## G3 partial: guarded systemd-user recipe

A generated user-unit recipe now makes the Node executable, installed launcher,
private control socket and process stop policy explicit. It does not install,
enable or activate a service. Type=exec means process execution only, not native
identity establishment or application readiness. Automatic Restart is disabled;
forced SIGKILL and process-group cleanup are not enabled by this recipe.

Independent review identified a startup-lock race in a proposed immediate
ExecStartPost bind. That command is omitted; the operator must confirm native
startup and perform the documented explicit bind. An installed bounded readiness
wait helper remains a separate gate, not an untested automatic health promise.
[Evidence](evidence/g3-service-recipe.json) separates authored and independent
format/refusal checks, static unit validation and actual manager availability.
Exact new implementation CI is pending. No native/controller/alpha runtime changed.

The accepted readiness6abc8883 and archive783de799 CI remain preserved. G2 remains
partial with permanent release/published-file replay open. Real nonroot user-manager
service lifecycle, TLS trust, failure/slow-drain/orphan cases, G4-G8 and Production
V1 remain unaccepted. Full native and deferred Continuum scope stay preserved.


### Exact CI: generated user-unit recipe only

Implementation `0daf4086f77e43b829c6a848d19597411fb6325d` passed both
actual native CI jobs, including the new required user-unit recipe checks on
Node22. [Hosted receipt](evidence/g3-service-recipe-hosted.json) records actual
job/step outcomes, downloaded native artifact ZIP digests, separate event/build
identities, existing native/Unix/archive compatibility and research runtime skips.
No runtime sources changed or runtime reruns were requested in this receipt.

This verifies recipe generation/refusal compatibility only. It preserves local
authored15 and independent40 controls separately, including initial test/setup
failures, user-mode static verify ENXIO and system-mode parser success. No real
service was installed or activated. Type=exec is not application readiness;
manual bind remains mandatory, and an installed bounded wait helper needs its
own acceptance. Real nonroot user-manager lifecycle, TLS, failure/drain/orphan
cases, G2 permanent distribution/published-file replay, G4-G8 and Production V1
remain open. Full native and deferred Continuum scope remain preserved.


## G3 partial: installed bounded startup wait-bind

The installed alpha now exposes wait-bind to observe owned startup before one
existing controller bind. Prepared/alpha-lock startup observations release the
alpha lock between attempts. Installation/session changes, stopped/faulted
states, integrity, identity and health refusals do not become retry loops.
A monotonic wait budget reserves time for the existing bind operation; late or
cancelled in-flight binding may have committed and requires explicit inspection,
not an assumed rollback or blind retry. Filesystem/kernel stalls are not an
unconditional hard-timeout guarantee.

[Evidence](evidence/g3-wait-bind.json) keeps authored, independent and native
regression results as separate units, including adverse/setup outcomes, source
identities and owned cleanup. Exact resulting implementation CI is pending.
The first final native aggregate failed19/20: unchanged reload-listener-observation
raised ESRCH in inspectTcpListeners at handover-baseline.mjs314. Alpha45/45 and
controller86 passed separately; the complete native result is not PASS. Which
captured-process observation failed and the exact cause remain unknown. The held
old worker had been observed stopped before the observer call; the fixture had
not yet issued its own SIGCONT. ESRCH alone does not establish disappearance.
Source/binary/mode stability and complete owned cleanup do not prove no causal
relationship to the helper. No unchanged rerun, out-of-scope runtime fix or
historical observer-fix claim is made. Inspect exact CI and diagnose this
observation before broad native acceptance.
Native/controller code and bundle inventory are unchanged; alpha runtime changed.
Prior readiness and recipe exact CI remain preserved separately.

The generated unit still omits automatic ExecStartPost health startup; this
installed command does not activate a service or accept a nonroot target user
manager. Explicit operator bind or wait-bind remains necessary. G2 permanent
release/published-file replay, verified TLS, real service failure/drain/orphan
paths, G4-G8 and Production V1 remain open. Full native and deferred Continuum
scope remain preserved.


### Exact CI: installed wait-bind; local observer failure retained

Implementation `3b293c570f9a4cf80e06ba6887f0799c39b755eb` passed actual
exact native CI, including the expanded installed alpha checks and required
Unix/archive/feature-off compatibility. [Receipt](evidence/g3-wait-bind-hosted.json)
records jobs/steps, downloaded ZIP digests, actual build identities, counts and
research runtime skips. No runtime sources changed or runtime reruns were
requested in this receipt.

This narrow hosted acceptance does not repair the local first final native19/20
ESRCH failure. Alpha45/controller86 positives, earlier test/setup failures and
local Unix EPERM remain separate evidence. Which captured-process observation
failed and its exact cause remain unknown; ESRCH alone is not disappearance
proof. The held old worker had previously been observed stopped, and the fixture
had not yet issued its own SIGCONT. Stable source/binary/mode and later CI success
do not prove no causal relationship or a historical observer fix. The next gate
is a bounded counterexample and scoped fix only if established under new lease;
no unchanged expensive aggregate rerun substitutes for diagnosis.

Automatic unit readiness, real nonroot service/TLS, failure/drain/orphan paths,
G2 permanent distribution/published-file replay, G4-G8 and Production V1 remain
open. Full native and deferred Continuum scope remain preserved.


## Bounded observer correction: stale proc reads and ESRCH

A newly controlled process-exit boundary established a stale `/proc` read
mechanism separately from the retained wait-bind native19/20 failure. The
captured-process observer now accepts ESRCH as an exit candidate only when
two independent directory lookups specifically confirm ENOENT. ESRCH alone,
a present or reused PID, inaccessible identity and uncertain lookups cannot
become listener closure. Existing sampled-identity and captured-process-only
limitations remain; this is not an OS-level generation fence.

[Evidence](evidence/listener-esrch.json) records the unchanged-baseline
counterexample, frozen candidate/refusal controls, independent review and
fresh native regression as separate outcomes and counting units. Exact new
implementation CI is pending; earlier wait-bind CI does not verify these bytes.

The frozen authored observer suite passed41 nested cases plus one wrapper
(42 TAP), including13 new cases and the preserved28 earlier cases. Independent
review checked14 distinct synthetic scenarios on baseline/candidate and one
actual-kernel Node/shared-TCP observer scenario, not native NGINX. One fresh
build and one changed-candidate official aggregate passed20/20 native groups;
controller86, alpha45 and operator30 TAP remain separate counts. Official
results retain1083 strict PASS,25SKIP and1expected TODO-fail, with no unexpected
FAIL. Existing local AF_UNIX EPERM and feature-off evidence were not rerun or
relabelled as new PASS. These root/Node24 checks do not accept the declared
nonroot Node22 target.

The original native19/20 ESRCH failure stays retained. Its failing captured
process and exact cause remain unknown. The held old worker had previously
been observed stopped, and the fixture had not issued its own SIGCONT. This
new mechanism does not prove that historical interleaving, a historical repair
or no causal relationship to wait-bind. No unchanged expensive aggregate was
rerun merely to relabel that failure. Native C, alpha runtime and service unit
are unchanged; only the optional observer and its tests changed.

Next verify exact resulting CI, then continue G3 verified TLS and real nonroot
service/failure/drain/orphan gates. Automatic unit readiness, G2 permanent
distribution/published-file replay, G4-G8 and Production V1 remain open. Full
native compatibility and deferred Continuum scope remain preserved.


### Exact CI: captured-process observer ESRCH compatibility

Implementation `4a8ec8c0d2ecb2e14778651a581ea5f231f2a458` passed both
actual exact native CI jobs, including the changed observer boundary suite.
[Receipt](evidence/listener-esrch-hosted.json) keeps completed jobs, actual
job logs, downloaded artifact digests, event/build identities, counted results,
research runtime skips and API metadata observations separate. This receipt
changes no runtime sources and requests no workflow or local runtime reruns.

Both native jobs on observed Node22.23.3 passed20/20 aggregate groups,
42 observer TAP tests, controller86, alpha45 and operator30. Required Unix
control9/generations10/operator30 and feature-off4 passed separately, as did
user-unit15/archive15/release-record35 and actual packed-archive verification.
Official results retain1105 strict PASS,25SKIP and1expected TODO-fail, with
zero unexpected FAIL. Research PR actually ran21core/7process/27C1/48C2a;
push research runtime was skipped. These are separate counting units. API
step arrays remained null/empty; actual outcomes come from complete job logs
and digest-verified artifacts, with the metadata cause unknown.

This accepts the narrow stale-proc correction and compatibility only. The
original local19/20 failure stays retained: its failing captured process and
exact cause remain unknown. The bounded kernel mechanism, new local20/20 and
exact hosted success do not establish that historical interleaving, a historical
repair or no causal relationship to wait-bind. ESRCH alone still cannot prove
process exit; the independent double-ENOENT proof and all identity refusals stay
mandatory. Local AF_UNIX EPERM and root/Node24 target limits are not repaired by
hosted success. Inherited CLA failure remains separate; no agreement was accepted.

Next implement and verify the bounded TLS CA/hostname application/proxy path,
then actual nonroot user-manager startup/stop/restart and failure/drain/orphan
gates. Automatic unit readiness, G2 permanent distribution/published-file replay,
G4-G8 and Production V1 remain open. Full native and deferred Continuum scope
remain preserved.


## Installed HTTPS-upstream trust verification

A bounded extracted/installed native proxy path now has reproducible TLS
upstream acceptance checks with an explicit private fixture CA, hostname/SNI
and rejection controls. The managed frontend remains HTTP: this package does
not add a frontend TLS listener or change the manager listener restrictions.
Existing native `proxy_ssl_*` directives enforce upstream trust; application
readiness remains a separate HTTP check.

[Evidence](evidence/g3-tls-trust.json) retains the actual authored, independent
and fresh native outcomes, hashes, cleanup, failures and counting units. A new
required native CI step executes the installed trust suite. Exact resulting
implementation CI remains pending; earlier observer CI does not verify these
new test/workflow bytes. Native C, alpha/controller/observer runtime, bundle
inventory and service recipe remain unchanged.

The original local19/20 ESRCH observation and unknown historical cause remain
retained. No TLS check identifies its failing process or interleaving. Next
verify exact new CI, then continue a supported frontend TLS path and real
nonroot service startup/stop/restart, failure, drain and orphan boundaries.
Automatic unit readiness, permanent versioned release/published-file replay,
G4-G8 and Production V1 remain open. Full native and deferred Continuum scope
remain preserved.

The authored installed suite passed 9 nested scenarios plus one wrapper
(10 TAP), including 3 rejected TLS candidates with actual native502 and
controller rollback checks. Independent review passed 5 separate actual native
upstream heldouts and 17 static checks; those heldouts use a single-process
native fixture, not the installed lifecycle. One fresh native build and one
frozen official aggregate passed 20/20 existing groups; the new TLS suite is
counted separately. Official outcomes retain 1083 strict PASS,
25 SKIP and 1 expected TODO-fail, with
0 unexpected FAIL. Local root/Node24 does not accept the
nonroot Node22 target. Initial authored 5PASS/5FAIL test assertions and the
independent chown EINVAL fixture setup are retained as diagnostic history;
they are not product runtime fixes.


### Exact CI: installed HTTPS-upstream trust verification

Implementation `84a12537c2f102a9e3c8bcc8ba2ad1ebf59397fe` is now
exact-hosted verified for the installed managed HTTP gateway to HTTPS
application upstream. Both actual native jobs ran the new required installed
TLS step; its 10 TAP results (9 nested scenarios plus one wrapper) and owned
cleanup are separate from the 20 existing native aggregate groups.
[Receipt](evidence/g3-tls-trust-hosted.json) records actual completed jobs,
complete logs, downloaded ZIP digests, source/build/merge identities and the
retained metadata observations. Earlier observer CI was not borrowed as proof.

Both native jobs observed Node 22.23.3 and separately passed 20/20 native
aggregate groups, controller 86, alpha 45, operator 30 and listener 42.
Required Unix control 9/generations 10/operator 30, feature-off 4,
user-unit 15/archive 15/release-record 35 and actual packed-archive checks
also passed. Official results retain 1105 PASS/25 SKIP/1 expected TODO-fail
and zero unexpected FAIL. Research PR actually executed 21 core/7 process/
27 C1/48 C2a; push research runtime was skipped. Current executed job step
arrays expose completed success; no earlier missing-step anomaly is
inferred or copied. Inherited CLA failure remains separate and no agreement
was accepted. These are separate counting units.

The authored local initial 5 PASS /5 FAIL fixture assumptions and corrected final
local results remain preserved in the unchanged original evidence. The old
local 19/20 ESRCH cause also remains unknown. This receipt executes no local
runtime tests and changes no native, alpha, controller or observer runtime.

This is upstream TLS only: the frontend stays HTTP and the readiness relay
is a test fixture. Next implement a separately supported frontend HTTPS
certificate/listener lifecycle, then actual nonroot user-manager service and
failure/drain/orphan acceptance. Automatic unit readiness, G2 permanent
distribution/published-file replay, final soak, G4-G8 and Production V1 remain
open. Full native compatibility and deferred Continuum scope are preserved.


## Explicit managed loopback frontend HTTPS

An optional candidate `https` object now requests a fixed IPv4-loopback TLS
listener alongside the existing HTTP management/readiness listener. It names
an unprivileged port and operator-owned certificate/key files; arbitrary
`listen` and `include` directives remain rejected. Legacy inputs without
`https` retain their canonical representation and rendered HTTP fragment.
Native `-t` checks certificate configuration before reload. Existing readiness
is still HTTP and does not automatically authenticate a frontend TLS session.

[Evidence](evidence/g3-frontend-tls.json) records actual installed trust,
certificate lifecycle/refusal checks, independent review and fresh native
compatibility. The final authored suite passed 15 nested
scenarios (16 TAP including its wrapper); independent review
passed 56/56 separate controls with zero blocking
findings. One fresh native build and the final official aggregate passed
20/20 groups. Official results retain 1083
strict PASS, 25 SKIP and 1 expected
TODO-fail, with 0 unexpected FAIL. Counts use separate units.

The new mandatory CI step runs `frontend-tls.test.mjs`; exact resulting
implementation CI remains pending. Earlier HTTPS-upstream evidence does not
verify these new controller/test/workflow bytes. Local root/Node24 tests do
not accept the supported nonroot Node22 service profile. Operator certificate
files remain external, versioned and retained for revert/restart; config
rollback cannot recreate a removed or changed certificate. Automatic TLS
health, renewal, user-service lifecycle and final Production V1 remain open.

The historical local19/20 ESRCH failure and unknown process/interleaving are
preserved. No frontend TLS result explains that historical failure. Next
verify exact new CI, then complete actual nonroot service startup/stop/restart,
failed-start, drain and orphan boundaries. G2 permanent release/published-file
replay and G4-G8 remain open; full native and deferred Continuum are preserved.


### Exact hosted frontend HTTPS verification

Implementation `fcc7123a` now has separately verified native PR and targeted
push-retry evidence. [Receipt](evidence/g3-frontend-tls-hosted.json) records
the actual required frontend TLS step and digest-verified TAP artifacts:
16/16 TAP (15 nested scenarios plus wrapper), two owned native sessions
stopped, launcher exit, sockets0 and temporary-root removal. The old upstream
TLS suite remains a separate10/10 TAP. Native20/20 groups, controller86,
alpha45, operator30/listener42, required Unix9/10/30, feature-off4, recipe15,
archive15 and release-record35 passed. Hosted official1105 strict PASS,
25 SKIP and one expected TODO-fail remain separate counting units.

Push attempt1 failed when the runner received a shutdown signal during the
old upstream TLS step: exit143, new frontend step skipped, no evidence
artifact and final fixture cleanup unconfirmed. Its underlying shutdown
cause is unknown. One authorized targeted retry of that failed job used
unchanged source. Successful PR/retry outcomes do not erase the failure,
explain the runner shutdown or claim a product fix. Research PR actually
executed21 core/7 process/27 C1/48 C2a; research push was scope-only.
Inherited CLA failure remains separate, with no agreement accepted.

No runtime code or local tests changed in this receipt. Original local
source-change wrapper failure, summary-parser correction and historical
local19/20 ESRCH uncertainty remain preserved. Next complete actual nonroot
user-manager startup/stop/restart, failed-start, drain and orphan boundaries.
HTTP health is not automatic TLS acceptance; renewal, permanent published
release/replay, final soak and Production V1 remain open.


## Read-only user-manager preflight

The service prerequisite command now checks a bounded, explicit nonroot
user-manager capability response. An exit0 with a textual systemd-unavailable
stub is refused; exit status alone cannot accept a manager. The command
performs no service activation, unit installation, enablement or linger
change. Existing user-unit rendering and installed native lifecycle stay
unchanged. [Evidence](evidence/g3-service-preflight.json) keeps real root CLI
refusal separate from synthetic positive manager-property fixtures.

Actual authored tests passed 42/42 TAP; independent
review passed 39/39 separate controls with no blocking
findings. One fresh native build and final official aggregate passed
20/20 groups. Official results retain 1083 strict
PASS, 25 SKIP and 1 expected TODO-fail, with
0 unexpected FAIL. These counts have different units.

The new mandatory CI step tests the preflight contract and records a
sanitized actual read-only CLI observation. It does not activate a manager
or service. A structured prerequisite refusal is not live-manager or
service acceptance. Exact resulting implementation CI remains pending.
Then use an authorized nonroot environment for actual manager and service
startup/stop/restart, failed-start, drain and orphan checks. Do not manufacture a manager through account/security changes.
G2 permanent distribution/published-file replay, G4-G8, final soak and
Production V1 remain open. Prior frontend HTTPS hosted evidence, its
shutdown143 failure and historical local19/20 ESRCH uncertainty are retained;
this prerequisite does not explain their causes. Full native and deferred
Continuum scope remains preserved.


### Exact hosted preflight and unresolved TLS refusal

Implementation `9e63d3c1` passed42/42 preflight TAP in both exact native
jobs on Node22.23.3. [Receipt](evidence/g3-service-preflight-hosted.json)
records real readonly CLI observations: nonroot:true, managerAvailable:true,
probeExecuted:true, reason:null, with service/V1 acceptance false. These
are actual prerequisite observations, distinct from synthetic positives;
no unit was installed or activated. A future ephemeral test host must be
checked again immediately before service work.

Native push40138539074 passed20/20 groups, upstream10TAP, frontend16TAP
and required Unix/feature-off/package checks. Native PR40138541844 passed
20/20 aggregate groups but FAILED the upstream wrong-CA case: expected
apply CLI exit1, actual0. Its fail-fast TAP contains6tests/4PASS/2FAIL
including wrapper. Native502 was observed at least once and owned cleanup
was confirmed. The new frontend step and later Unix/feature-off/package
steps were skipped. This is not the previous runner shutdown143. Its
underlying controller/native/fixture sampling cause is not established;
there was no blind retry, no product fix and no full native CI acceptance.

Research PR actually executed21core/7process/27C1/48C2a; research push
was scope-only. CLA failure is separate. Original local preflight hook
setup failure and prior TLS receipts, shutdown143/cleanup uncertainty
and historical local19/20 ESRCH uncertainty remain retained unchanged.

Next reproduce and correct the wrong-CA refusal failure with bounded
counterexample/candidate evidence and exact new CI before advancing real
nonroot service startup/stop/restart, failed-start, drain and orphan tests.
No runtime code changed in this receipt. Permanent distribution/replay,
package rollback, soak, Production V1 and full deferred Continuum remain open.


### Candidate-bound upstream TLS relay fixture

The upstream TLS readiness fixture now binds each input to its own route
marker and health URL. An old known-good route cannot satisfy another
input merely by returning HTTP200. Restored inputs retain their own binding
so rollback can pass under its fresh revision. Native trust/hostname
verification and explicit correctly bound TLS-refusal observations remain
required. Controller/native runtime code is unchanged.

[Local evidence](evidence/g3-tls-relay-binding.json) preserves the original
failed PR, a deterministic borrowed-old-route counterexample, candidate
controls and final installed TLS verification: 18/18 TAP. One fresh
native build and official aggregate passed 20/20 groups.
These counts have separate units; they do not reconstruct the exact
historical CI interleaving or establish a product runtime vulnerability.
Exact resulting fixture implementation CI is pending. Next verify that
source and all required profiles, then proceed to actual nonroot service
lifecycle on a freshly checked authorized host. Service/V1 remain open.


### Exact CI: candidate-bound TLS relay fixture

Implementation `376f810f` is exact-hosted verified for the corrected
candidate-bound TLS readiness fixture. [Receipt](evidence/g3-tls-relay-binding-hosted.json)
records completed native push40143307531 and PR40143311124, actual steps,
complete logs, downloaded ZIP digests and separate source/merge identities.
Both Node22.23.3 jobs passed upstream18/18 TAP:7 synthetic controls,
9 installed native scenarios and2 wrappers. Correctly bound native502
refusals and owned cleanup remain explicit; frontend16/16 and preflight42/42
TAP passed separately, including actual readonly nonroot manager observations.

Both native aggregates passed20/20 groups, controller86, alpha45, operator30
and listener42. Required Unix9/10/30, feature-off4, recipe15, archive15,
release-record35 and actual packed-archive checks passed. Official1105
strictPASS/25SKIP/1expectedTODO-fail/0unexpectedFAIL retain their own units.
Research PR actually ran21core/7process/27C1/48C2a; research push was
scope-only. CLA failure remains separate, with no agreement accepted.

Original9e63 wrong-CA expected apply exit1/actual0, its deterministic
borrowed-old-route counterexample and unknown exact historical interleaving
remain preserved. New success verifies the fixture correction narrowly;
no controller/native runtime vulnerability or historical product fix is
claimed. Earlier shutdown143/cleanup uncertainty and local19/20 ESRCH
uncertainty remain retained. No runtime code or local runtime test changed
in this receipt. Next verify actual nonroot service lifecycle on a fresh
authorized host after fresh preflight. Service/V1, permanent distribution,
package rollback, recovery and final soak remain open.


## Bounded generated user-service lifecycle acceptance harness

A source-checkout checker now exercises a uniquely named temporary runtime
user unit built from the unchanged guarded recipe. It verifies fresh
nonroot prerequisites, an explicitly supplied archive/checksum, installation,
basic start, explicit installed wait-bind, a native request and stop/start with a fresh session before bounded
owned cleanup. It never enables a unit
or changes linger, accounts, manager settings or production deployment.

[Evidence](evidence/g3-service-lifecycle.json) keeps authored pure/refusal
checks, actual local root refusal, independent review and one fresh native
aggregate separate. The final authored contract passed49/49; independent
review passed28 synthetic heldouts and44 static checks. An actual own-proc
identity check was unavailable with EACCES and is not a PASS. One fresh
native aggregate passed20/20 groups, with official1083PASS/25SKIP/
1expectedTODO-fail/0unexpectedFAIL and3 dependency-skipped files.
These units are separate; the aggregate does not execute the new checker.
Local root refusal is not actual service acceptance.
The new mandatory CI step must provide actual nonroot service observations
for the resulting exact source; accepted376 TLS fixture CI is not borrowed
as verification of these changed checker/test/workflow bytes.

The generated unit still uses Type=exec and no automatic readiness hook.
Manual installed wait-bind is explicit; active(systemd) alone is insufficient.
Basic lifecycle does not close actual logging, the single manager restart
operation, failed-start/cancellation/slow-drain/orphan,
combined TLS/service, package rollback/recovery, permanent published replay,
final soak or Production V1. Earlier adverse histories remain retained.


### Exact actual service CI: install failure retained

Implementation `0ade140e` FAILED both mandatory actual service commands:
push40147719156/job121032594807 and PR40147722978/job121032597723.
[Receipt](evidence/g3-service-lifecycle-hosted.json) records actual steps,
complete logs, downloaded ZIP digests, source/merge identities and failure
JSON. Both observed fresh nonroot manager prerequisites, then returned
phase `install`, code `lifecycle_failed`, exit1. No actual service lifecycle
is accepted; the exact hidden exception remains unknown.

Both preceding native aggregates passed20/20, upstreamTLS18/frontendTLS16/
preflight42 and required Unix/feature-off/package checks. Contract tests
recorded49total/48PASS/1explicit root-onlySKIP. Official1105PASS/25SKIP/
1expectedTODO-fail/0unexpectedFAIL and research PR21/7/27/48 remain
separate units; research push runtime was skipped. CLA failure is separate.

Installation/temp-root removal and application sockets0 were reported.
Other cleanup flags remain false and are not accepted proof. False start/
link flags alone never prove no ambiguous action; the narrower pre-link
location is inferred from exact source control flow, not the hidden error.
Next diagnose the install/inspection guard without weakening authority and
verify any changed source in exact new CI. Original failures and accepted376
fixture CI remain preserved. Service and Production V1 remain open.


A bounded actual install-only local diagnostic on UID0/Node24 observed
30 of31 allowlisted prerequisite checks true and the selected Node owner
check false. The unchanged authoritative recipe inspector refused it. No
serving native process, manager or service was started; existing pack/install
validation may invoke native -V/config syntax checks. Cleanup succeeded.
This establishes that local refusal only, not the exact nonroot Node22 CI
exception. No Node ownership/mode, account or admission policy was changed.

The checker now adds fixed recipe-inspection phase/refusal diagnostics and
bounded allowlisted read-only prerequisite booleans. They confer no
admission authority; all original inspector checks remain mandatory. New
diagnostic source CI is pending. The final changed-source local contract
passed67/67; those pure/refusal tests are separate from the old exact49TAP
and from actual service execution. This is observability, not a product fix
or accepted service lifecycle.


## Independently verified official Node dependency candidate

Both exact239 actual service attempts refused the selected Node at
`recipe_inspection`: mode policy false, owner policy true. Native20/20,
upstreamTLS18/frontendTLS16/preflight42, contract67total/66PASS/1rootSKIP
and required compatibility steps passed separately; the whole CI remains
FAILED. Specific prohibited mode bits and the original0ade exception are
unknown. The local Node24 owner-policy refusal remains a different result.

A new source tool prepares a pinned official Node release in a fresh owned
private dependency prefix. Public release key and signed checksums are
verified separately from archive bytes and execution. The rejected global
cache is untouched; original inspector, recipe, preflight, lifecycle checker,
alpha/controller/native sources and all admission checks remain unchanged.

[Evidence](evidence/g3-verified-node.json) records actual local public-signature
verification, authored contracts, independent trust/lifetime and archive/
storage review. Actual official archive download/preparation/execution and
nonroot service acceptance require the resulting exact CI. No new native
aggregate or unchanged CI retry is borrowed as proof of this new dependency.
Production V1, permanent release, package rollback and final soak remain open.


## Preserve primary service failures separately from cleanup

Both exact700 jobs verified the official signed Node archive and prepared
private Node22.23.3, including actual runtime-version execution and all
seven admission prerequisites. Both full workflows nevertheless FAILED
the actual service at first_start/cleanup_unconfirmed after a confirmed
runtime unit link. The original primary error was overwritten and remains
unknown. actualUnitStartedfalse does not prove the start command had no
side effects or that the physical service never ran. Service cleanup is
unconfirmed; the private dependency runtime was retained for possible stop.

[Evidence](evidence/g3-service-primary-failure.json) preserves those actual
artifacts and adds bounded primaryFailure, separate cleanup failures and
first-start command/state observations. New diagnostics cannot change
admission, operations or success. Only the fixed checker SHA is propagated
to dependency cleanup and the workflow; all other logic is unchanged.

Local synthetic/refusal validation and independent review do not accept
an actual service. The new exact CI is pending; native20 compatibility and
research21/7/27/48 belong to the prior700 source. Earlier failures remain
retained. Actual service operation/cleanup and Production V1 remain open.


## Observe known owned service fragment identity

Both exact7d1 jobs retain primary unit_fragment_identity at first_start /
before_properties. Their actual parsed unit was loaded/inactive/dead with
result success, no main PID or cgroup and a present FragmentPath. The current
guard therefore rejected a literal mismatch with the expected unit path
before its own start request. Actual path values, runtime-link alias or
canonical equivalence versus another file remain unknown. The same cleanup
code has no separate state snapshot, so its failing OR branch is unknown.

[Evidence](evidence/g3-service-fragment-identity.json) preserves both actual
failed workflows, their digest-verified artifacts and independent62 checks.
Preceding native20/TLS18/16/preflight42/dependency46 passed separately; the
service contract had85total/84PASS/1rootSKIP. Research PR actually ran
21/7/27/48; push research was scope-only. Those counts belong to7d1.
Service and dependency cleanup remain unconfirmed and the private runtime
was retained. Original700/0ade primary causes remain unknown.

The new checker adds fixed bounded match facts for only the already known
owned unit and runtime-link paths. No admission, start, cleanup or runtime
retention guard changes. Diagnostics do not accept a presumed alias or
canonical identity. Local contracts and independent review do not prove
an actual nonroot service or this changed source's hosted result.

Next inspect exact new CI and identity facts, then make any reviewed identity
correction justified by actual evidence. Service lifecycle, final cleanup,
logging, restart, adverse cases, combined TLS, package rollback/recovery,
permanent distribution, soak and Production V1 remain open.


## Verify the exact known owned unit fragment

Both exactf434 hosted service attempts observed loaded/runtime_link in
both lifecycle and cleanup, with preceding link target and owned unit
mode/hash checks verified. Canonical identity was explicitly not measured.
The original strict unit-file string guard refused both attempts; actual
service and cleanup remained FAILED and private Node was retained.

[Evidence](evidence/g3-owned-fragment-equivalence.json) preserves actual
artifacts and96 native/13 research/32 independent baseline proofs once.
Preceding native20/TLS18/16/preflight42/dependency46 and lifecycle104total/
103PASS/1rootSKIP passed separately; research PR actually ran21/7/27/48,
push research was scope-only. Those counts belong to the exactf434 source.
Earlier7d1 spelling and700/0ade primary causes remain unknown.

The new guard deliberately accepts only the loaded exact owned unit or
known runtime-link spelling. Runtime-link spelling requires canonical checks
of the two already known owned paths. Both spellings then repeat every
original link/file owner, mode, hash and target check after manager query.
Foreign manager-returned paths never become filesystem inputs. This is a
reviewed identity rule change, not blanket alias permission or OS fencing.

The pre-validation diagnostic snapshot still says canonicalIdentity:
not_measured; it does not describe later canonical verification. New local
owned-file and synthetic manager controls do not prove actual nonroot
service operation or cleanup. Exact new CI is pending. Service lifecycle,
logging, manager restart, adverse cases, combined TLS/service, package
rollback/recovery, permanent distribution, soak and Production V1 stay open.


## Opt-in automatic readiness after basic service acceptance

Both exactd119 native workflows passed the narrow real nonroot service
fixture: two separate start/stop sessions, manually invoked installed
wait-bind, HTTP proxy/upload/stream and complete owned service cleanup,
verified Node removal and bootstrap root removal. Native20/TLS18/16/
preflight42/dependency46 and lifecycle118total/117PASS/1rootSKIP passed
separately; research PR ran21/7/27/48 and push research was scope-only.
[Evidence](evidence/g3-auto-readiness.json) preserves actual artifacts and
101 native,13 research and72 independent baseline proof checks once.

The new explicit autoReadiness option adds ExecStartPost with the pinned
absolute Node, installed wait-bind and fixed10000ms budget. Missing/false
options retain identical default unit bytes. The lifecycle harness selects
the option and has no manual wait-bind fallback; after manager start it
independently observes the bound installed session. Local contracts and
independent controls do not prove this new actual manager path. Exact new
CI remains pending and readinessAutomated is not product acceptance.

The current basic-service success does not accept a single manager restart,
automatic readiness, logging, failed-start/cancel/drain/orphan or combined
TLS/service. Existing pre-validation canonical snapshots and truncation
limits remain explicit; earlier failed executions are retained as history.
Package rollback/recovery, permanent distribution, soak and Production V1
remain open. Next verify this exact automatic-readiness CI, then continue
the remaining bounded G3 operational gates.


## Fresh cleanup observations for each service attempt

Both exact1eb native workflows FAILED actual service at second_start /
request_start with primary unit_start_failed and separate cleanup failure
native_cleanup_unknown. One first automatic start/stop/proxy/upload/stream
cycle completed per run. The five true stop/absence cleanup flags were
already set by that first stop; they do not confirm final cleanup after the
failed second start. Removal flags stayed false and private Node/bootstrap
were retained. Hook cause and failing inventory record remain unknown.

[Evidence](evidence/g3-cleanup-freshness.json) preserves both actual failed
artifacts and95 native/13 research/74 independent proofs plus fresh46 CI
reconciliation checks once. Native20/recipe28/lifecycle124total123PASS/
1rootSKIP/dependency46/preflight42/TLS18/16 passed separately; research PR
actually ran21/7/27/48 and push runtime skipped. These do not accept the
failed full service lifecycle or final cleanup.

The checker now resets exactly five existing stop/absence facts before
every start and stop attempt, including finally cleanup. False means
current-attempt unconfirmed, not observed resource presence. All actions,
guards, counters, other cleanup fields and runtime-retention rules remain
unchanged. No hook telemetry is added. Local controls and review establish
report freshness only; exact new actual CI remains pending.

Next verify fresh cleanup reporting, then capture bounded direct installed
hook outcomes and an owned startup rendezvous. ExecMain is not the post-hook
and raw ExecStartPost serialization is unsafe evidence. Preserve the unknown
cause, original first-cycle progress and earlier adverse history. Automatic
two-cycle service, logging/restart/adverse/TLS, package recovery, permanent
distribution, soak and Production V1 remain open.


## Bounded owned post-start status observations

Both exactd697 workflows still FAILED second_start/request_start with
primary unit_start_failed and separate cleanup native_cleanup_unknown.
One first automatic cycle passed per run. The five current-attempt cleanup
confirmations are now false in both actual reports, narrowly verifying
cleanup-evidence freshness. False is unconfirmed, not physical presence;
final cleanup and hook/native/manager cause remain unknown. Private Node
and bootstrap were retained without a dependency-cleanup receipt.

[Evidence](evidence/g3-hook-status.json) retains the current actual native52,
research14 and independent66 audits plus fresh47 CI checks once. Native20,
recipe28, lifecycle138total137PASS/1rootSKIP, dependency46/preflight42 and
TLS18/16 passed separately; research PR ran21/7/27/48, push runtime skipped.
Matching outer failures do not prove the same historical cause or timing.

New best-effort observations query the known owned post-start property
before startup and after failed startup, publish finite classifications
and keep raw process/time identity private. recordChangedSincePreStart
is a tri-state record comparison only, never fresh invocation authority.
Guard/query/parse failures cannot overwrite primary errors or cleanup.
No startup repair or new service acceptance is claimed.

After the diagnostic await, normal full ownedProperties(false) authority
is checked again and requires inactive/MainPID0, then cancellation is
rechecked before start. Real state/authority refusals from that gate remain
mandatory; only the diagnostic itself is best-effort. A signal during the
failed-start observation does not replace the original unit_start_failed
primary. Existing normal command arguments, identity-check implementations,
counters, cleanup resets and runtime retention remain; admission now also
revalidates authority/state after the diagnostic await. Exact new CI is
pending; direct owned-hook outcome/rendezvous evidence and broader G3/V1
acceptance remain open.


## Explicit startup session preparation

Both exact ee464 native workflows FAILED second_start/request_start with
unit_start_failed and separate native_cleanup_unknown. Their guarded
post-failure known-command hook record showed exit1, but both pre-start
records were parse_refused and every record comparison was unknown.
Neither current invocation freshness nor semantic startup cause was proved.
Final cleanup remained unconfirmed and private Node/bootstrap were retained.
Separate native20 and lifecycle194PASS/1rootSKIP remain scoped observations.

The automatic-readiness recipe now runs installed prepare-run as ExecStartPre.
It uses the same locked guarded session preparation as run, publishing the
prepared session before run and strict wait-bind can execute concurrently.
Preparation neither starts native code nor performs bind/readiness. Missing
or false autoReadiness retains the exact previous default recipe bytes.
The general wait-bind state, registry and binding rules remain unchanged.

[Evidence](evidence/g3-startup-rendezvous.json) records the actual baseline
CI failure, source identities and separate local validation receipts. A
local ordering counterexample is not a reconstruction of the older hosted
failure. Exact new CI, repeated automatic service cycles and complete owned
service/private Node cleanup are required before scoped service acceptance.
Logging, one manager restart, adverse paths, combined TLS/service, package
rollback/recovery, permanent release, security/soak and Production V1 stay open.


## One manager restart and bounded journal verification

Exact401209 native push40173329359 and PR40173331990 both completed success.
Each actual nonroot service report recorded two automatic start/stop sessions,
readiness/proxy/upload/stream twice and complete owned service/private Node
cleanup. Native20/alpha62/recipe28 and lifecycle194PASS/1rootSKIP passed
separately. Research PR actually ran21/7/27/48; push runtime was skipped.
This accepts the narrow two-cycle basic path, not a manager restart or full V1.
The earlier ee464 failure is preserved in history and cleared as the active
service failure; the current service CI state records the exact401209 result.

The new acceptance checker adds one manager restart from an active second
session, exact old launcher/native retirement, distinct replacement identity
and bounded current-invocation journal observations. New cleanup receipts
require that profile; runtime retention and all existing identity/refusal
rules remain mandatory. Native/alpha/controller/recipe runtime is unchanged.
Local synthetic and contract tests do not accept a nonroot manager or journals.

[Evidence](evidence/g3-restart-journal.json) records actual prior CI, source
identities and separate local verification. The resulting restart/journal
CI is pending. Adverse startup/cancel/drain/orphan, combined service/TLS,
package upgrade/rollback/recovery, permanent release/provenance, security and
60-minute soak remain open. Production V1 and semantic Continuum migration
are not accepted; the next portfolio project remains waiting.

Local post-pin contracts passed333/333 with no skips/failures:246 lifecycle,
36 journal and51 cleanup-receipt controls. Independent source review passed191
proofs. These units are separate from513 unchanged source/license comparisons
and do not accept real manager/service behavior.


## Journal formatter sequence metadata compatibility

Both exacta03 native workflows FAILED first_start/journal_read with primary
journal_response_invalid. Startup/readiness/proxy/upload/stream each reached
one observation; restart commands and accepted journal checks remained zero.
Six process/socket/link cleanup flags and runtime unit removal were true;
installation/temp roots and private Node were retained, with no cleanup failure
or dependency-cleanup receipt. The actual rejected raw field/cause is unknown.

The journal parser now names the two optional standard systemd255 formatter
fields __SEQNUM and __SEQNUM_ID as ignored private metadata under the existing
shape/bounds rules. Required attribution, query/authority logic, checker pins,
workflow and all native/alpha/controller runtime remain unchanged. A fixed
public-formatter synthetic baseline refusal motivates the narrow change,
not a reconstruction of the historical raw CI condition.

[Evidence](evidence/g3-journal-format.json) preserves exacta03 failure and the
separate prior401209 scoped success. Local post-integration contracts passed
342/342:246 lifecycle,45 journal and51 dependency controls. Independent review
passed45 proofs;523 unchanged file comparisons and15 structural checks are
separate units. Actual journal/restart acceptance requires the resulting CI.
Full G3/V1, adverse paths, combined TLS/service, package rollback/recovery,
permanent distribution, security/soak and Continuum migration remain open.


## Partial downstream HTTPS service candidate

Both exact06e4 native workflows completed success on the scoped HTTP service
path:three native/start-stop/readiness/proxy/upload/stream sessions, one
manager restart, four retirement/replacement proofs, three bounded journal
checks and complete owned service/private Node cleanup. The old a03 failure
is appended to history before the active failure is cleared. Its raw rejected
journal condition is still unknown; later success does not reconstruct it.

The new candidate adds downstream HTTPS to the real operated service while
keeping an HTTP application origin. Positive CA/hostname payload exchange,
wrong-CA and wrong-host refusals, restart/journals and owned TLS-port/private
PKI cleanup must be verified by exact resulting CI. Local contract or fixture
checks cannot accept the actual nonroot service or its cleanup path.

[Evidence](evidence/g3-service-https.json) keeps this partial milestone explicit.
The unchanged RELEASE-CONTRACT/profile require both downstream HTTPS and a
verified HTTPS origin; this candidate does not close that combined TLS gate.
Full G3/V1, adverse recovery, package upgrade/rollback, permanent distribution,
independent security,60-minute soak and semantic Continuum migration stay open.

Local post-pin contracts passed384/384:267 lifecycle,45 journal,16 TLSfixture
and56 dependency controls. Independent review135 proofs,521 unchanged-file
comparisons, nine root integration and seven workflow checks remain separate
units. The strengthened helper late-callback draft15PASS/1FAIL and final16/16
are retained; actual managed-service TLS and both-leg acceptance stay pending.


## G3 combined HTTPS-origin candidate; full V1 not accepted

Prior exact1e6 push and PR native workflows passed the scoped downstream HTTPS service with HTTP
origin. Each observed three TLS sessions, one real manager restart, three attributable journals,
twelve verified positive certificate requests and three wrong-CA plus three wrong-name refusals.
All nine service cleanup confirmations, private Node/bootstrap removal and zero remaining
application sockets were observed. These are distinct request/session units, not twelve
installations. Earlier HTTP-only06e4 acceptance and a03 unknown raw journal rejection remain
unchanged in history.

The new local candidate combines downstream HTTPS with a verified HTTPS origin. Its owned relay
queries regular native HTTP /ready with an immutable per-candidate marker; it neither borrows
direct-origin readiness nor native management self-health. Tags correlate the candidate input;
they are not authentication, all-worker fencing or atomic cutover. Ordinary application traffic
remains native NGINX. Existing release contract/profile, TLS helper,
native/controller/alpha/recipe/preflight/journal sources are unchanged.

Actual local combined tests:474/474 PASS, zero FAIL/SKIP/cancel/TODO and empty stderr:328
lifecycle,45 journal,16 unchanged downstream TLS helper,23 new origin helper,62 dependency
receipt controls. Independent review passed229 bounded controls:45 real owned Node origin
TLS/fake-native relay,107 extracted harness,13 lifetime and64 boundary/receipt controls. Root
checked10 source/pin/contract conditions and7 workflow conditions;518 other protected files were
byte-identical. Proof units are separate from test counts and do not count installations.

The managed-service candidate requires three distinct combined origin body/upload/stream
sessions. Three separate bad upstream CA/name/plaintext candidates each require independent
good-origin reachability, exact installed rollback, fresh candidate-tag native502, restored HTTP
and downstream HTTPS payloads, and zero application POST replay. One direct-origin counter is
the initial check; downstream twelve positive certificate requests exclude three additional
restored-path probes. Four extra origin/relay server-and-port cleanup booleans augment prior
cleanup guards. Direct helper exact-leaf checks do not claim native leaf pinning.

Two initial test assertions failed and remain recorded:the harness expected object omitted
origin_negative, and the missing-marker test helper defaulted undefined to a valid marker.
Corrections changed test expectations/inputs without changing runtime admission. Final
harness328/helper23 passed. A separate read-only unchanged-file inventory refused the already
edited coordinator workflow; corrected518-file scope excludes it. These observations do not
identify any historical managed-runtime failure cause.

Local Node24 UID0 fixtures, pure contracts and source-extracted controls do not accept actual
Node22 nonroot managed combined TLS. Exact resulting CI is pending and may fail. Require
complete owned origin/downstream TLS/relay/PKI/service/private Node cleanup. Same-UID trust and
user-space timeout limits remain; no complete secret-erasure claim. Full G3, adverse
startup/drain/recovery, separate config/package rollback, permanent distribution, independent
release acceptance,60-minute soak and Production V1 remain open. Deferred Continuum and full
native roadmap remain preserved.


## G3 failed-start control; exact service CI pending

Prior exact dd6c push40185635547 and PR40185637960 native workflows completed
success with all31 required actual steps. Each observed three combined downstream
HTTPS and verified HTTPS-origin sessions, one manager restart, three attributable
journal checks, bad upstream CA/name/plaintext refusal with rollback and all13
owned service cleanup confirmations. Private Node/bootstrap removal was also
confirmed. Fresh review reused approved archives and passed80 separate proofs;
research PR actually ran21/7/27/48 while push runtime was skipped. No unchanged
runtime rerun was requested. This accepts the scoped prior path, not full G3/V1.

The new acceptance candidate deliberately refuses startup while its owned HTTP
application returns503 for readiness. It first holds the owned health response
long enough to capture the activating unit, launcher/native session, invocation
and post-hook identity. After explicit refusal, acceptance requires exact manager
exit1/failed exit-code and known current post-hook exited1. A timeout, signal,
foreign/stale identity, malformed record or missing observation cannot substitute.
Observed503 and hook exit1 do not exclude every possible internal failure cause.
Captured values remain private; published output uses bounded counts and booleans.

Before the application becomes healthy, the checker requires no binding or pending
transaction, a stopped captured session, exited owned launcher, absent native
groups and closed gateway/health/control resources. Only that exact hash/owner/link
verified failed unit may be reset after a final absence check. The first healthy
start must use fresh session, invocation and launcher identities. The failed
session is retained in cleanup inventory and is not one of the three successful
TLS/readiness/I/O sessions. No broad reset, direct kill or manager-setting change
is added. The normal combined TLS/restart/journal/final cleanup path remains.

The narrow report requires failedStartChecks1 and all11 failedStartProof booleans.
Strict dependency cleanup rejects prior/missing/partial proof receipts and retains
private runtime on unknown outcomes. Broad failedStartAccepted, serviceAccepted
and productionAccepted remain false. Source hashes, final actual local counts,
separate independent reviews and any adverse drafts are in
[failed-start evidence](evidence/g3-service-failed-start.json).

Local root contracts and source-extracted controls do not execute the nonroot
managed service. Exact resulting CI is pending and may fail. Native, controller,
alpha, unit recipe, release contract/profile and prior TLS/journal helpers are
unchanged. Same-UID trust, user-space timeouts and PID-to-signal limits remain.
Prior a03 raw journal rejection cause and older failure interleavings are still
unknown; later success does not explain them. Full adverse startup/cancel/drain/
orphan recovery, package upgrade/rollback/backup restore, permanent distribution,
security acceptance,60-minute soak and Production V1 remain open. Deferred
Continuum and the full native roadmap are preserved.


## G3 controlled drain; actual service CI pending

Both exact13d native workflows completed success with all31 required actual steps.
Each observed one deliberate unhealthy readiness startup refusal, all11 owned
failure/retirement/recovery proofs and a fresh healthy start. The three normal
combined downstream HTTPS and verified HTTPS-origin sessions, one manager
restart, three attributable journal checks and all13 final cleanup confirmations
also passed, with private Node/bootstrap removal. Fresh82-proof review reused
approved archives and logs. Research PR actually ran21/7/27/48; push runtime was
skipped. These are separate observation units, not four accepted installations.
The broad failed-start and complete G3/V1 contracts remain unaccepted.

The new candidate starts one controlled held response on the owned HTTPS origin
and pauses a verified downstream TLS client after its initial response bytes.
Within the same third healthy service session, it captures owned unit, session,
invocation, launcher and native identities, then issues one manager stop. Before
release, it must observe that command pending, the exact unit deactivating, the
owned native group still live and the response incomplete. These observations
must bracket the same identities; stale or unrelated processes grant no authority.

Only then may the origin release its held suffix and the client resume. The full
response must complete with exact payload and verified downstream TLS, followed
by completed manager stop and fresh absence of captured launcher/native groups,
gateway/health/TLS ports and the control socket. Cancellation, timeout, premature
close, payload mismatch, foreign/stale identity or unknown cleanup must fail
closed and retain private runtime. All previous startup-refusal, combined TLS,
restart/journal, callback lifetime and final cleanup guards remain required.

A report requires controlledSlowDrainChecks1 and all14 narrow proof booleans.
The dependency cleanup profile refuses old, missing or partial drain evidence.
Final source hashes, actual local test counts, independent review and preserved
adverse drafts are recorded in
[slow-drain evidence](evidence/g3-service-slow-drain.json).

This is a controlled held-origin response and paused-client graceful-stop check.
It does not establish pure network backpressure, every slow-client/drain case,
slow upload, abnormal/orphan recovery, resource/performance acceptance or the
predeclared60-minute soak. Broad slowDrainAccepted, serviceAccepted and
productionAccepted remain false. Local Node contracts/loopback helpers and
source-extracted checks do not execute the actual nonroot managed native service;
exact resulting CI is pending and may fail.

Native/controller/alpha, unit recipe, journal/downstream TLS helper and release
contract/profile remain unchanged. Same-UID trust, user-space timeout limits and
PID-to-signal races remain explicit. Earlier adverse evidence and unknown raw
historical causes are preserved. Distinct package upgrade/rollback/backup restore,
permanent distribution, independent release acceptance, full G3/V1 and semantic
Continuum remain open; the next portfolio project remains waiting.


## G3 operator interruption; actual service CI pending

Both exactf9 native workflows completed success with all32 required actual steps.
Each observed one controlled held-HTTPS-origin response and paused verified-TLS
client graceful stop, all14 narrow drain proofs and exact payload completion.
The prior startup refusal/all11 proofs, three healthy combined TLS sessions, one
manager restart, three attributable journal checks and all13 final cleanup
confirmations also passed, including private Node/bootstrap removal. Fresh86-proof
review reused approved archives and logs; research PR actually ran21/7/27/48,
while push runtime was skipped. These scoped observations do not accept every
slow-client state, network backpressure, recovery failure or Production V1.

The new candidate interrupts one installed APPLY CLI while a unique candidate's
native readiness probe is held and its durable transaction is reload_requested.
Before signalling, it must match the fresh current last-confirmed revision,
candidate/input/fragment/history relation, service/native/session/invocation and
the two exact owned operator processes plus their two captured lock inodes.
Only the captured operator process group receives SIGTERM; the service continues.
A timeout or broad process search is not accepted as confirmed interruption.

Both stale locks must remain after those operators exit. Installed recover must
first refuse alpha_locked without changing the transaction. The test helper then
models the existing documented trusted-operator manual-inspection step: after
confirming the recorded lock owners and their process group absent, remove only
the same two inspected fixture-owned lock inodes. This helper action is confined
to its disposable installation; no installed automatic lock-reaping API is added.
An unknown, replaced, foreign or still-owned lock must remain untouched.

Explicit installed recover must return exit1/rolled_back/explicit_recovery with
the expected candidate/previous-revision relation, clear pending and restore
exact HTTP and verified HTTPS content. The same live owned service/session/
invocation must remain, application POST counts must not advance, and repeated
recover must return nothing_pending. A report requires operatorInterruptionChecks1
and all14 narrow operatorInterruptionProof booleans; strict dependency cleanup
must refuse prior, missing or partial interruption receipts. Previous failed-start,
controlled drain, combined TLS/restart/journal and final cleanup guards remain.
Final hashes, actual local counts, independent reviews and adverse drafts are in
[interruption evidence](evidence/g3-service-operator-interruption.json).

This is one controlled APPLY-CLI interruption and explicit recovery scenario.
It does not establish automatic production stale-lock cleanup, all crash/storage/
orphan states, binary/package rollback, all-traffic atomic cutover or reversal
of application side effects. Local root contracts and loopback/helper checks do
not execute the actual nonroot managed native service; exact resulting CI remains
pending and may fail. Broad operatorInterruptionAccepted, serviceAccepted and
productionAccepted remain false.

Native/controller/alpha, unit recipe, prior slow-client/journal/downstream TLS
helpers and release contract/profile remain unchanged. The manual-inspection
rules in alpha/control documentation still apply to real operators. Same-UID
trust, user-space timeout limits and PID-to-signal races remain explicit. Earlier
adverse evidence, unknown historical causes and the prior expired-lease safe
resume record are preserved. Full G3/V1, abnormal/orphan recovery, distinct package
upgrade/rollback/backup restore, permanent distribution, independent release
acceptance,60-minute soak and semantic Continuum remain open.


A local process-fixture draft timed out because its PID namespace and mounted
/proc view differ. Some own private fixture prefixes were removed before process
absence was proven; old cleanup remains FAIL/UNKNOWN. The final helper refuses
this profile before any spawn. Nine physical group cases are SKIP locally, not
PASS; exact supported-host CI must run all18 without skips. No namespace entry,
host-PID signals or permission changes were used. Later CI success cannot erase
this earlier local cleanup uncertainty.


## G3 mixed interruption CI; containment candidate remains pending

Exact3bf native CI had mixed actual outcomes. Push40209963590/job121218936536
FAILED required service step28 during operator_interruption: the primary failure
was operator_fixture_not_held after the first four of14 interruption proofs.
Cleanup separately recorded unit_stop_unconfirmed; nine final cleanup flags
remained unconfirmed, no private Node cleanup receipt existed and bootstrap
retained its runtime/root. False flags mean unconfirmed, not observed presence.
PR40209966500/job121218941776 passed its scoped operator recovery, controlled
drain, startup refusal, three combined TLS sessions, restart/journals and13 final
cleanup confirmations with private Node/bootstrap removal. Both actual operator
suites ran18 tests without skips. The implementation is not accepted by the PR
success. The92 factual audit checks reconcile observations, not92 runtime passes.

Research PR actually ran21/7/27/48 while push runtime was skipped. Those separate
passes do not override native service failure. Earlier local operator fixture
cleanup remains FAIL_UNKNOWN, including the previously recorded prematurely
removed private prefixes; later hosted evidence cannot repair that uncertainty.
The exact historical not-held interleaving/internal cause remains unknown.

The new candidate adds bounded, finite interruption-step/guard observations and
failed-fixture containment. Diagnostics publish no raw paths, process identifiers,
command output, private pending/configuration bytes or secrets and grant no
lifecycle authority. The existing1000ms held-probe and350ms hook budgets remain;
no timeout extension or same-SHA rerun is used to relabel the failed result.

Failure containment must stay within the already captured owned operator group,
exact captured lock inodes, immutable pending/input identity, original deadline
and current process-absence guards. It cannot rearm a refused capability, acquire
candidate acceptance, blindly clear foreign/stale locks or replace the original
primary error with successful cleanup. Any explicit fixture recovery remains
separate from runtime acceptance. Unknown cleanup retains the installation and
private dependency. The new refusal/containment controls and final frozen hashes,
actual local results and independent review are in
[containment evidence](evidence/g3-service-interruption-containment.json).

The original push failure and scoped PR success remain separate durable records.
New exact CI is pending and must run all26 operator controls with zero skips.
No actual nonroot managed service is run by
local root contracts or source-extracted controls. Prior startup/drain/TLS/
restart/journal guards, every existing acceptance proof and namespace refusal
remain required. This candidate does not establish the historical not-held cause,
a general automatic lock cleaner, production crash recovery or package rollback.

Native/controller/alpha, unit recipe, origin/slow-client/journal/downstream TLS
helpers, release contract/profile and the broad roadmap remain unchanged.
Installed service-recipe distribution is parked until the current required
service failure is understood and accepted runtime evidence is available.
FullG3/G4-G8, permanent release, security/soak, Production V1 and semantic
Continuum remain unaccepted. No other portfolio project is started.


A normal hosted interruption PASS does not prove the separate failure-containment
branch ran. New receipts must retain its attempted/completed disposition and the
first finite hold refusal. If that branch was not exercised, actual managed
failure-containment acceptance remains pending despite passing normal controls.


## G3 native held challenge; prior containment scope kept separate

Exactc1cf native CI again had mixed actual outcomes. Push40212661367 completed
its normal scoped service path with all14 operator proofs, controlled drain,
startup refusal, three combined TLS sessions, restart/journals and13 cleanup
confirmations plus private Node/bootstrap removal. PR40212664983 failed the
normal interruption path after the first4 proofs. Its finite first refusal was
terminate_capture/live_probe_gap at347ms with deadlineExpired:false. The primary
operator_fixture_not_held remained unchanged. This does not prove the earlier
3bf failure had the same timing or identify every internal cause.

The PR did execute strict failure containment: all7 containment booleans were
true, disposition contained,11 owned cleanup facts and runtime-unit removal
confirmed, cleanupFailures empty. Installation/temp roots and private Node/
bootstrap were retained; this is scoped containment evidence, not normal-profile
or complete-cleanup acceptance. Both operator26 and failure-QA100 controls passed
without skips. Research PR ran21/7/27/48; push runtime was skipped. Fresh60 factual
audit checks preserve these outcomes separately and do not accept allc1cf.
Earlier3bf pushFAIL/PR scopedPASS and local fixture cleanup FAIL_UNKNOWN remain.

The new candidate requires a runner-owned fresh one-use nonce challenge through
the actual native candidate route. It must bind the response to the current
candidate tag, held request and service/native/pending authority, then reobserve
that authority before signalling. Direct-origin readiness, cached relay state,
a retained sourceHeld Boolean or a response from another candidate/nonce must
not substitute. Nonces and raw response/identity values remain private; public
evidence contains only allowlisted counters, booleans and source bindings.

Normal interruption acceptance additionally requires operatorNativeChallengeChecks1
and exactly6 true operatorNativeChallengeProof fields: nativeRouteObserved,
ownedRequestObserved, relayResponseMatched, candidateBindingMatched,
authorityReobservedBeforeSignal and ownedChallengeClosed. These augment all14
existing operator proofs in strict dependency cleanup receipts. A failed or
contained attempt cannot increment that successful counter or obtain challenge
acceptance. The1000ms hold,350ms hook,8s fixture and original10s operator helper
budgets remain unchanged. Strict captured-only containment, cancellation,
primary-error preservation and every older admission guard remain mandatory.
Final actual local results, source bindings, reviews and adverse drafts are in
[native challenge evidence](evidence/g3-service-native-held-challenge.json).

This is freshness evidence for an application/service acceptance fixture. It is
not authentication, malicious same-UID isolation, OS fencing or a Continuum/TLS
state-transfer result. Wrong/stale/replayed nonce, wrong candidate, timeout,
malformed response, closed challenge or lost current authority must fail closed.
The new actual nonroot service CI is pending and may fail; local root contracts,
Node loopback helpers and source-extracted controls cannot accept it.

The operator process helper/test, native/controller/alpha, unit recipe, prior
slow-client/journal/downstream TLS helper and release contract/profile stay
unchanged. Earlier3bf failure and old local FAIL_UNKNOWN are not retroactively
repaired. Installed recipe distribution remains parked until required service
acceptance; fullG3/G4-G8/V1, package rollback, permanent distribution,60-minute
soak and semantic Continuum remain open.


## G3 admission diagnostics and captured early-failure containment candidate

Exact0420287 native results remain mixed. Push40215886529 completed its scoped
native challenge, operator recovery, startup refusal, controlled drain, TLS,
restart/journals and complete owned cleanup. PR40215890093 failed before initial
ownership capture with primary origin_challenge_identity and final
cleanup_unconfirmed/unit_stop_unconfirmed. Its containment was no_snapshot;
all six challenge and fourteen operator proofs stayed false. The exact rejected
historical admission predicate is unknown. Fresh51 factual readback checks do
not turn this mixed result into acceptance. Research PR ran21/7/27/48; research
push runtime was skipped. Earlierc1cf scoped containment,3bf mixed outcomes and
local cleanup FAIL_UNKNOWN remain preserved.

This candidate records bounded first-refusal admission stages/reasons, status
classes, matched-field booleans and bounded counters without nonce/tag/header,
body, route, port, PID or raw-error values. Diagnostics cannot grant authority.
Accepted records admission history; after cleanup,
currentPairLive is false and cannot authorize any later action.
Cleanup ownership and the pending snapshot are captured before challenge open,
using only a current stage-restricted initial held probe. Acceptance interruption
still requires the owned current native challenge at both termination stages;
there is no legacy fallback for the acceptance signal. Failed admission keeps
its primary failure and can use only the original strictly captured cleanup
snapshot. Full pending and same-service identity are reread after awaited open.
A late callback, stale identity or expired deadline cannot revive it.

All14 operator and six challenge proofs, strict cleanup receipts and original
1000ms/350ms/8s/original10s budgets remain required. Native/controller/alpha,
operator process helper/test, unit recipe and release contract/profile stay
unchanged. Local contracts and Node bridge controls do not execute the actual
supported nonroot managed native service. Final frozen local integration846/846 passed with zero
skips/failures.
Exact resulting CI remains pending.
See [admission evidence](evidence/g3-service-challenge-admission.json) for
frozen source bindings, actual local counts, review and adverse draft history.

Installed recipe distribution remains next after required current service
acceptance. FullG3/G4-G8/V1, package rollback, permanent release,60-minute soak
and semantic Continuum remain open. No production or deployment change is
performed by this fixture checkpoint.

The prior lease expired while tree creation was pending. That tree remained
unpublished: no implementation commit or implementation ref update occurred.
This checkpoint resumes from fresh ownership with identical source bytes and
fresh root verification; the original owner work window is unchanged.


## G3 installed recipe distribution candidate; prior normal scope accepted

Exact89aa native push40265731122 and PR40265734847 completed all34 actual
required steps each. Both passed the scoped normal native challenge/operator
recovery path with all6 challenge/all14 operator proofs, controlled drain,
startup refusal, three combined TLS sessions, restart/journals and all13 cleanup
facts plus private Node/bootstrap removal. Failure containment was not_needed;
its actual failure branch remains unexercised. Final admission diagnostics show
accepted history after closure, not current signal authority. Research PR ran
21/7/27/48; push runtime was skipped. Inherited CLA failure remains unbypassed.
This accepts the scoped89 implementation, not fullG3 or Production V1. Older
mixed failures, unknown historical causes and local cleanup FAIL_UNKNOWN stay.

This candidate adds an immutable service recipe helper to exact schema2 bundle
and install inventories. The installed service-unit command validates the full
installation and recorded Node identity before importing that helper. It prints
structured JSON whose unit field contains the generated unit; it writes no
unit file and performs no linking, enablement, manager start or activation.
The actual service harness obtains its recipe from installed payload, with no
source-checkout fallback. Existing manual/automatic rendered unit bytes remain
unchanged; helper validation and distribution runtime do change.

Strict cleanup receipts now additionally require bundleSchemaVersion2,
installSchemaVersion2 and installedRecipeGenerated:true. These augment all six
challenge/fourteen operator/startup/drain/TLS/restart/journal/cleanup obligations;
they do not substitute for them. An emitted field is not proof until the actual
installed payload is strictly verified. Exact resulting native service CI is
pending; local contracts cannot accept that supported nonroot operated service.
Final frozen local contracts1017/1017 passed; separately selected alpha14/14
passed. Older physical alpha groups were filtered and not run. Native aggregate
and actual managed service were not executed locally. See evidence for units.

Legacy schema1 packages retain their existing commands and source recipe path.
Their original package bytes do not acquire the new installed service-unit
command. The new CLI reading a valid legacy manifest refuses that new command
as service_recipe_unavailable. Exact v1/v2 inventories are selected by declared
schema; mixed or partial helpers, unknown files and mode/link drift are refused.
No in-place conversion, package upgrade/rollback or G4 migration is claimed.
FullG3/G4-G8/V1, permanent distribution, independent published-file acceptance,
60-minute soak and semantic Continuum remain open.

See [installed recipe evidence](evidence/g3-service-installed-recipe.json).


## G3 exact195 full-alpha failure and recipe Node fixture candidate

Exact195a native push40268333912 and PR40268338245 both failed step20:
19/20 native groups and full alpha76 TAP tests,74PASS/2FAIL. The extracted-bundle
recipe subtest and its parent reflect one nested service_recipe_invalid refusal
at the exact recorded-Node guard. The individual path/version/owner/mode/hash
comparison was not recorded and remains unknown. Selected new controls passing
did not override this full-profile failure. Managed service step29 was skipped;
service/package/archive/bootstrap/Node cleanup reports were absent. Missing
reports do not establish successful actual service execution or cleanup.
Research PR ran21/7/27/48, push runtime was skipped and CLA failure remains.
Prior89 scoped normal native challenge/operator acceptance remains unchanged;
its actual failure containment was unexercised. All older adverse history and
local cleanup FAIL_UNKNOWN remain preserved.

This candidate changes only the alpha test fixture. The checked-bundle path and
synthetic positive recipe fixture share a private owned0500 exact Node copy;
installation records that runtime and recipe generation executes the same copy.
The host executable is not chmoded, replaced or adopted as owned fixture data.
This satisfies the fixture prerequisite without relaxing product validation.
The local observation motivates the fixture change; it does not identify the
specific unrecorded comparison in the historical195 CI refusal.

CLI/helper/archive verifier, actual-service harness, strict cleanup receipts,
workflow and all native/controller runtime bytes remain unchanged. Schema2
inventories and required bundleSchemaVersion2/installSchemaVersion2/
installedRecipeGenerated:true facts remain mandatory, together with all prior
challenge/operator/startup/drain/TLS/restart/journal/cleanup proofs. The actual
new full native/alpha profile and installed-payload managed service CI remain
pending. Local selected16/16 passed with actual exit0; older physical groups and
unchanged runtime contracts were not rerun. These selected fixture controls
cannot accept the full native/service path or erase the195 failure.
FullG3/G4-G8/V1, package lifecycle, permanent release, independent published-file
acceptance,60-minute soak and semantic Continuum remain open.

See [fixture evidence](evidence/g3-service-recipe-node.json).


## Declarative backup foundation and exact installed recipe CI — 26 October 2026

The exact previous implementation `eb577ff140b376b68c2cd10984deb736d3a9ed67`
passed native push40270300320/job121401514260 and
PR40270304404/job121401530223, with all34 actual steps in each job. Each
reported20/20 native groups and78/78 full alpha TAP tests without skips or
failures. Schema2 bundle/install and installed recipe generation were observed
on the real managed-service path. Each retained all6 native challenge,
14 operator interruption,14 controlled drain,11 failed-start and13 cleanup
facts, three combined TLS sessions, one manager restart, three journal checks,
zero remaining application sockets and private Node/bootstrap removal.

This accepts that normal scoped installed-recipe/service implementation only.
Actual failure containment was not exercised. The current source mode observation
does not establish the specific historical195 Node comparison, which remains
unknown. Both195 full-alpha failures before managed service, absent service and
cleanup evidence, older adverse observations and local cleanup FAIL_UNKNOWN are
preserved. Research PR40270304433/job121401537325 actually ran21/7/27/48;
research push runtime was skipped. CLA40270302762 remains a separate failure
without signing an agreement or bypassing checks.

The new alpha runtime adds private declarative backup from clean stopped/prepared
sessions and fresh unbound restore into an absent prefix. The exact current
local counts, baseline counterexample, source bindings, independent reviews and
adverse controls are recorded in [backup evidence](evidence/g4-declarative-backup.json).
Local tests are the named synthetic/pure profile. Physical native process groups,
manager activation and the full native aggregate were not run locally in this
nested namespace; supported hosted CI is required. No physical local cleanup
uncertainty is repaired by a later hosted pass.

The source's package, bindings, process identities, session history, libraries
and TLS material are not transferred. Exact declared ports and candidate input
are retained; external referenced files are not copied or remapped. Fresh native
`-t` does not check application readiness. This is a G4 foundation, while broadG3
and G4-G8 acceptance remain open. Package A-to-B-to-A, permanent release,
independent published replay,60-minute soak and full semantic Continuum are not
accepted. Exact resulting native/restored-service CI is pending; do not substitute
the previouseb success for the newly changed alpha runtime.


The earlier unpublished candidate tree5cb23ff2c72760d98be0652abaae3d5377cafedb
was created, but the deadline guard stopped before any implementation commit
or ref update after its lease expired. Its local Git backing directory became
unavailable. A fresh full clone, central/source readback and new lease were used
for resumption; the three frozen source files were copied without byte changes.
The coordinator reran125 selected controls in the fresh copy, with separate
82-case QA and named independent resumption reviews. Old results are retained
as old results. This does not extend the owner work window or prove new hosted CI.


## Restored HTTP application fixture and exact backup CI — 26 October 2026

Exact backup implementation `1c257bd85c27e905ddc8d7d2725a7ebc579b81d7` is
reconciled from native push40282133430/job121437617601 and
PR40282138842/job121437649271: both completed all34 actual steps successfully,
with20/20 native groups and160/160 full-alpha TAP tests per job. Actual fresh
unbound restore retained16 finite observations and completed native `-t`; no
restored daemon or application readiness was exercised. Both separate normal
service paths retained challenge6/operator14/drain14/startup11, combinedTLS3,
restart1/journal3, all13 owned cleanup confirmations and private Node/bootstrap
removal. Actual failure containment remained unexercised.

Research PR40282138736/job121437645059 actually ran21/7/27/48; research push
runtime was skipped and CLA40282136447 failed without agreement or bypass.
A separate synthetic source-extracted counterexample showed that an existing
fixture stdout handler accepted an incomplete numeric PID prefix before the
newline. No real native process or signal was used in that counterexample.
The shared fixture parser now requires a complete bounded stdout line and a
safe PID greater than one before registration; persistent controls cover the
refusal boundary. This is a fixture correction, not a native runtime or
PID-to-signal race fix.

The historical195 Node comparison, earlier failing interleavings, initial
UTF-8 backup counterexample and local cleanup FAIL_UNKNOWN remain preserved.
No unchanged workflow rerun was requested to obtain these observations.

Only the alpha test fixture and its new persistent PID-framing controls change now. It authors actual restored foreground
HTTP application start/bind/readiness/traffic/stop/owned-removal and original
source/backup preservation checks. Frozen local selected controls and independent
source/security/semantic reviews are recorded in [restored-app evidence](evidence/g4-restored-app.json).
The full physical native aggregate and service were not executed locally in the
nested namespace. Exact resulting native CI remains pending, so the new actual
restored application path is not yet accepted by this checkpoint.

The owner directly requested another10-hour X10 window on26October.
The current code cutoff is27October2026 03:23:06UTC (07:23Samara),
with report-only cleanup until04:23:06UTC. The old60-hour window
and its history remain recorded.

FullG3/G4-G8/V1, separately restored managed service, TLS backup, meaningful
runtime-package A-to-B-to-A, permanent distribution, independent published replay,
60-minute soak and full semantic Continuum remain open.


## Recovery checkpoint after expired coordination lease — 27 October 2026

A preceding candidate tree remained unconfirmed after an attempted
Git object write. Fresh branch readback still named the preceding
lease-only commit, and the candidate tree lookup returned404 without
confirming remote creation. No implementation commit or implementation
ref update had been attempted. The unknown Git-write outcome remains
unaccepted.

The preceding lease had expired before resumption. The coordinator obtained
a new lease with a new run identifier, exact ancestry and state readback,
then recreated a clean worktree. This was a new acquisition, not renewal of
the expired term. The two reviewed source files remained byte-identical.
Fresh selected162 TAP and46 separate virtual controls passed under the new
lease. Physical native/service checks remain pending exact resulting CI.
The earlier valid renewal and all adverse/unknown outcomes remain history.
The owner window still ends27October2026 03:23:06UTC.


## Reviewed fixture checkpoint after sanitized bootstrap — 27 October 2026

The owner approved a single technical checkpoint cleanup together with new
lease acquisition. Exact parent, tree and lease readback were verified.
The coordinator recreated a clean worktree and retained the two reviewed
source files without changing their bytes. Fresh assigned-tester selected162 TAP and46
separate virtual controls passed; actual restored native application
acceptance remains pending exact resulting CI. Existing technical evidence,
adverse outcomes and private spending/authority limits were preserved.
This does not accept managed-service restore, package rollback or V1.


Gate-plan synchronization remains pending as a separate write. This
fixture checkpoint leaves GATES.json unchanged; fullG3/G4/V1 is not
accepted. Exact resulting implementation CI remains required.


The compact technical BACKGROUND requires readback of the complete prior
acceptance, pending work and adverse history at commit
`a276533d8472bfdd8cc74322864a350d6f15e107`. That Git history is unchanged.
Private operational policy remains in force; compaction changes no gate,
spending allowance, native capability or acceptance claim.


## Exact restored foreground HTTP CI and technical gate checkpoint — 27 October 2026

Implementation245d25ca4878b2dcb08fd34c0353b2f9a1ff6c02 passed both native
workflows with34 actual successful steps,20 native groups and197 full-alpha
TAP tests each. Both observed all35 finite restored-HTTP diagnostic fields,
including fresh identities, wrong-readiness refusal, exact GET/POST without
replay, graceful owned stop, closed resources and preserved source/backup.
Normal managed-service evidence remained scoped; actual failure containment
was unexercised. Research PR ran21/7/27/48; push runtime skipped and CLA failed.
Full G3/G4/V1, managed-service restore, package rollback, permanent release
and60-minute soak remain open. GATES keeps all10 gate core records and
unchanged statuses; every earlier deep record is mandatory through its
immutable245d commit/blob reference. Evidence: x10/evidence/g4-restored-http-hosted.json.


## Restored HTTP managed-service candidate — 27 October 2026

A new service acceptance fixture stops the confirmed HTTP source before TLS
configuration, exports its private declarative backup, retires its exact unit
and restores into a new installation, session, revision and systemd-user unit.
It checks HTTP serving and manager restart, then preserves the existing TLS
regressions and verifies six original records, backup and archive through
owned cleanup. The two authenticated checker pins identify the exact reviewed
source; no timeout, permission or runner policy is relaxed.

Frozen local Node24 pure/tempfile/virtual checks passed802/802, including84
new controls. Independent14 virtual review controls are a separate count.
No physical native or systemd fixture ran locally. Exact resulting hosted CI
is PENDING; expected5 sessions,2 manager restarts,6 bounded journal checks
and3 TLS sessions are assertions to verify, not local runtime observations.
Evidence: x10/evidence/g4-restored-service.json. FullG3/G4/V1, TLS backup,
meaningful package A-to-B-to-A, permanent release and60-minute soak stay open.

The owner renewed the X10 work window for20 hours from27October2026
03:45:59UTC to23:45:59UTC (28October03:45:59Samara). Earlier windows remain
history. Six useful helper roles supported this bounded pass; continuous
processes and completion by elapsed hours are not guaranteed. Existing
authority, spending, deployment and other-project limits remain unchanged.
The deferred Windows plan is saved in PLAN and does not change the central
portfolio queue or claim Windows compatibility.


## Exact restored HTTP managed-service acceptance — 27 October 2026

Implementation831360a9a9770815c660f5bc06d002b92154a1b0 passed native
push40447807340/job122003205464 and PR40447810051/job122003208919:
34 actual successful steps,20 native groups and197 alpha tests each.
Both actual artifacts contain all18 restored proofs,5 successful sessions,
2 manager restarts,6 bounded journal checks and unchanged3 TLS sessions.
All13 cleanup facts, socket absence, unit removal and private Node/bootstrap
removal are verified. Hosted contract results are617PASS/1root-onlySKIP;
the real nonroot service was exercised separately. Failure containment
remains unexercised. Research PR ran21/7/27/48; push runtime skipped, CLA failed.

This accepts only restored HTTP configuration within the same checked
runtime package and the declared temporary systemd-user profile. It does
not accept a distinct-package A-to-B-to-A transition, TLS restore, external
application data recovery, permanent release, soak or fullG3/G4/V1.
The two archives differ in provenance, with the same native binary;
that difference is not a package-upgrade acceptance. Next: implement the
explicit side-by-side package transition/state-compatibility contract and
verify meaningful A-to-B-to-A, preserving known-good files and prior failures.
Evidence: x10/evidence/g4-restored-service-hosted.json.


## Installed package identity foundation — 27 October 2026

The installed package-info command verifies the complete installation and
recorded host dependencies before reporting canonical runtime/operator payload
fingerprints and a separate native binary hash. Build/provenance, docs,
examples and installation/session/host metadata do not create a different
runtime identity. Excluded immutable files are still verified by the existing
installation guard. Inspection takes no alpha lock, writes no state and
launches no native code. Hashes are consistency records, not signatures.

Frozen local Node24 pure/tempfile checks passed248/248, including86 new
controls. Independent10 pure heldouts are a separate count. Four initial
source-extracted install test failures were fixed by relocating the new
helper; old assertions were preserved. Actual extracted-bundle observations
and new runtime regressions remain pending exact hosted CI. Native source,
package inventories, schemas, workflows and service checker pins are unchanged.

The831360 restored HTTP service receipt remains scoped to its exact runtime.
This feature does not accept package staging, state compatibility, A-to-B-to-A,
native binary upgrade, TLS restore or fullG3/G4/V1. After exact package-info
acceptance, implement the supported side-by-side package transition while
preserving the old package and records. Older A has no package-info command;
its identity must come from independently verified known installed records.
Evidence: x10/evidence/g4-package-identity.json.

A separate exact-name Node/private-tempfile test passed1/1 using a
nonexecuted native placeholder. It exercises the actual installed CLI and
strict file/dependency guards without NGINX, service or signal execution.
This result is not added to248 or claimed as extracted-bundle acceptance.


## Exact installed package identity acceptance — 27 October 2026

Implementationacb648392e745b5246a5620f2ea6a6286dc06d42 passed native
push40455973705/job122029316296 and PR40455978706/job122029337388:
34 actual successful steps,20 native groups and284 alpha tests each.
Both artifacts contain the15-field package identity diagnostic,11 runtime
files and identical runtime/operator/native fingerprints across contexts.
Actual installed-byte, fresh restored identity, prepared-record/owned-lock
preservation and argument-refusal observations passed. The passing fixtures
also retain excluded immutable-file and dependency-drift refusals, plus
unchanged application request/POST counters before first startup.

Existing restored-service regressions also passed on this new CLI:18 proofs,
5 sessions,2 restarts,6 bounded journal checks,TLS3 and all13 cleanup facts,
with unit/private Node/bootstrap removal. Service contract617PASS/1root-only
SKIP remains explicit; normal operation did not exercise failure containment.
Research PR actually ran21/7/27/48; push runtime skipped and CLA failed.

This accepts read-only package identity, not package staging, compatibility,
activation, native binary upgrade or A-to-B-to-A. Next: implement bounded
side-by-side staging with no implicit activation and preserved known-good
files, then verify actual reviewed payload transitions and rollback.
Hashes are consistency records, not signatures. FullG3/G4/V1, TLS restore,
permanent release, independent published replay and60-minute soak stay open.
Evidence: x10/evidence/g4-package-identity-hosted.json.


## Explicit side-by-side package staging candidate — 27 October 2026

The explicitly trusted extracted schema2 candidate now accepts stage with
exact source-runtime and raw-bundle-manifest pins. It checks disjoint private
roots, the complete package tree and all registered source sessions under an
identity-checked cooperative source lock. Only current confirmed HTTP input
is transferred; a different runtime payload is required. A fresh target stays
prepared and unbound, while every known source file is retained and rechecked.
Changed locks, unknown files and partial targets are preserved for inspection.
Native version/dependency/syntax checks can execute, but no serving daemon,
readiness check, user-unit activation or traffic switch is performed.

Frozen local Node24 selected pure/tempfile/virtual controls passed
374/374, including126 new staging controls once. Independent7 package-tree
and6 lock/reader heldouts are separate. A selected actual Node CLI test on a
NONEXECUTED synthetic native installation passed1/1 separately. Local physical
native/process-group/signal/systemd fixtures were not run. Draft cleanup,
preflight and hosted assertion issues were corrected before frozen validation.

Authored hosted evidence uses real earlier acb operator bytes and the same
compiled native binary; historical bundle reassembly is explicitly not a
published historical archive or native binary upgrade. Exact new hosted CI
must verify the actual stage result, payload bytes, preservation and cleanup.
Staging, state compatibility, activation and A-to-B-to-A remain separate gates.
No fullG3/G4/V1, TLS restore, permanent release, independent published replay,
60-minute soak or semantic Continuum acceptance is granted. Windows stays
deferred and unverified. Evidence: x10/evidence/g4-package-stage.json.


## Exact side-by-side package staging acceptance — 27 October 2026

Implementationad012446592488fe4bc33ff28a2f4189bb8c865a passed native
push40468943667/job122071147148 and PR40468947907/job122071164947:
34 actual successful steps,20 native groups and410 alpha tests each.
Both exact artifacts contain one36-field staging diagnostic and four refusals
without overwrite. The25-field stage result is asserted against actual bytes.
Historical acb operator code differs from the candidate; native binary is the
same. Source files and backup stayed unchanged, the fresh target remained
prepared/unbound, listeners stayed closed and owned installations were removed.
The historical bundle is an explicit checked reassembly, not a published archive.

Existing service regressions passed on this new CLI:18 restored proofs,
5 sessions,2 restarts,6 bounded journal checks,3 downstream and3 upstream TLS
sessions, all13 cleanup facts and unit/private-Node/bootstrap removal.
Service contract617PASS/1root-onlySKIP is explicit. Normal successful operation
did not exercise failure containment. Research PR actually ran21/7/27/48;
research push runtime skipped and inherited CLA failed.

This accepts staging without activation. The source A is prepared/unbound
in this proof, so no A-to-B-to-A traffic, reverse state compatibility or native
binary upgrade is accepted. Next: A serves P, B serves and confirms Q, then
the exact old A installer restores B-produced Q into fresh A2 and A2 serves Q.
Keep known-good A and application effects intact; verify every owned stop.
Foreground return and managed-service transition remain separate gates.
FullG3/G4/V1, TLS restore, permanent release, independent published replay,
60-minute soak and semantic Continuum stay open. Runtime is unchanged by
this receipt. Evidence: x10/evidence/g4-package-stage-hosted.json.


## Foreground operator return candidate — 27 October 2026

A new supported-host fixture exercises reviewed old operator A serving P,
current B staging and serving a newly confirmed HTTP input Q, then the exact
old installer restoring B-produced Q into fresh A2 and serving Q. The native
binary stays identical; historical operator reassembly is not a published
historical archive. Each leg requires explicit owned stop and TCP refusal
before the next launch. Known-good A files remain preserved throughout.
Three distinct completed synthetic in-memory POST receipts are retained
without replay/reset, and three bounded256KiB streams are compared exactly.
These are scoped observations, not database durability or release load budgets.

Frozen local Node24 selected pure/tempfile/virtual controls passed581/581,
including207 new proof controls once. Independent12 proof heldouts and4
virtual stream controls are separate; selected actual Node/NONEXECUTED native
installation passed1/1 separately. No physical native/process-group/signal/
systemd fixture ran locally. Only test harness/checker/evidence changed.
Actual foreground return acceptance awaits the new exact hosted CI artifact.
This does not accept managed-service package return, arbitrary state/journal
migration, native binary upgrade, TLS restore, permanent release, soak or V1.
Evidence: x10/evidence/g4-operator-return.json.


## TLS fixture connection selection candidate — 27 October 2026

Exact6401 push40475357966 passed34steps,20groups and617alpha plus
service regressions. PR40475365565 passed the617alpha return component
but FAILED step21: first HTTPS-upstream POST returned503 rather than200;
the origin received0POST requests. Cleanup passed, later PR trust/service
checks were not executed. The exact old-worker interleaving is unknown.
Both actual foreground return proofs and both ZIP digests are retained.

The fixture-only correction selects one actual verified downstream HTTP GET
connection and permits one POST/stream on that exact live reused socket.
Automatic replacement is disabled; no POST retry is permitted. It changes
no CLI, controller, native code, service recipe or package payload. Cold GET,
Agent free-pool timing, EOF and terminal error draining are checked explicitly.
Initial draft missing socket equality and late-error cleanup controls failed
before their corrections; those observations are not hidden by final PASS.

Frozen local Node24 pure/virtual controls passed639/639, including58 new
controls once. Separate synthetic readiness8/8 and independent virtual
security3/integration6 controls passed. No network/native/process-group/
signal/systemd fixture ran locally. Actual correction and overall return
acceptance remain pending exact new hosted CI; all-worker readiness,
managed-service package return, native binary upgrade and fullV1 stay open.
Evidence: x10/evidence/g3-tls-verified-route.json.


## Exact foreground operator return and verified-route acceptance — 27 October 2026

Implementation `ac2ae992d47907d82817cbd2dfb23480972c056a` passed native
push40480203383/job122108410221 and PR40480208863/job122108417175:
all34 actual steps,20 native groups and617 alpha tests per context. Each
HTTPS-upstream job passed76 TLS TAP tests, including58 virtual controls;
these counts are not76 TLS sessions. Both artifacts contain the14-field
verified-route diagnostic: the actual good GET, one65551-byte POST and one
65537-byte stream used the same checked downstream HTTP socket, with one
origin POST and no POST retry. The existing CA/hostname/plaintext refusal
controls and owned fixture cleanup passed.

Both exact events also contain the foreground operator A(P) → B(Q) → A2(Q)
proof:19 diagnostic fields,13 phases and3 traffic legs, with P!=Q=A2 checked
within each event. The exact old A installer consumed B-produced Q into fresh
A2, whose operator/runtime payload equals A and differs from B. The native
binary is identical throughout. Three distinct65551-byte completed synthetic
in-memory origin POST receipts and three256KiB streams were retained/compared
without replay or counter reset; these are not database durability or release
load-budget evidence. Known-good A files stayed unchanged and each owned
serving process/listener stopped before the next phase. The historical acb
operator bundle remains an explicit checked reassembly, not a published archive.

Existing restored-service regressions passed separately on the same runtime:
18 restored proofs,5 successful native sessions,2 manager restarts,6 bounded
journal checks, the existing three-session service TLS profile and complete
owned cleanup, including unit/private-Node/bootstrap removal. Six checks do
not imply exactly six journal queries. Normal cleanup success does not exercise
the full failure-containment matrix.

Accepted scope is foreground operator-package return, backward compatibility
of the declared HTTP backup/input and the verified-route TLS fixture only.
The historical6401 PR40475365565 step21 POST503/originPOST0 failure remains
preserved; its cause is unknown. The passing correction changes test routing
assumptions, not native/controller code, and does not prove all-worker readiness.
Managed-service package return, native binary upgrade/downgrade, TLS restore,
permanent release, independent published replay,60-minute soak, fullG3/G4/V1
and semantic Continuum remain open. Next: the separately verified managed-service
package-transition/recovery gate. Windows and G9 remain deferred/unchanged.
Evidence: x10/evidence/g4-operator-return-hosted.json.


## Managed operator-package return candidate — 27 October 2026

A separate nonroot systemd-user checker now exercises three private units:
A serves HTTP P, stops and retires; B stages from A, first serves P, applies Q,
serves Q and completes an actual manager restart; the exact old A installer
then restores B-produced Q into a fresh A2 that serves Q. Each unit retains
its own immutable prefix/binary/launcher context. Actual hosted acceptance
of this new scenario is pending; the accepted foreground receipt remains
separate at `ee2daa0385f654e96fd5b75c09da4e0179bb90a1`.

The expected new proof has 12 sections,16 phases,3 units,4 successful native
invocations,1 manager restart and5 bounded journal checks. These are separate
from the unchanged legacy18 restored proofs/5 sessions/2 restarts/6 journal
checks/3 downstream plus3 upstream TLS sessions. Journal checks are not exact
query counts. Four successful traffic-leg GET checks can each use up to8
idempotent route-acquisition attempts; the initial B/P GET is one separate
check. Each leg sends one unique65551-byte POST and one exact65537-byte stream
on its already verified downstream HTTP connection, without POST retry.
Synthetic POST effects remain in origin memory, not durable business storage.

The checker requires observed prepared null bindings for A/B/A2. B manager restart can bind before
external observation; its intermediate initial binding is explicitly null
meaning unobserved, while new actual session/revision/binding/invocation and
old process retirement are mandatory. Eleven stop/link/not-found facts gate
activation of the next unit. Known-good A files and backups remain preserved.

Checkout-owned system Node supplies exact reviewed historical CLI bytes as
a private0400 input outside the candidate bundle. Private Node never runs Git
or changes security configuration. Both source-pinned collectors and strict
success reports are now mandatory before private Node cleanup. The new report
is bounded12KiB and the combined envelope32KiB. Closed adverse reports remain
`ok:false`; unknown logs/proofs are not published and dependency cleanup refuses.

Frozen local Node24 pure/tempfile/virtual checks passed631/631, including529
new controls once. Separate review has3 historical-reader controls,8 workflow
tempfile controls and8 virtual report controls. YAML/inline Node syntax passed.
No physical native/process-group/signal/systemd/network fixtures ran locally.
The actual new managed package path therefore remains unaccepted pending exact
hosted push/PR jobs and `service-package-return.json`.

B remains the operator runtime introduced by `ad012…`; fixtures/docs do not
create another runtime version. A/A2 use reviewed historical CLI reassembly
with the same compiled NGINX binary. Native/library upgrade, TLS restore,
full recovery/security matrix, permanent release, independent published replay,
60-minute soak, fullG3/G4/V1 and semantic Continuum remain open. Historical
6401 POST503/origin0 failure with unknown cause, local cleanup FAIL_UNKNOWN,
CLA failure, owner window and deferred Windows plan remain unchanged.

Evidence: `x10/evidence/g4-managed-package-return.json`; ledger: `x10/review/g4-managed-package-return-ledger.json`.


## Managed-return immutable revision reader candidate — 27 October 2026

Exact implementation `c2adbea6c8d1e8b864291383445d35a0b27e875a` failed
both native contexts at step30: push40486053822/job122128117810 and
PR40486064789/job122128133176. Each new managed-return report stopped in
`install_a`, ended with `cleanup_unconfirmed` and contained no managed proof.
The original primary refusal was overwritten by the final cleanup code.
Private Node/history/bootstrap resources were retained; dependency-cleanup
artifacts and confirmed bootstrap removal are absent. This is a failed new
managed path, not successful cleanup or an accepted package transition.

The earlier components still passed in each event:20 native groups,617 alpha
tests,76 TLS TAP tests and the separate legacy service's18 restored proofs,
5 sessions,2 restarts,6 bounded journal checks and3 downstream/3 upstream TLS
sessions. Legacy owned-service cleanup does not establish cleanup of the new
failed collector or permission to remove its retained private Node.

A safe source-extracted counterexample reproduced a concrete reader mismatch:
the unchanged manager writes immutable revision records as0400, but the new
collector required0600. The exact baseline reader refused0400 while accepting
identical0600 bytes. The candidate requires0400 instead; it does not broaden
permissions or change the manager, installed CLI, native runtime or service
recipe. This reproduced contract defect does not establish the exclusive cause
of the historical CI failures, whose original primary error was not recorded.

The new strict report is schema2 with13 fields, adding finite `primaryFailure`.
Success requires null primary failure; an adverse report preserves its original
allowlisted code/phase even if later cleanup also fails. Valid failure reports
remain `ok:false` and never authorize dependency removal. The proof retains its
12 sections,16 phases and declared counts; source/proof pins must match across
workflow and cleanup consumer. Legacy e88ef source and workflow budgets/permissions
remain unchanged.

Frozen local Node24 pure/tempfile/virtual controls passed662/662 with no
fail/cancel/skip/TODO. The31 additional fix controls are included once:
18 proof,9 actual-reader and4 consumer controls. The separate3-control exact-c2
baseline is not added. An intermediate mixed-schema consumer run had11 failures
among118 controls; that adverse result stays separate from final verification.
YAML and inline Node syntax passed. No physical native/process-group/signal/
systemd/network fixture ran locally.

New exact hosted verification is pending; local pure checks cannot accept a
physical managed-service return. Full recovery/security gates,
native binary upgrade, TLS restore, permanent release, independent published
replay,60-minute soak, fullG3/G4/V1 and semantic Continuum remain open.
Evidence: x10/evidence/g4-managed-package-return.json.


## Exact managed HTTP operator-package return acceptance — 27 October 2026

Implementation `0ebded94ea331c1b28c52e71fa725dc35bb2f08a` passed both
native contexts: push40490525329/job122143117385 and
PR40490532178/job122143157669, all35 actual steps each. Both actual artifacts
contain schema2 reports with13 fields and `primaryFailure:null`, plus the
schema1 proof's12 sections and16 ordered phases. The managed path exercised
3 distinct owned units,4 invocations and1 actual B manager restart.

Each event verifies5 bounded journal CHECKS,4 successful traffic-leg GET
CHECKS plus1 separate initial B/P check,4 unretried65551-byte POSTs and4 exact
65537-byte streams. Route acquisition may use up to8 idempotent GET attempts
per leg; neither GET checks nor journal checks are exact raw request/query
counts. Synthetic POST effects remain in origin memory, not durable business
storage; these sizes do not satisfy the release upload/stream/load budgets.

Actual operator/runtime payloads satisfy A=A2!=B with one unchanged compiled
native binary; P!=Q=A2 holds within each event, with run-specific input hashes.
The old installer consumes B-produced Q into fresh A2. Eleven stop/link/not-found
facts gate transitions;12 restart freshness/retirement facts were confirmed.
The intermediate prepared binding during automatic B restart is explicitly
unobserved/null, while its actual fresh final binding/invocation is verified.
Known-good A files/backups stayed intact. All3 owned units/installations and
private Node/history/bootstrap resources were removed after both mandatory
source-pinned service reports succeeded. Historical A remains a checked CLI
reassembly, not an independently published historical archive.

Separate regressions passed in each context:20 native groups,617 alpha tests,
76 TLS TAP tests and legacy18 restored proofs/5 sessions/2 restarts/6 journal
checks/3 downstream+3 upstream TLS sessions. Research PR40490532200 actually
ran21/7/27/48; research push runtime skipped and inherited CLA failed.
Normal successful cleanup does not accept the complete failure-containment matrix.

Accepted scope is managed HTTP operator-package return and backward compatibility
of the declared HTTP input only. Earlier c2 step30 failures, masked primary
refusal, exact0400/0600 baseline and6401 POST503/cause-unknown history remain
preserved. No full package-failure/recovery/security, native binary upgrade,
TLS restore, permanent release, independent published replay,60-minute soak,
fullG3/G4/V1 or semantic Continuum acceptance follows.
Next: distinct B fails readiness after A was retired, with zero B POSTs,
verified failed-target quiescence and explicit retained-A reactivation. The
legacy refusal primitive already exists; this next gate covers the separate
cross-package fallback. Evidence: x10/evidence/g4-managed-package-return-hosted.json.


## Kept-A fallback candidate — 27 October 2026

The separate managed HTTP failure profile stages distinct operator B after A
has stopped, captures B while its owned readiness response is held, and
requires the exact failed hook before B retirement. Only after failed B is
quiescent and every retained A file/backup is checked does the operator
explicitly prepare and restart the SAME old A installation with fresh unit,
session, revision, invocation and binding, then verify P traffic without replay.
This fixture does not add automatic production fallback or change native code.

Fallback counts are separate:3 units,2 installations,2 successful invocations,
1 failed B attempt,0 restarts,2 successful journal CHECKS,2 traffic legs.
Normal3/4/1/5 and legacy18/5/2/6/TLS3 contracts stay unchanged. The private Node
consumer requires all three strict reports and source pins within32KiB before
dependency removal. Local physical fixtures were not run; exact hosted artifact
acceptance and fullG3/G4/V1 remain OPEN. Earlier c2/6401 failures and local
FAIL_UNKNOWN remain preserved. Evidence: x10/evidence/g4-kept-a-fallback.json.

The owner renewed work for40 hours from27Oct11:24:15UTC through
29Oct03:24:15UTC (29Oct07:24:15 Europe/Samara), then report/owned cleanup only
through04:24:15UTC. Previous20h/10h/60h/70h windows remain history. This does
not guarantee continuous processes or completion. Deferred Windows remains
UNVERIFIED after separately accepted LinuxV1, with no automatic queue change.


## Exact explicit KEPT-A fallback acceptance — 27 October 2026

Implementation7b32841d28a8b155b5783cef1a0c56337bb45a06 passed both native
contexts: push40497965654/job122168221801 and PR40497972686/job122168235728,
all36 actual steps each. ZIP digests and actual strict reports were checked.
Each fallback report is4653 artifact bytes with13 fields,13 proof sections,
13 phases and19 failed-B facts. The owned B fails the exact readiness hook,
has no binding or POST effects, and fully retires before explicit kept-A
preparation. The same old installation serves P with fresh unit/session/
revision/invocation/binding and unique unretried POST/stream, without replay.

Separate fallback counts are3 units,2 installs,2 successful invocations,
1 expected failed B attempt,0 restarts and2 bounded successful journal CHECKS.
Normal3/4/1/5 and legacy18 restored proofs/5sessions/2restarts/6journalCHECKS/
3downstream+3upstream TLS sessions remain verified separately. All owned
resources and private Node/history/bootstrap were removed after all3 strict
source-pinned reports succeeded. These CHECKS are not exact raw query counts.

Native20 groups,alpha617,TLS76,normal544/fallback545/Node138 TAP passed each;
legacy617passed/1root-onlyskip and official1105pass/25skip/1expectedTODO/
0unexpectedFAIL remain separate. Research PR actually ran21/7/27/48;
push research runtime skipped; CLA failed. New fixture success does not erase
c2/6401 failures or local FAIL_UNKNOWN, or establish a native binary upgrade.

Only the named explicit operator fallback is accepted. Same-UID trust,
unsigned pins and checked historical CLI reassembly limits remain. The next
operator gap is a reviewed faulted/orphan incident runbook using existing
strict refusals and confirmed backups, not automatic reaping or lifecycle
editing. Release-record step completeness/cap also needs reconciliation.
Permanent release, independent published replay,60minsoak, full recovery/
security, TLS restore,fullG3/G4/V1 and semantic Continuum remain OPEN.
Evidence: x10/evidence/g4-kept-a-fallback-hosted.json.


## Reviewed faulted/orphan incident procedure — 27 October 2026

The [incident runbook](service/INCIDENT-RUNBOOK.md) now gives the trusted
nonroot operator concrete bounded observations, STOP_UNRESOLVED outcomes and
a conditional fresh HTTP restore from a preexisting confirmed backup.
The old potentially live prefix stays IN PLACE; no command clears faulted
lifecycle or permits its forced uninstall. Unknown identity/resources/ports/
locks stop the procedure. Original X10 listeners must be safe; a separately
owned compatible upstream may remain running. Restore preserves declared
ports/input and does not repair the old installation or replay side effects.

Independent final review checked14 CLI command specifications,9 Bash blocks
for syntax only,15 relative links,26 security boundaries and13 desk cases.
These are source/document reviews, not TAP or actual incidents. Corrections
cover restore result versus separately checked installationId, diagnostic
status-write errors, absent/safe output files, clean local manager endpoint
and explicit queued-job observation. Runtime and workflow bytes are unchanged.
No runbook command or physical native/network/systemd/signal fixture ran here.

The preceding receipt F native push40501089044/job122178775321 and
PR40501096395/job122178756176 each completed36 successful actual steps;
research PR40501096469/job122178757773 completed11. Research push runtime
skipped; CLA40501093063/job122178662944 failed step3. No new artifacts were
downloaded or unchanged manual reruns requested, and no guessed merge/build
checkout or research counts are attributed to this read. The accepted actual
fallback remains exact7b32841d28a8b155b5783cef1a0c56337bb45a06.

Next: fix the release-record32-step cap and missing current-step completeness
against the full ordered36-step native receipt, with a finite64 bound and
independent pure refusal controls. Never truncate receipts or treat declared
JSON as authenticated runtime evidence. Actual orphan incident replay and
old-prefix disposal, full recovery/security, native binary upgrade, TLS restore,
permanent release, published replay,60-minute soak, fullG3/G4/G5/V1 and semantic
Continuum remain OPEN. Existing adverse histories, owner40h policy and deferred
Windows are preserved. Evidence: x10/evidence/g4-incident-runbook.json.
