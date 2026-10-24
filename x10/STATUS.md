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
