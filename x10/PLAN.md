# План развития ENGINE X10 на базе NGINX

Решение владельца от 22 октября 2026 года: взять NGINX за основу, сохранить всё существующее и улучшать каждую область. Полный исходный NGINX Open Source остаётся в дереве. Коммерческие и сторонние продукты не считаются автоматически включёнными или проверенными.

## Обязательные условия

1. Не сокращать совместимость ради удобства панели. Полный native nginx.conf остаётся допустимым; управляемые X10 fragments отделяются от конфигурации оператора.
2. Сохранять native event model, memory pools, buffer ownership, request/subrequest lifetime, multiworker shared state, reload generations и platform abstractions.
3. Сначала воспроизвести недостаток на закреплённой исходной версии. Затем сделать небольшой patch и проверить исправление, допустимые входы и соседние сценарии.
4. Сравнивать одинаковые версии зависимостей, configure flags, оборудование и нагрузку. Записывать ошибки, throughput, p50/p95/p99, CPU, RSS и особенности потоков.
5. При ухудшении другого существенного показателя явно записать компромисс. Выигрыш в одном сценарии не распространять на весь NGINX.
6. Не делать обязательным LLM, облако или консоль для прохождения обычного запроса. Управление и наблюдаемость отделять от сетевого hot path.
7. Сохранять upstream sync и обновления исправлений. Держать изменения reviewable, не переименовывать все C symbols ради бренда.

## Матрица работ

Ни одна строка ниже не означает уже полученное преимущество. Это обязательства по сохранению и направления экспериментов.

| Область | Сохраняем | Улучшение для проверки | Доказательство |
| --- | --- | --- | --- |
| Процессы и reload | Master/workers, old/new generations, inherited sockets | Понятная проверка, применение и восстановление конфигурации | Незавершённые запросы, ошибки parse/init/resource, новый worker, отсутствие ложного ACID обещания |
| Events и ОС | epoll/kqueue/poll/select, posted events, timers, partial I/O | Диагностика event-loop stalls и исчерпания ресурсов | Linux/BSD/Windows matrix, slow clients, FD reuse, p99 и CPU |
| Память и буферы | Pools/slabs, shadow chains, recycled buffers, direct I/O | Измеряемые границы памяти и объяснение pressure | RSS, allocation counts, backpressure, abort/AIO cleanup |
| HTTP/1 | Parsing, body framing, keepalive, chunking, CONNECT | Дополнительные regression/fuzz tests и точные ошибки | CL/TE, split input, smuggling regressions, ранние ответы |
| HTTP/2 и HTTP/3 | Stream state, HPACK/QPACK, flow control, reset/drain | Interop, устойчивость к malformed inputs и диагностика | Нативные клиенты, stream cancellation, limits, differential wire cases |
| QUIC/TLS | Handshake/session/key lifetime, congestion/loss/migration | Малые исправления по воспроизводимым контрпримерам | Parser regression, interop, TLS validation, сетевые потери; не одна компиляция |
| Upstream | RR/weights/hash/random/least_conn/least_time/sticky, zones и DNS | Прозрачное состояние peers, drain, health policy | max_conns/fails, DNS generation/refcount, distribution, topology changes |
| Проксирование | HTTP1/2 upstream, streaming, retries, trailers и upgrade | Безопасная настройка и профиль для конкретных приложений | POST replay, buffering, early response, disconnect, HTTP2 reuse |
| Кэш | Cache keys, Vary, locks, stale/revalidation, manager/loader | Объяснение hit/miss и настройка без утечек | Stampede, персональные ответы, disk full, purge policy, cache-key fixtures |
| FastCGI/SCGI/uWSGI/gRPC/memcached | Все adapters и их framing/ownership | Наблюдаемость и protocol-specific hardening | Настоящие fixtures каждого протокола, truncation и retries |
| Static/media/filters | sendfile, ranges, gzip, charset, SSI, MP4, image, XSLT | Подсказки по cost и opt-in оптимизации | Файлы/диапазоны/encoding, optional dependencies, byte-equivalent results |
| Rewrite/routing | Locations, regex, maps, geo, variables, internal redirects | Объяснение выбранного маршрута и валидация | Precedence, captures, phase reentry, subrequests, limits циклов |
| Доступ и ограничения | Native auth/access/realip, limit_req/limit_conn zones | Безопасный мастер настройки и измеримые policies | Multiworker accounting, trusted proxies, dry-run, expiry/cleanup |
| TCP/UDP | Stream routing, proxy protocol, half-close, TLS preread | Удобное управление без HTTP-предположений | Binary payload, datagrams, session lifetime, timeout и half-close |
| Почта | SMTP/IMAP/POP3, STARTTLS, auth_http и login handshake | Диагностика авторизации и предсказуемые отказы | Протокольные fixtures, denies/successes, tunnel, TLS/STARTTLS matrix |
| DNS и файлы | Native resolver TTL/retention/retry, open-file cache | Наблюдаемость причин отказов и состояния | DNS UDP/TCP/SRV/CNAME, changing records, inode/symlink races |
| Управление | nginx -t/-T, сигналы, optional native control API | Ограниченный локальный agent с защищённым удалённым API | Доступ к socket, секреты config dump, roles/audit, concurrent revisions |
| Сборка и модули | Configure probes, module order, version/ABI guards | Профили и manifest, диагностируемые несовместимости | Compiler/dependency matrix, dynamic modules, reproducible inputs |

## Порядок реализации

1. **Основа:** fork, upstream pin, чтение кода и регистр возможностей; baseline build и native regression fixtures. Первый parser patch проверяется отдельно.
2. **Совместимость:** добавить официальный nginx-tests с закреплённой ревизией, protocol clients и CI matrix. Не отмечать optional modules или HTTP3 как runtime-checked по наличию в бинарнике.
3. **Эксплуатация:** управляемые configuration fragments, native -t, revisions, ограниченное применение и health gate. Сначала loopback/Unix socket; TLS/RBAC/audit для удалённого доступа. Учитывать возможные ранние side effects native reload.
4. **Наблюдаемость:** понятные причины route/cache/limit/peer decisions и bounded metrics. Измерять влияние сбора на hot path.
5. **Производительность:** выбрать воспроизводимые workloads и сравнить native upstream и X10. Оптимизировать подтверждённые bottlenecks по одному.
6. **Расширение:** закрывать матрицу каждой области тестами и измерениями, переносить доказанные улучшения в stable line с обновлениями upstream.

## Выпуск

Development branch не является промышленным релизом. Для выпуска нужны соответствующие тесты, матрица сборок, сценарий обновления/отката, запись отличий и известных ограничений. Публичный хост NGINX X10 ещё не развёрнут. Vercel может размещать консоль, но не подменяет постоянно работающий native процесс.

## Реализовано к 23 октября 2026 года

Первый C patch и native baseline дополнены локальным контроллером ревизий с durable intent и storage-failure recovery, ручной captured-process listener диагностикой, native generation/birth API, generated QUIC parameter/frame checks под ASan/UBSan, реальным HTTP/3 interop и независимым HEAD client, mail TLS и FastCGI/SCGI/uWSGI fixtures, 19 feature-cases и закреплённой выборкой из 35 официальных test files. Добавлены изолированная Linux alpha, `status --human`, read-only `inspect-generations` с привязкой endpoint к master и упаковка из подтверждённого build manifest. Текущий runner настроен на 19 обычных / 20 `--official` групп; финальный локальный [milestone-7](evidence/native-checks-milestone-7.json) прошёл 20/20, без новых изменений C и с прежним native binary SHA. Предыдущий milestone-6 прошёл 18/18. Новый benchmark driver использует C client и pristine native origin, проверяет сопоставимость сборок и сохраняет сырые результаты. Точные успешные проверки, пропуски и ограничения находятся в [STATUS](STATUS.md); это не закрывает всю матрицу выше.

Ближайшие работы после этого checkpoint:

1. Следовать [native generation design](review/handover-generation-design.md): ручной observer теперь проверяет закрытие listeners только у captured processes, а live fixture разделяет новые ответы, listener closure и старые потоки. Добавлены native master generation и process birth identities с HUP/PATCH/respawn/slot checks. Полный listener-close ACK/fence и реальный binary upgrade остаются отдельными проверками. Apply пока подтверждает наблюдаемое новое поколение и health; кандидат уже может обслуживать трафик во время проверки.
2. Расширять уже проверенные initialization SIGKILL и storage-failure boundaries: filesystem/power-loss поведение, дополнительные отказы и операционное восстановление. Intent/history/state recovery действует только при точном валидном intent и подтверждённом runtime; старое несогласованное состояние без intent, partial records и противоречия остаются для ручной проверки.
3. Расширять FastCGI/SCGI/uWSGI и mail TLS/STARTTLS fixtures: дополнительные framing/state/error ветки, многопоточность и TLS-library matrix. После семи aioquic и четырёх независимых libcurl cases добавить raw-wire HEAD проверки, loss/migration, browser/client matrix и connection-state проверки ACK/flow/final size. Добавить 32-bit и другие ОС. Полный upstream suite и длительный fuzzing остаются отдельными работами; self-contained fixtures не отменяют upstream dependency skips.
4. Добавлять более широкие workloads, выделенный стабильный host и искать измеренные bottlenecks. Новый C client/native-origin HTTP1 benchmark пока не доказывает ускорение QUIC patch, отсутствие регрессий или масштабирование нескольких workers. Сохранять прежние неблагоприятные Node measurements рядом с новыми.
5. После укрепления локального управления добавить удалённый API с TLS/RBAC/audit и подключение консоли; проверить размещение native-процесса, обновление и откат в выбранной инфраструктуре проекта.

Сводный продуктовый порядок и критерии alpha/beta/release: [ROADMAP](ROADMAP.md).
Операторский путь локальной alpha реализован и описан в [QUICKSTART](QUICKSTART.md).
Локальный aggregate и lifecycle пакета прошли; [независимый review](review/local-alpha-review.md)
проверил 9 operator и 8 package controls. Следующая приёмка — отдельные
обязательные hosted Unix gates; затем нужны установка на чистой совместимой
машине, сценарий обновления и дополнительные отказы хранения/процессов.
Foreground alpha с отдельными историями сессий пока не является системным
service или переносимой промышленной поставкой. Стабильный performance стенд
остаётся отдельной работой.

Новый [R&D-план Guard](review/guard-research.md) исследует поиск контрпримеров
и проверку исправлений конфигурации. Его первый tenant/cache kernel работает
на заданных synthetic сценариях. LLM и сравнение на held-out конфигурациях
остаются следующими этапами. Сам kernel служит инструментом экспериментов;
это не утверждение о технологической новизне или AI discovery.

Для отдельного [cache dependency compiler](review/cache-dependency-research.md)
сначала нужны закрытая семантика response IR, независимый checker, правила
auth/version failures и корректный baseline. Реализация и её экономический
эффект пока не установлены.

## Новый исследовательский приоритет: Continuum

Решение владельца от 23 октября 2026 года: сохранить в Git концепцию, экономику
и порядок самостоятельной разработки, подключать помощников и возобновлять
работу периодически. Следуем [Continuum PLAN](continuum/PLAN.md): независимые
record vectors и ограниченный IR/checker, реальный same-connection process
fixture, затем handshake interoperability, OpenSSL state bridge и native
NGINX integration. Полный исходный NGINX и прежние отрицательные результаты
сохраняются. Cache/Guard эксперименты остаются вспомогательными и не считаются
новым изобретением по одному наличию реализации.

Денежная цель первого этапа — использовать имеющиеся ресурсы; резерв $100
является плановым ограничением, а не гарантией стоимости завершения или
поручением автоматически покупать услуги. Коммерческий масштаб и затраты
на поддержку рассматриваются отдельно в [ECONOMICS](continuum/ECONOMICS.md).

Срез C1 добавил настоящий authenticated TLS 1.3 handshake и bounded wire
observer: локально 22/22, независимо проверены отрицательные wire/trust и
прерывание с живым TLS. [Evidence](evidence/continuum-c1.json) сохраняет
контрпримеры, source hashes и границы проверки. Это двухсоединительный relay,
а не миграция. C0 и полный native aggregate повторены без изменения native
бинарника. Следующий C2 начинается с read-only state inventory/safepoint в
[закреплённом OpenSSL](continuum/OPENSSL-STATE.md); реальный semantic
export/import и native integration остаются отдельными работами.

Первый C2a observation profile реализован и локально проверен: **8/8** real
TLS cases на изолированном pinned OpenSSL 3.0.13, metadata-only key-install
monitor, private buffers/sequences и typed retry ledger. [C2a profile](continuum/C2A-PROFILE.md)
отделяет narrow `allowed` от полной safepoint/transfer приёмки. Полный native
aggregate повторён: 20/20; прежний binary SHA, upstream и LICENSE сохранены.
Research push/PR exact C2a SHA `99a017e` прошли; native и format-policy
результаты учитываются отдельно в [checkpoint](continuum/C2A-CHECKPOINT.md).
Далее закрыть peer/read KeyUpdate,
retry/control/shutdown inventory и runtime cancellation. C2b semantic capsule
не начинается с предположения о полноте одного положительного probe.

Текущий bounded срез добавляет реальные `completed-read-retry` и
`unrelated-write-read-retry`: завершение исходного READ до echo и сохранение
его retry при постороннем WRITE success. [Retry evidence](evidence/continuum-c2a-retry.json)
отделяет coverage baseline, 10-case aggregate, независимые held-out cases,
диагностические controls и первый отказ build hook. Далее — peer/read
KeyUpdate, завершение write retry и остальные control/shutdown/limit obligations.
Экспорт/import и opt-in native integration требуют своих последующих gates.

Continuum дополнен отдельным handled-runtime interruption стендом: локальные
13 checks отделяют10 обычных TLS cases,2 signals после настоящего READ и1
no-TLS cached-source control. [Evidence](evidence/continuum-c2a-interruption.json)
сохраняет независимые отказы при PKI debris и занятом relay listener, а также
исходные ошибки самого стенда. Native C сохранён, свежая регрессия20/20.
Приёмка exact hosted SHA ожидается; далее actual peer/read KeyUpdate inventory.

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


## Continuum: защита памяти при отказах

Source-only capture теперь повторяет уничтожение FAILED mapping без
восстановления authority и не снимает lock с неочищенных copied bytes.
[Контракт](continuum/SOURCE-CAPTURE.md) и
[проверки](evidence/continuum-capture-protection.json)
отделяют synthetic production-TU fault controls от настоящих TLS exchanges.
Локально C2a44,18 synthetic fault cases, independent2 actualTLS и native20
прошли; неблагоприятные попытки сохранены, exact hosted CI нового кода pending.
Semantic/API inventory остаётся следующим gate,
не разрешением на importer, ownership transfer или migration.


## Continuum: read-only established API metadata

Реализован bounded `inspect-api` на прежнем held source: ALPN, Finished lengths,
no-client-auth class и session observations без копирования значений/секретов.
Локально C2a48, core21/process7/C1 27 и native20 прошли. Прежний `ad5351f4`
проверен exact hosted; новый metadata код ожидает собственного CI.
[Контракт и проверки](evidence/continuum-api-inventory.json) не закрывают
value-preserving semantic capsule/import/ownership/retirement gates.
Следом — reviewed fuller protected source-state contract с actual required
ALPN/Finished/auth-class semantics, явно unsupported API и future-control
границами, до любого target I/O.


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
