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
