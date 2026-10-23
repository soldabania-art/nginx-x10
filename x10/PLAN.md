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

Первый C patch и native baseline дополнены локальным контроллером ревизий, единым проверяющим runner, шестью генерируемыми свойствами QUIC под ASan/UBSan, 19 feature-cases и закреплённой выборкой из 35 официальных test files. Отдельный benchmark driver проверяет сопоставимость сборок и сохраняет сырые результаты. Точные успешные проверки, пропуски и ограничения находятся в [STATUS](STATUS.md); это не закрывает всю матрицу выше.

Ближайшие работы после этого checkpoint:

1. Следовать [разобранным native handover contracts](review/handover-boundaries.md): перед подтверждением полного cutover доказать закрытие старых listening sockets, сохранив завершение старых потоков. Сейчас контроллер подтверждает наблюдаемое новое поколение и health, а кандидат уже может обслуживать трафик во время проверки.
2. После укрепления recorded event intent/history/state recovery расширять crash/storage-failure matrix. Известный разрыв между history append и state replacement закрывается только при точном валидном intent и подтверждённом runtime; старое несогласованное состояние без intent, partial records и противоречия остаются для ручной проверки.
3. Расширять уже добавленные FastCGI/SCGI/uWSGI и mail TLS/STARTTLS fixtures: дополнительные framing/state/error ветки, многопоточность и TLS-library matrix. Добавить HTTP3/QUIC interoperability и матрицу ОС. Полный upstream suite и длительный fuzzing остаются отдельными работами; self-contained fixtures не отменяют upstream dependency skips.
4. Добавлять более широкие workloads и искать измеренные bottlenecks. Текущий короткий HTTP1 benchmark не доказывает ускорение QUIC patch или масштабирование нескольких workers.
5. После укрепления локального управления добавить удалённый API с TLS/RBAC/audit и подключение консоли; проверить размещение native-процесса, обновление и откат в выбранной инфраструктуре проекта.
