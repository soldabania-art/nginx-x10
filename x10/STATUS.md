# NGINX X10: проверенное состояние

Состояние на **23 октября 2026 года**: полный native fork NGINX дополнен локальным контроллером конфигурации, закреплённой официальной выборкой тестов, проверками дополнительных функций и генерируемыми QUIC-свойствами под санитайзерами. Единый проверочный прогон завершился **7/7 успешных групп**. Это development-кандидат; performance acceptance и готовность к production остаются открытыми.

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

Кандидат уже может обслуживать трафик во время health gate. Native handover допускает краткое обслуживание старым поколением после наблюдения нового; это не мгновенный общий cutover. Rollback не отменяет выполненные запросы. Разрыв между history append и state replacement может потребовать ручной проверки; автоматическое восстановление произвольного повреждённого журнала не заявляется.

## Производительность: измеритель и открытый результат

[Driver](bench/README.md) проверяет одинаковые build profiles, SHA-256 и `-V`, точные 1024-byte ответы, ошибки, cleanup, AB/BA порядок, latency и Linux CPU/RSS. [Проверки самого driver](evidence/benchmark-verification.json) включают несовместимый профиль, SIGTERM и подмену manifest.

Сырые результаты сохранены без удаления неблагоприятных данных:

- [Первый A/B](evidence/benchmark-local.json): 16 samples, 0 request errors; candidate/baseline throughput для static C16 — **0,484**.
- [Одинаковый baseline под двумя метками](evidence/benchmark-identical-control.json): static C16 — **0,684**, proxy C16 — **1,623**, хотя SHA обоих бинарников одинаков.
- [Повтор A/B с четырьмя повторами по 2 секунды](evidence/benchmark-confirmation.json): static C16 — **0,826**, proxy C16 — **0,804**. Сам baseline изменялся от 812 до 12607 req/s между samples.

Эти контроли показывают существенную нестабильность измерения. Причина первого неблагоприятного результата не установлена; регрессия не исключена. Отношения не доказывают эффект C patch, который не исполняется в этих HTTP1 workloads. Node clients/upstream и общий хост ограничивают интерпретацию; наблюдение cgroup сохранено [отдельно](evidence/benchmark-observer.json). Ускорение и отсутствие регрессий не установлены. Для performance acceptance нужен более стабильный генератор/хост и дополнительные воспроизводимые workloads.

[Независимый review](review/milestone-2-review.md) перечисляет исправленные замечания и оставшиеся ограничения. Workflow [x10-native.yml](../.github/workflows/x10-native.yml) подготовлен с read-only permissions и закреплёнными actions; локальные результаты сами по себе не означают hosted CI PASS.

## Оставшиеся границы

- HTTP/3 и QUIC end-to-end, сетевые потери/миграция, полная TLS-library matrix и 32-битные сборки не проверены. Компиляция HTTP/3 с OpenSSL compatibility path этого не заменяет.
- Mail TLS/STARTTLS, upstream HTTP/2/multiplexing, полный набор protocol adapters, optional modules, ОС и аварийных веток ещё требуют отдельных тестов. Проверка отказа reload охватывает синтаксис, а не все поздние side effects и ошибки инициализации.
- Полная официальная suite, длительный fuzzing, полноценная crash matrix и стабильная performance matrix ещё не выполнены. Генерируемые свойства и короткие loopback measurements не заменяют эти работы; преимущество «10x» не установлено.
- Публичный native gateway не развёрнут. Ранее размещённая на Vercel консоль относится к Node-прототипу; она не запускает и не подтверждает доступность native NGINX X10.

Следующие шаги и обязательства совместимости: [PLAN](PLAN.md). Команды сборки и локальных проверок: [README](README.md) и [BUILD](BUILD.md). Принимать следующие изменения следует по отдельным воспроизводимым baseline/candidate доказательствам.
