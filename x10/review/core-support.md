# NGINX: DNS, адреса, строки и регулярные выражения

Снимок `148c75678cd4171338c31d4ed4c02411736d5fe9`, NGINX `1.31.9`. Полностью прочитаны все восемь выделенных файлов, 9 839 строк; диапазоны — в `core-support-coverage.json`. Сборки и runtime-проверки не выполнялись.

## Зафиксированные наблюдения

- `src/core/ngx_inet.c:ngx_parse_url()` разделяет Unix-domain, bracketed IPv6 и IPv4/hostname forms; учитывает listen, URI, no_resolve, wildcard/default ports и диапазоны портов. Явные порты проверяются на 1..65535. `ngx_ptocidr()` ограничивает prefix32/128 и возвращает NGX_DONE, если пришлось очистить host bits. IPv4-mapped IPv6 учитываются в CIDR match. Это специализированные внутренние parsers, а не универсальная browser URL library.
- `ngx_inet_resolve_host()` — синхронный getaddrinfo/gethostbyname path; его нельзя смешивать с асинхронным `ngx_resolver.c`. `no_resolve` оставляет hostname для более позднего решения. Formatting и parse имеют собственные size/lifetime contracts; ngx_str_t не обещает trailing NUL.
- `src/core/ngx_string.c`: `ngx_atoi/atosz/atoof/atotm` перед умножением проверяют cutoff/cutlim для соответствующего типа; пустая/нечисловая/переполняющая строка возвращает NGX_ERROR. ASCII comparisons намеренно избегают locale. `ngx_snprintf/slprintf` ограничены last/max, возвращают end pointer и не добавляют NUL автоматически; `ngx_sprintf` предполагает достаточный buffer.
- URI/args/component/mail-xtext имеют разные escaping tables; HTML и JSON — отдельные функции. Двухпроходный контракт сначала считает расширение (`dst==NULL`), затем пишет в заранее выделенный buffer; writer сам не получает capacity. Base64 size macros также полагаются на ограниченную входную длину у caller. Такие primitives нельзя считать общими валидаторами недоверенных строк без анализа вызывающего кода.
- `src/core/ngx_regex.c:ngx_regex_compile()` поддерживает PCRE1/PCRE2 и строго принимает только caseless/multiline options; получает число и таблицу именованных captures. PCRE2 pattern передаётся с length; PCRE1 compile использует NUL-terminated pattern.
- Compiled patterns используют переданный `rc->pool` (при разборе config — cycle pool); PCRE2 compile context и match data кешируются с heap allocation. Runtime matching выделяет backtracking frames из heap; match data растёт при нужде. JIT выключен по умолчанию и проверяется в linked library; studies выполняются при module init, не при runtime compile. Отказ JIT конкретного pattern логируется, основной regex остаётся. Cleanup явно освобождает executable JIT memory и сбрасывает глобальные contexts, включая неудачный разбор config. Глобальные allocator/match-data pointers означают, что перенос этого кода в многопоточный движок требует отдельного ownership/concurrency design.

## Асинхронный DNS: состояния и время жизни

`src/core/ngx_resolver.c:ngx_resolver_create()` создаёт отдельные red-black trees для hostnames, SRV и reverse IPv4/IPv6; рядом находятся очереди повторной отправки и освобождения cache nodes. Это встроенный event-driven DNS client для A/AAAA, CNAME, PTR и SRV. Если временный контекст уже содержит IPv4 literal, `ngx_resolve_start()` использует быстрый синхронный callback. IPv4 и IPv6 queries имеют отдельные IDs и состояния; совпадающие запросы на один name объединяются списком `rn->waiting`.

| Механизм | Прочитанный контракт |
| --- | --- |
| `valid` | Срок допустимости ответа. Для A/AAAA/SRV используется минимум TTL просмотренных records; отрицательный signed TTL обнуляется. `valid=` переопределяет срок. PTR использует TTL выбранной PTR record. |
| `expire` | Отдельный срок хранения node; по умолчанию 30 секунд после использования. Это не DNS TTL. `ngx_resolver_expire()` освобождает не более двух старых nodes за вызов. |
| `resend_timeout` | 5 секунд по умолчанию, повторная отправка к следующему DNS peer round-robin, без exponential backoff в этом коде. При первоначальной send failure есть одна немедленная попытка следующего peer. |
| `ctx->timeout` | Индивидуальный event timer. Его callback сообщает TIMEDOUT; caller завершает и отсоединяет контекст через `ngx_resolve_*_done()`. При timeout 0 личный timer не создаётся. |
| DNS errors | Ошибочный node удаляется; callbacks получают error и `ctx->valid` на `valid=` либо 10 секунд. Это не долгоживущий отрицательный cache node в resolver tree. |

`ngx_resolver_udp_read()` использует неблокирующий connected UDP socket. Для truncated A/AAAA и SRV ответов обработчики переводят соответствующий query на TCP; TCP использует двухбайтовую length prefix, отдельные read/write buffers и write timeout. Parser проверяет стандартный response, число questions, class/type, идентификатор и состояние ожидаемого query. `ngx_resolver_copy()` проверяет границы compression pointers и ограничивает обход 128 итерациями, чтобы не зациклиться. CNAME chains ограничены `NGX_RESOLVER_MAX_RECURSION=50`. Это наблюдение исходных проверок, а не выполненный fuzz/security test.

SRV сначала кеширует записи по priority, затем запускает дочернее разрешение target names. Общая valid date ограничивается также target validity; port переносится в resulting sockaddr. Итоговые адреса группируются по priority, старт внутри группы выбирается с учётом weight и числа адресов. Source implementation нормализует нулевой weight к 1. При cache export возможна ротация адресов.

Важен контракт владения: часть arrays/names существует только во время callback и освобождается сразу после него; SRV handler копирует target sockaddr перед `ngx_resolve_name_done()`. Отмена удаляет waiting context и его timer, а не обязательно немедленно уничтожает общий query других consumers. Cleanup cycle закрывает resolver connections, удаляет timers и освобождает trees. Комментарии `lock ... mutex` в этом файле не являются реализованной синхронизацией; перенос в общий многопоточный cache требует отдельной защиты и определения владения.

## Выводы для ENGINE X10

DNS улучшения должны сохранять дедупликацию in-flight queries, различие TTL/retention/request timeout, TCP fallback, service records и предсказуемый callback lifetime. Разрешение hostname при parse config и запрос DNS в worker runtime — разные операции; блокирующий lookup нельзя незаметно внести в event loop. Для нового движка полезны явные budgets на pending DNS, память cache и recursion; фактические лимиты и поведение нужно проверять отдельно, а не считать отсутствие найденной настройки доказательством отсутствия защиты.

Строковые primitives надо выбирать по контексту: URI escaping не заменяет JSON escaping, length-bearing string не заменяет C-string, числовая overflow check не делает безопасным последующее вычисление allocation size. Regex JIT и pool cleanup необходимо сравнивать при одинаковых PCRE versions/options. Эти выводы формируют задачи проверки и не подтверждают ускорение ENGINE X10 либо дефект NGINX.
