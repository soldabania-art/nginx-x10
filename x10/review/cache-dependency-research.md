# Cache dependency compiler: исследовательский кандидат

Статус: техническая гипотеза, без реализации и измерений. Guard остаётся
вспомогательным проверяющим инструментом, а не технологией cache compiler.

## Кандидат на разработку

Компилятор ограниченного response/policy языка выводит достаточную проекцию
входов для повторного использования ответа. Независимый маленький checker
проверяет certificate полноты зависимостей. NGINX использует эту проекцию для
cache partition, но отдельно проверяет текущую авторизацию каждого запроса.
Неизвестная семантика означает BYPASS; известный запрет доступа означает DENY.
Это разные исходы: bypass не должен обходить обязательную авторизацию.

Предполагаемый выигрыш: разделять одинаковый ответ между допущенными
пользователями без ручного перечисления cache-key inputs, сохраняя изоляцию
при изменении данных, прав и конфигурации. Генерация ключей, labels и проверка
auth перед HIT по отдельности уже известны. Исследуемый вклад — проверяемая
компиляция двух отдельных обязательств reuse и access для заданной семантики.
Её новизна и практическое преимущество пока не установлены.

## Ближайшие первичные источники

| Источник | Что уже известно | Граница нашего вывода |
| --- | --- | --- |
| [RFC 9111 §§3.5, 4.1, 7.2–7.3](https://www.rfc-editor.org/rfc/rfc9111.html) | `Vary` задаёт дополнительные условия повторного использования; authenticated responses имеют ограничения shared caching; cache timing и sensitive headers создают риски. | Dependency certificate не отменяет HTTP caching semantics и не является новым именем `Vary`. |
| [Cloudflare cache keys](https://developers.cloudflare.com/cache/how-to/cache-keys/) | Настраиваемые query/header/cookie/host/user dimensions, включая язык; согласование URL normalization с origin. | Добавить tenant/cookie/language в ключ — существующий механизм, не изобретение. |
| [Cloudflare WAF before cache](https://developers.cloudflare.com/cache/interaction-cloudflare-products/waf-snippets/), [NGINX auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html) | Проверки доступа до cache и authorization subrequests уже доступны. | Current authorization gate сам по себе не нов. Нельзя заменять current policy проверкой устаревшего session label. |
| [Fastly surrogate keys](https://www.fastly.com/documentation/guides/full-site-delivery/purging/purging-with-surrogate-keys/) | Ответы помечаются ключами для группового selective purge. | Invalidation tag не доказывает полноту всех зависимостей ответа. |
| [Sqlcache, POPL 2017](https://adam.chlipala.net/papers/SqlcachePOPL17/) | Compiler optimization автоматически добавляет sound SQL caching для Ur/Web, сохраняя transactional semantics. | «Компилятор сам выводит зависимости cache» уже имеет прямой prior art. Здесь анализируется закрытый DSL, а не opaque HTTP origin. |
| [TxCache, OSDI 2010, §2.1](https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Ports.pdf) | Automatic database dependency tracking/invalidation и consistent snapshots для cacheable functions. Нужны pure deterministic functions, зависящие только от аргументов и DB; реализация доверяет программисту. | Требуется явно определить доверенную основу полноты и источник актуальных revisions. |
| [MultiverseDB, MIT 2018](https://pdos.csail.mit.edu/papers/multiversedb:larat-meng.pdf) | Security policies формируют пользовательские views; computation/views могут разделяться между security groups. | Reuse между совместимыми правами уже известен; lifecycle policy/membership изменений требует собственного протокола. |
| [Hails, авторская версия](https://cseweb.ucsd.edu/~dstefan/cse291-winter18/papers/hails.pdf) | IFC labels и mandatory enforcement защищают данные через trusted runtime. Авторы отделяют модель noninterference от полной реализации. | Нельзя заявлять IFC-гарантию, просто добавив недоверенный HTTP label. Это framework, не подтверждённый нами готовый NGINX cache compiler. |

Это не исчерпывающий patent/novelty search. Источники не доказывают отсутствие
у существующих систем всей предлагаемой комбинации.

## Маленькая модель, которую действительно можно проверять

Пусть `p` — total pure программа поддержанного IR, `x` — запрос, trusted
identity/context и неизменяемый data snapshot. `O(p,x)` — наблюдаемый результат:
status, body, все end-to-end headers/trailers, cookies и внешние effects.
Компилятор предлагает проекцию `D` и certificate следующего обязательства:

```text
forall x,y in SupportedDomain(p):
    project(D,x) == project(D,y)  =>  O(p,x) == O(p,y)
    effects(p,x) == []
```

Это достаточная, не обязательно минимальная проекция. Условия ветвления,
выбор record/query и отсутствие результата тоже создают dependencies.
Сначала разрешён консервативный union зависимостей всех ветвей; удаление
избыточной dimension требует отдельного проверяемого обоснования.

Второе обязательство независимо: `Authorize(principal,resource,action,policy_t,
identity_t)` должно разрешить запрос в определённой точке принятия решения.
Равенство response projections не означает равенство прав и не выдаёт доступ.
Пользователи могут разделять body, если оба сейчас допущены и полный `O` одинаков;
если body содержит имя пользователя, это попадёт в `D` либо caching запрещается.

Certificate связывает IR/program hash, checker/rule version, NGINX semantic
profile/config epoch, observation model, `D` и правила data-version validity.
Runtime проверяет эту связь, актуальность inputs/revisions и auth до выдачи HIT.
Ключ кодируется однозначно; credentials не становятся открытыми key/log values.
Подпись certificate подтверждает издателя; математическое обязательство требует
реально реализованного checker, а не только подписи или набора unit tests.

## Доверенная основа и невозможность black-box обещания

- Полноту можно обосновывать для закрытого IR с известными операциями и
  контролем всех reads/effects. Альтернатива — instrumented runtime, который
  действительно перехватывает все relevant reads; это отдельная большая задача.
- Клиентский `X-Tenant`, cookie, origin header `Dependencies: tenant` или даже
  подписанный origin label не доказывают ни identity, ни полноту dependency set.
  Trusted resolver проверяет identity и resource/action; анализатор связывает
  зависимости с реально исполняемой программой. Сам origin может ошибаться.
- По конечной выборке HTTP traces нельзя доказать отсутствие скрытой ветки,
  clock/random/feature-flag/DB/external-service зависимости. AI и sampling могут
  опровергать предполагаемый контракт, но не выдавать certificate полноты.
- `data revision` должен соответствовать согласованному snapshot всех reads,
  включая query membership/negative reads. Произвольный `ETag` этого не доказывает.
  Устаревший policy epoch или потерянный invalidation event не считается fresh.
- Для первого среза auth, snapshot selection и reuse decision имеют одну
  сериализованную точку `t` в локальном sequencer. Revoke после `t` не отменяет
  уже допущенную передачу. Мгновенный distributed revoke/отзыв отданных bytes
  не обещается. Для нескольких узлов нужен отдельный epoch/lease протокол.
- `Date`, `Age`, cache diagnostics и другие изменяемые поля требуют явно
  заданной семантики; нельзя незаметно исключать security-relevant headers.
  Timing/cache-occupancy side channels не покрываются равенством response bytes.
  При такой threat model нужны дополнительные isolation/side-channel меры.

## Первый технический эксперимент

Закрытый typed template IR: constants, trusted context fields, bounded
conditionals и чтение одного versioned synthetic record. Никаких arbitrary
origin calls, Lua/njs, mutable globals, streaming, clock/random, `Set-Cookie`
или произвольных filters; такие операции дают unsupported/BYPASS.
Выдаваемая cache policy явно opt-in и не ослабляет `no-store`/HTTP restrictions.

1. Получить зависимости полного response, сгенерировать certificate и проверить
   его независимыми правилами. AI может предлагать оптимизацию, но не её verdict.
2. Связать один generated endpoint с native NGINX cache и trusted local
   authorizer/version source. Проверить refinement IR → реально отданный response.
   Пока соответствие NGINX семантике не обосновано, theorem остаётся про IR.
3. Один tenant: два допущенных пользователя разделяют подходящий ответ; другой
   tenant/язык/response-dependent scope разделяются автоматически. Изменение
   неиспользуемого поля сохраняет reuse; изменение используемого поля — MISS.
4. Прогреть cache, revoke пользователя и запросить прежний URL: DENY даже при
   наличии body. Изменить policy/config/data epoch и воспроизвести update/fill
   races. Tampered certificate, неизвестный read и stale version source не HIT.
5. Guard проверяет native sequences. Отдельный oracle сравнивает их с execution
   без cache. Нужны negative controls: пропущенная branch/status/header dependency,
   неправильно объявленный shared scope, stale epoch и «всё bypass».

Измерять reuse/origin calls, ложный bypass, memory/CPU, стоимость свежего auth
и revision checks, latency всего пути и maintenance effort. Сравнить no-cache,
корректный handwritten key+auth+invalidation, консервативную partition per user
и compiler projection. Все варианты имеют одинаковую policy/freshness семантику.
Нет заранее обещанного ускорения: проверка revisions/auth может съесть выигрыш.

Критерий дальнейшего R&D: узкий checker отвергает ошибочные certificates,
полезный sharing сохраняется, native adapter соответствует модели на проверенном
профиле, а стоимость ниже полного пересчёта на целевой нагрузке. Иначе это
полезный, но ограниченный механизм либо неудачная гипотеза, не «мировой прорыв».
