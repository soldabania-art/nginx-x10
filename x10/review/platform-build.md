# NGINX: платформа, процессы и сборка

Исследован официальный снимок `nginx/nginx` на commit `148c75678cd4171338c31d4ed4c02411736d5fe9`; `src/core/nginx.h` сообщает версию `1.31.9`. Из 214 файлов выделенного manifest полностью прочитаны 213 текстовых файлов, 31 297 строк. Единственное исключение — бинарный ресурс `src/os/win32/nginx.ico`: проверены размер и заголовок ICO (1 350 байт, три изображения), статус `structural`. Фактические диапазоны находятся в `platform-build-coverage.json`.

Это разбор исходников. `configure`, сборка, тесты, нагрузочные замеры и выполнение ветвей разных ОС не проводились. Чтение не доказывает отсутствие дефектов и не заменяет проверку конкретного собранного бинарника.

## Процессы и обновление конфигурации

`src/os/unix/ngx_process_cycle.c:ngx_master_process_cycle()` обрабатывает состояние, выставленное сигналами, за пределами signal handler. При reload master создаёт новый cycle через `ngx_init_cycle()`, при успехе запускает новых workers и затем просит старых завершиться gracefully. Неудачная конфигурация оставляет прежний cycle действующим. Worker закрывает listeners и idle connections, но продолжает event loop, пока активная работа не закончится; возможен отдельный shutdown timer из core. Cache manager/loader имеют собственный lifecycle.

`src/os/unix/ngx_process.c:ngx_spawn_process()` использует `fork()` и неблокирующие `socketpair()` с `FD_CLOEXEC`; `src/os/unix/ngx_channel.c` передаёт открытые descriptors через `SCM_RIGHTS`. Reaping и respawn отделены от обработчика сигнала; fatal exit code 2 отключает respawn. После смерти worker master освобождает удержанные им shared mutexes. Windows реализует управление через `CreateProcess()` и именованные events, а не через Unix fork/signals; последовательность reload также начинает с новых workers.

**Следствие для ENGINE X10:** graceful reload и сохранение старой конфигурации при ошибке уже входят в базовую зрелость NGINX. Отличие нашего продукта нужно доказывать точными сценариями: проверка новых upstream, handover активных запросов, отказ нового поколения, дедлайн завершения и наблюдаемость результата. Само наличие reload API не доказывает превосходство.

## Control API уже есть в этом снимке

`src/os/unix/ngx_control.c:ngx_control_init()`, `ngx_control_content()`, `ngx_control_reload_config()` реализуют дополнительный listener master. Он собирается только при `--with-control-api`; в `auto/options` значение по умолчанию — `CONTROL_API=NO`, а `auto/modules` отвергает его для Windows.

Есть GET endpoints для версии, процессов и dump конфигурации: `/1/nginx`, `/1/control/processes`, `/1/control/config`. PATCH `/1/control/config` перечитывает **файлы конфигурации** через `ngx_init_cycle()`; это не загрузка новой JSON-конфигурации из тела запроса. При ошибке возвращается 422 с захваченными warnings/errors, старый cycle остаётся. Успех запускает handover workers в master loop.

В реализации 64 FD slots, включая listener, и 1 KiB request buffer; при заполнении закрывается самый старый клиент. Unix socket получает права `0600`; также допустим TCP listener. В этом модуле нет встроенных Bearer authentication, TLS и RBAC. Listener передаётся при binary upgrade через `NGINX_CTRL`, с восстановлением владельца `F_SETOWN`.

**Следствие:** утверждение «у NGINX нет API управления» для этого снимка неверно. Сравнивать можно определённые полномочия, транспорт, transaction semantics и проверку здоровья перед активацией, после проверки фактических configure flags обеих сборок.

## Сетевой и файловый ввод-вывод

`src/os/unix/ngx_os.h:ngx_os_io_t` связывает общий event слой с платформенными функциями. В `ngx_linux_sendfile_chain()` и `ngx_writev_chain()` учтены частичные передачи, `EINTR`, `EAGAIN`, состояние readiness, coalescing соседних буферов и ограничения размера операции. Linux сочетает memory headers и файловые buffers с TCP_CORK; thread sendfile имеет отдельный путь завершения. FreeBSD, Darwin и Solaris используют другие sendfile ABI и обрабатывают исторические особенности ядра. Перенос одного удачного fast path между ОС не является достаточной реализацией.

UDP chain сохраняет границы датаграмм через flush/last markers; это не тот же контракт, что потоковый `writev`. Вспомогательные сообщения нужны для адресов wildcard UDP listeners. Windows использует WSA recv/send chains; присутствие sendfile-констант в headers ещё не означает активный Unix sendfile path.

`ngx_file_aio_read()` различает `active`, `complete`, `ready`; повторная отправка до завершения запрещена. `EAGAIN` и `ENOSYS` допускают синхронный fallback. Комментарий FreeBSD указывает, что `aio_cancel()` не отменяет file AIO. Следовательно, срок жизни connection, event, file и thread task необходимо учитывать независимо от желаемого дедлайна закрытия.

Unix shared memory выбирает anonymous mmap, `/dev/zero` или SysV в зависимости от probes. Windows mapping учитывает необходимость совместимых адресов между процессами и reload. `src/os/win32/ngx_files.c:ngx_win32_check_filename()` проверяет неоднозначности NTFS paths, alternate streams, завершающие точки/пробелы и соответствие длинному имени; UTF-8/UTF-16 преобразования проверяют суррогаты.

**Следствие:** начинать ENGINE X10 разумно с явно заявленной Linux support matrix и контрактов backpressure/cancellation/ownership. Для заявления о переносимости нужны отдельные сборки и интеграционные сценарии на каждой поддерживаемой ОС.

## Как формируется конкретный бинарник

`auto/configure` последовательно выполняет настройку compiler, OS/features, modules/libraries, затем генерирует make/install/summary. `auto/feature` создаёт маленькую C-программу, компилирует её и при необходимости запускает в режимах проверки наличия, значения либо известной ошибки. Header presence не заменяет успешную проверку функции.

`auto/module` отдельно собирает static, dynamic и addon modules; `auto/modules` задаёт зависимости и порядок filters. PCRE1/PCRE2, OpenSSL/QUIC, zlib, libxslt, GD, Perl и прочие libraries проверяются или собираются по отдельным правилам. Windows thread pools явно отвергаются. Настройки GCC/Clang включают собственные warnings и оптимизацию `-O`; нельзя предполагать одинаковые compiler flags при сравнении производительности.

В данном tree HTTP SSL, HTTP/2 и HTTP/3 по умолчанию выключены; control API также выключен. `HTTP_UPSTREAM_LEAST_TIME=YES` и `HTTP_UPSTREAM_STICKY=YES`. Это значения configure defaults конкретного commit, а не вывод о произвольной установленной версии NGINX. Состав исходников, syntax highlighting и список модулей не являются одинаковыми перечнями доступных функций.

`src/os/win32/ngx_service.c` — незавершённый stub, отсутствующий в `WIN32_SRCS`. Это пример того, почему наличие файла нельзя считать реализованной возможностью.

## Конфигурация, packaging и вспомогательные файлы

`conf/nginx.conf` — пример: один worker, `worker_connections 1024`, HTTP port 80, `sendfile on`, `keepalive_timeout 65`; gzip и многие блоки закомментированы. Эти значения нельзя выдавать за универсальную production-настройку. `fastcgi.conf` содержит `SCRIPT_FILENAME`, тогда как `fastcgi_params` его не задаёт. Прочитаны также MIME/charset maps, uWSGI/SCGI params и образец Windows HTML.

`misc/GNUmakefile` экспортирует release из git, перемещает configure/documentation, формирует tar/zip и лицензии зависимостей. `contrib` содержит конвертеры geo/Unicode и Vim integration; syntax file перечисляет также сторонние и коммерческие directives и потому не является списком собранных модулей.

`.github/workflows` делегируют ряд операций внешнему `nginx/ci-self-hosted`. Его содержимое не входит в этот clone и не исследовано. Отдельный `nginx-tests`, упомянутый шаблоном PR, не клонировался и не запускался. Это остаётся границей данного чтения.

## Что требуется проверить дальше

Для ENGINE X10 важнее конкретные измеримые цели, чем название «10×»: одинаковый набор протоколов и нагрузка; p50/p95/p99, throughput, CPU/RSS; медленные клиенты и upstream; прерывание операций; ошибочный reload и гибель worker; файловые и TLS сценарии. Этот отчёт определяет исходные контракты и зоны риска, но не содержит результатов таких проверок.
