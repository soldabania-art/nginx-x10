# NGINX X10 — развитие полного NGINX

Основа проекта — полный NGINX Open Source. Задача владельца: сохранить его возможности и последовательно улучшать каждую область. Существующие конфигурации, протоколы и модули входят в требования совместимости; отдельный упрощённый reverse proxy их не заменяет.

Это независимый fork, не официальный выпуск NGINX/F5. Исходные copyright и LICENSE сохранены. База: commit `148c75678cd4171338c31d4ed4c02411736d5fe9`; `nginx.h` содержит версию `1.31.9`. Это снимок master, а не утверждение о готовом стабильном релизе X10.

Понятный срез продукта, готового и предстоящего: [ROADMAP](ROADMAP.md). Точная матрица работ: [PLAN](PLAN.md).

## Исследовательский эксперимент Guard

[Проверяющее ядро](proof/README.md) исполняет заданные проверки изоляции
tenant/cache на настоящем NGINX и отклоняет исправление, которое просто
выключает обязательный cache. Это узкое детерминированное ядро; LLM и импорт
произвольных конфигураций пока не реализованы. Сравнения с существующими
подходами предусмотрены в [R&D design](review/guard-research.md).

[Кандидат нового технологического ядра](review/cache-dependency-research.md) —
компилятор проверяемых зависимостей ответа с отдельной текущей авторизацией.
Это концепция без реализации и измерений; Guard служит инструментом экспериментов.

## Попробовать локальную alpha

[Короткая инструкция](QUICKSTART.md) ведёт через установку в отдельный каталог,
запуск native сервера, читаемый status, применение и откат настройки,
остановку, повторный запуск и удаление. Нужны Linux, Node.js 22+ и собранный
native профиль. Системный NGINX не заменяется; пример слушает только loopback.
Обычные запросы обрабатывает C-бинарник, Node используется для команд управления.
Это development alpha, не промышленная поставка и не проверенный Windows-порт.
Новый запуск создаёт отдельную сессию с последним подтверждённым содержимым;
прежние истории сохраняются в `runs/<session>`. Установленный бинарник требует
совместимых динамических библиотек машины. Обычный `run` не открывает control
API; private Unix socket включается только явной опцией.

## Что уже сделано

- Сохранены исходная история, ветки и теги NGINX.
- Команда выполнила первый проход по всему текстовому коду выбранного снимка. [Покрытие](review/coverage-summary.json) разделяет реально прочитанные файлы, историческую документацию и бинарную иконку. Это не доказательство отсутствия дефектов или полного понимания всех взаимодействий.
- Подготовлен [нативный профиль сборки](BUILD.md) с учётом реальных configure flags, зависимостей и состава модулей.
- Добавлены настоящие HTTP/TLS/HTTP2, stream/mail и QUIC parser regression fixtures; границы каждого набора записываются в JSON. [Почтовый TLS-набор](test/MAIL-TLS.md) проверяет SMTP/IMAP/POP3 upgrade и implicit TLS с CA/hostname controls. [Adapter-набор](test/ADAPTERS.md) проверяет FastCGI/SCGI/uWSGI на локальных backend без optional Perl-модулей. [HTTP/3-набор](test/HTTP3.md) выполняет семь проверок через настоящий UDP QUIC/TLS 1.3 с ALPN `h3`, native protocol headers, точными ответами и CA/hostname negatives; TCP fallback отсутствует.
- [Независимый HEAD-набор](test/http3-head.md) использует curl_cffi/libcurl: обязательный HTTP/3, проверку CA/hostname, GET control и HEAD status/headers с пустым телом на уровне клиентского API. Сохранённые [candidate](evidence/http3-head-fixed.json) и [reference](evidence/http3-head-reference.json) reports содержат по 4/4 успешных случая; это отдельные прогоны, а не результат нового полного aggregate. Это не packet-level доказательство отсутствия DATA frames. Прежний aioquic HEAD diagnostic сохранён отдельно и не объявлен native-дефектом.
- Первый минимальный C patch исправляет сужение QUIC transport parameter ID и неполное потребление числового значения. Исходная и исправленная версии проверяются одним parser harness. Политика дубликатов пока не меняется.
- Добавлен native `GET /1/control/generations`: поколение принятой конфигурации и отдельный birth ID каждого процесса. Endpoint включается только через явно открытый control API; существующие process/cycle layouts и `/processes` JSON сохранены. [Контракт](review/native-generation-contract.md), [проверки](test/GENERATIONS.md). Это принадлежность процессов, а не worker readiness или listener-close ACK.
- Добавлен [локальный контроллер](control/README.md): ревизии одного управляемого HTTP server fragment, native `-t`, привязка к конкретному master, проверка нового поколения, health gate, rollback и журнал. Остальная конфигурация остаётся у оператора. Новые явные команды `snapshot-listeners` и `inspect-listeners` наблюдают ownership TCP listener только у конкретных captured processes; условия обычного apply/recover не меняются. [Живой reload fixture](test/HANDOVER.md) разделяет новый ответ, закрытие старого listener и завершение принятого потока.
- `status --human` показывает revision, binding/runtime, pending и действия при расхождениях, сохраняя JSON по умолчанию. Read-only `inspect-generations` связывает явно выбранный API endpoint с bound master lifetime, namespaces и LISTEN inode до/после GET, ограничивает HTTP/JSON и сохраняет точность uint64. `ok:true` диагностической команды не означает health, worker readiness или полный drain.
- [Linux alpha](QUICKSTART.md) устанавливается в новый private prefix без `sudo`, запускается в foreground и поддерживает явные bind/apply/revert/stop/restart/uninstall. [Упаковка](alpha/README.md) использует проверенный build manifest; это локальная development-поставка с Node.js 22+ и зависимостями native бинарника, а не универсальный Linux пакет.
- [Официальные nginx-tests](CI.md) закреплены по ревизии и запускаются без изменения исходных тестов; пропуски, TODO и строгие ошибки считаются отдельно.
- Отдельные native fixtures проверяют кэш, ограничения, файлы и маршрутизацию. Генерируемые свойства QUIC transport parameters и отдельные [6579 frame-parser входов](evidence/quic-frames-fixed.json) проверяются под ASan/UBSan; число связанных входов не считается числом независимых функций. Frame-набор не проверяет состояние соединения, flow control или сетевую совместимость; LeakSanitizer в этом профиле отключён.
- [Проверка C load client](bench/NATIVE-LOAD.md) включает 41 короткий functional/sanitizer control и native smoke. Это проверка генератора нагрузки, а не performance gate. В [milestone-4](evidence/native-checks-milestone-4.json) контроллер прошёл 66 TAP-проверок, включая ограниченные сценарии journal recovery и ошибок хранения; они не доказывают устойчивость ко всем сбоям питания. Текущий набор дополнен CLI-проверками listener diagnostics и отдельными observer boundary tests.
- Подготовлено [сравнение с C client и native origin](bench/NATIVE-COMPARE.md): точные ответы, одинаковые профили, порядок AB/BA, сырые замеры и раздельные CPU/RSS. [Прежний Node driver](bench/README.md) и его неблагоприятные результаты сохранены. Результат одного workload не распространяется на весь NGINX; ускорение пока не установлено.

Результаты конкретной сборки: [STATUS](STATUS.md). План всех областей: [PLAN](PLAN.md). Машинный список модулей, директив и определений функций: [feature-catalog.json](feature-catalog.json). Каталог получен по структуре исходников, не заменяет AST, тестовую матрицу или ручные выводы.

## Сборка и проверки

```bash
# HTTP/3 test client: Linux x86_64, CPython 3.12; требуется python3-venv.
python3 -m venv x10/.build/http3-venv
x10/.build/http3-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: \
  -r x10/test/http3-baseline.requirements.txt
x10/.build/http3-venv/bin/python -m pip check
# Независимый libcurl HTTP/3 HEAD client, отдельный pinned venv:
python3 -m venv x10/.build/http3-head-venv
x10/.build/http3-head-venv/bin/python -m pip install \
  --require-hashes --only-binary=:all: \
  -r x10/test/http3-head.requirements.txt
x10/.build/http3-head-venv/bin/python -m pip check
bash x10/build.sh
node x10/test/all.mjs
# Дополнительно: официальный sample, первый запуск требует Git network access.
node x10/test/all.mjs --official
# Только проверка соответствия исходников, бинарника и build manifest:
node x10/test/all.mjs --provenance-only
```

Общий runner отвергает устаревший build manifest, изменённые native исходники, подмену бинарника и расхождение трёх generated build inputs с записанными SHA-256/размером/режимом. Текущий профиль последовательно запускает 19 групп: HTTP/TLS/HTTP2/reload, stream/mail, mail TLS/STARTTLS, FastCGI/SCGI/uWSGI, aioquic HTTP/3, независимый HTTP/3 HEAD, features, QUIC regression, generated transport parameters, frame boundaries, C load-client verification, native control, operator status, local alpha lifecycle, observer boundary tests, reload/listener observation, native control API, process generations и generation boundaries. `--official` добавляет двадцатую группу — закреплённый официальный sample. Сохранённый [milestone-4 aggregate](evidence/native-checks-milestone-4.json) относится к предыдущему профилю и прошёл 12/12 групп; пропуски и TODO внутри official sample остаются отдельными результатами. Старый manifest без generated identities требует настоящей пересборки. Прерывание возвращает неуспех и передаёт сигнал fixture-процессам для очистки. Сравнение производительности запускается отдельно в спокойном окружении.

Зависимости и точные ограничения профиля указаны в BUILD.md и [CI.md](CI.md). Для fixtures нужны Node.js 22+, CPython 3.12 с venv, C compiler и OpenSSL CLI; для официального sample — Perl и указанные optional clients. Десятипакетный aioquic lock и отдельный четырёхпакетный curl_cffi 0.16.3 lock предназначены для Linux x86_64/CPython 3.12. Установка требует доступа к пакетам; тесты сами ничего не устанавливают. Другие подготовленные pinned venv можно указать через `X10_HTTP3_PYTHON=/absolute/venv/bin/python` и `X10_HTTP3_HEAD_PYTHON=/absolute/venv/bin/python`; отсутствие или несовпадение версий завершает соответствующую обязательную группу ошибкой, а не passing skip. Тесты используют временные каталоги, локальные upstream и синтетические учётные данные. Шлюз не устанавливается глобально и не публикуется в интернет.

Последний [milestone-5 aggregate](evidence/native-checks-milestone-5.json) прошёл **15/15 групп** после исправления отмены HEAD-стенда: controller **68/68 TAP**, observer **29/29 TAP**. Hosted CI проверяется отдельно на опубликованном commit.

Предыдущий [milestone-6 aggregate](evidence/native-checks-milestone-6.json) прошёл **18/18 групп** после реальной native пересборки. Финальный локальный [milestone-7 aggregate](evidence/native-checks-milestone-7.json) прошёл **20/20**, exit 0: operator-status **30/30 TAP**, alpha lifecycle **9/9**, controller **68/68**, observer **29/29**; official sample сохранил **1083 strict PASS / 25 SKIP / 1 expected TODO / 0 strict FAIL**. Новых изменений C нет, native binary SHA сохранился. [Независимый review](review/local-alpha-review.md) отдельно проверил 9 operator и 8 package controls. Новый hosted CI ещё ожидается. Отдельные обязательные Unix transport/operator-status и feature-off build gates, а также CI tar/checksum artifact описаны в [CI](CI.md). Native generation — development-возможность, без worker ACK/fence или performance claim.

## Локальное управление

```bash
node x10/control/cli.mjs --help
```

Полный пример `init → запуск native master → bind → apply/status/history/revert/recover` находится в [control/README.md](control/README.md). Контроллер — отдельный opt-in инструмент для Linux и доверенного оператора. Он управляет одним явно включённым loopback HTTP server fragment, не редактирует произвольный `nginx.conf` и не открывает удалённый административный API.

Для отдельной диагностики сохраните JSON snapshot до apply, затем передайте его inspect:

```bash
node x10/control/cli.mjs snapshot-listeners --state /home/alex/x10-run/.x10-control > before.json
node x10/control/cli.mjs apply --state /home/alex/x10-run/.x10-control --file candidate.json
node x10/control/cli.mjs inspect-listeners --state /home/alex/x10-run/.x10-control --file before.json
```

`ok:true` при inspection означает успешное наблюдение. Состояние `observation.state` отдельно показывает `pending` или `closed`. Команды не посылают сигналы; они проверяют bound master, текущие файлы и идентичность captured processes. Закрытие listener у этого конечного набора не подтверждает все поколения, respawns, здоровье приложения или полный drain. Подробные ограничения находятся в [LISTENERS.md](control/LISTENERS.md).

Health gate выполняется после reload: кандидат может обслужить запросы до проверки и отката. Подтверждение нового поколения не является мгновенным переключением всех запросов. Сценарии восстановления и границы хранения журнала описаны рядом с командами.

Консоль и ранние Node-эксперименты остаются в [engine-x10](https://github.com/soldabania-art/engine-x10). Рабочее направление сетевого ядра — этот native fork.

## Как принимается улучшение

Для каждой возможности фиксируем исходное поведение, недостаток, изменение, тест совместимости и измеряемый результат. Успешный тест исправления — доказательство конкретного исправления. Компиляция — доказательство конкретной сборки. Ускорение, экономия памяти, надёжность и время оператора измеряются отдельно. Название X10 не является результатом benchmark.
