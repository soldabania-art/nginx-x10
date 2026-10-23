# NGINX X10 — развитие полного NGINX

Основа проекта — полный NGINX Open Source. Задача владельца: сохранить его возможности и последовательно улучшать каждую область. Существующие конфигурации, протоколы и модули входят в требования совместимости; отдельный упрощённый reverse proxy их не заменяет.

Это независимый fork, не официальный выпуск NGINX/F5. Исходные copyright и LICENSE сохранены. База: commit `148c75678cd4171338c31d4ed4c02411736d5fe9`; `nginx.h` содержит версию `1.31.9`. Это снимок master, а не утверждение о готовом стабильном релизе X10.

## Что уже сделано

- Сохранены исходная история, ветки и теги NGINX.
- Команда выполнила первый проход по всему текстовому коду выбранного снимка. [Покрытие](review/coverage-summary.json) разделяет реально прочитанные файлы, историческую документацию и бинарную иконку. Это не доказательство отсутствия дефектов или полного понимания всех взаимодействий.
- Подготовлен [нативный профиль сборки](BUILD.md) с учётом реальных configure flags, зависимостей и состава модулей.
- Добавлены настоящие HTTP/TLS/HTTP2, stream/mail и QUIC parser regression fixtures; границы каждого набора записываются в JSON. [Почтовый TLS-набор](test/MAIL-TLS.md) проверяет SMTP/IMAP/POP3 upgrade и implicit TLS с CA/hostname controls. [Adapter-набор](test/ADAPTERS.md) проверяет FastCGI/SCGI/uWSGI на локальных backend без optional Perl-модулей. [HTTP/3-набор](test/HTTP3.md) выполняет семь проверок через настоящий UDP QUIC/TLS 1.3 с ALPN `h3`, native protocol headers, точными ответами и CA/hostname negatives; TCP fallback отсутствует, HEAD остаётся непроверенным.
- Первый минимальный C patch исправляет сужение QUIC transport parameter ID и неполное потребление числового значения. Исходная и исправленная версии проверяются одним parser harness. Политика дубликатов пока не меняется.
- Добавлен [локальный контроллер](control/README.md): ревизии одного управляемого HTTP server fragment, native `-t`, привязка к конкретному master, проверка нового поколения, health gate, rollback и журнал. Остальная конфигурация остаётся у оператора.
- [Официальные nginx-tests](CI.md) закреплены по ревизии и запускаются без изменения исходных тестов; пропуски, TODO и строгие ошибки считаются отдельно.
- Отдельные native fixtures проверяют кэш, ограничения, файлы и маршрутизацию. Генерируемые свойства QUIC transport parameters и отдельные [6579 frame-parser входов](evidence/quic-frames-fixed.json) проверяются под ASan/UBSan; число связанных входов не считается числом независимых функций. Frame-набор не проверяет состояние соединения, flow control или сетевую совместимость; LeakSanitizer в этом профиле отключён.
- [Проверка C load client](bench/NATIVE-LOAD.md) включает 41 короткий functional/sanitizer control и native smoke. Это проверка генератора нагрузки, а не performance gate. Контроллер проходит 66 TAP-проверок, включая ограниченные сценарии journal recovery и ошибок хранения; они не доказывают устойчивость ко всем сбоям питания.
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
bash x10/build.sh
node x10/test/all.mjs
# Дополнительно: официальный sample, первый запуск требует Git network access.
node x10/test/all.mjs --official
# Только проверка соответствия исходников, бинарника и build manifest:
node x10/test/all.mjs --provenance-only
```

Общий runner отвергает устаревший build manifest, изменённые native исходники, подмену бинарника и расхождение трёх generated build inputs с записанными SHA-256/размером/режимом. Затем последовательно запускаются 11 групп: HTTP/TLS/HTTP2/reload, stream/mail, mail TLS/STARTTLS, FastCGI/SCGI/uWSGI, настоящий HTTP/3, features, QUIC regression, generated transport parameters, frame boundaries, C load-client verification и native control. `--official` добавляет двенадцатую группу — закреплённый официальный sample. Последний [локальный aggregate](evidence/native-checks-milestone-4.json) прошёл 12/12 групп; пропуски и TODO внутри official sample остаются отдельными результатами. Старый manifest без generated identities требует настоящей пересборки. Прерывание возвращает неуспех и передаёт сигнал fixture-процессам для очистки. Сравнение производительности запускается отдельно в спокойном окружении.

Зависимости и точные ограничения профиля указаны в BUILD.md и [CI.md](CI.md). Для fixtures нужны Node.js 22+, CPython 3.12 с venv, C compiler и OpenSSL CLI; для официального sample — Perl и указанные optional clients. Полный десятипакетный HTTP/3 lock предназначен для Linux x86_64/CPython 3.12. Установка требует доступа к пакетам; тесты сами ничего не устанавливают. Другой подготовленный pinned venv можно указать через `X10_HTTP3_PYTHON=/absolute/venv/bin/python`; отсутствие или несовпадение версий завершает обязательную HTTP/3-группу ошибкой, а не passing skip. Тесты используют временные каталоги, локальные upstream и синтетические учётные данные. Шлюз не устанавливается глобально и не публикуется в интернет.

## Локальное управление

```bash
node x10/control/cli.mjs --help
```

Полный пример `init → запуск native master → bind → apply/status/history/revert/recover` находится в [control/README.md](control/README.md). Контроллер — отдельный opt-in инструмент для Linux и доверенного оператора. Он управляет одним явно включённым loopback HTTP server fragment, не редактирует произвольный `nginx.conf` и не открывает удалённый административный API.

Health gate выполняется после reload: кандидат может обслужить запросы до проверки и отката. Подтверждение нового поколения не является мгновенным переключением всех запросов. Сценарии восстановления и границы хранения журнала описаны рядом с командами.

Консоль и ранние Node-эксперименты остаются в [engine-x10](https://github.com/soldabania-art/engine-x10). Рабочее направление сетевого ядра — этот native fork.

## Как принимается улучшение

Для каждой возможности фиксируем исходное поведение, недостаток, изменение, тест совместимости и измеряемый результат. Успешный тест исправления — доказательство конкретного исправления. Компиляция — доказательство конкретной сборки. Ускорение, экономия памяти, надёжность и время оператора измеряются отдельно. Название X10 не является результатом benchmark.
