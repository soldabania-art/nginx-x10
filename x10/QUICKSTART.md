# NGINX X10: локальная Linux alpha

Эта инструкция запускает отдельное native-демо на вашем компьютере: HTTP на
`127.0.0.1:8088` и native self-check на `127.0.0.1:8089`. Установка выполняется
от обычного пользователя, в новую личную папку, без `sudo` и системного service.

Это development snapshot для Linux. Windows не проверен. Бинарник динамически
связан с библиотеками машины: соберите и запускайте его на этой машине;
папка установки не является переносимым пакетом для любого Linux.

## 1. Собрать и установить

Нужны Node.js 22+, Git и инструменты/библиотеки из [BUILD.md](BUILD.md): Bash,
Python 3, C compiler, GNU make, PCRE2, OpenSSL, zlib и libcrypt. Во время
установки также используется `ldd`. Порты 8088 и 8089 должны быть свободны.

```sh
git clone --branch x10-continuum-development https://github.com/soldabania-art/nginx-x10.git
cd nginx-x10
x10_source_sha="$(git rev-parse HEAD)"
git checkout --detach "$x10_source_sha"
git rev-parse HEAD
bash x10/build.sh --jobs 2

x10_prefix="$HOME/nginx-x10-local"
node x10/alpha/cli.mjs install --prefix "$x10_prefix" --port 8088 --health-port 8089
```

Сохраните выведенный полный `x10_source_sha` вместе с build manifest. Это закрепление
выбранного development checkout, а не ссылка на принятый постоянный выпуск.
Пока versioned alpha не опубликована и не принята, здесь нет команды скачивания
такого выпуска. Нельзя подставлять старый SHA, в котором ещё нет новых опций.

`x10_prefix` должен быть новым абсолютным путём без пробелов и symlink-компонентов.
Существующая папка не перезаписывается. Для другого подтверждённого build record
можно явно указать `--manifest /absolute/path/manifest.json`.

Успешный `install` возвращает `outcome: "installed"`, пути и начальный
`revision`. Сохраните этот реальный ID, если хотите затем вернуться к исходному
демо. Установлены `bin/nginx`, `bin/x10`, пример конфигурации и лицензия.

## 2. Запустить в первом терминале

```sh
"$x10_prefix/bin/x10" run
```

Первое событие `native_starting` содержит ещё непроверенный PID кандидата.
Дождитесь JSON с `outcome: "running"` и проверенным PID. Команда остаётся в foreground;
оставьте этот терминал открытым. `run` не подтверждает здоровье вашего приложения.

## 3. Управлять из второго терминала

```sh
x10_prefix="$HOME/nginx-x10-local"
"$x10_prefix/bin/x10" bind
"$x10_prefix/bin/x10" status --human
"$x10_prefix/bin/x10" info
```

`bind` явно привязывает controller к запущенному master. `status --human`
показывает состояние понятным текстом; без `--human` команда возвращает JSON.
`info` показывает текущую сессию, её папку, порты и режим health.

Откройте <http://127.0.0.1:8088/> в браузере: ответ — `NGINX X10 local alpha`.
Комплектный health URL — `http://127.0.0.1:8089/__x10_demo_self_check`.
Это проверка native-демо, а не внешнего upstream или бизнес-логики приложения.

## 4. Применить изменение и вернуть ревизию

```sh
"$x10_prefix/bin/x10" apply --file "$x10_prefix/examples/candidate-b.json"
"$x10_prefix/bin/x10" status --human
"$x10_prefix/bin/x10" history
```

После успешного apply можно наблюдать ответ `NGINX X10 updated local alpha`.
Во время завершения старых workers отдельные запросы ещё могут получать прежний
ответ. Gate проверяет выборочные ответы, а не атомарное переключение всего трафика.
Пример меняет один управляемый fragment; полный произвольный `nginx.conf`
этой командой не редактируется.

Для возврата возьмите **реальный ID** нужной ревизии из `history` или первого
ответа `install`. В следующей команде замените `ID_ИЗ_ИСТОРИИ` на него:

```sh
"$x10_prefix/bin/x10" revert --revision ID_ИЗ_ИСТОРИИ
```

Revert создаёт новую ревизию с прежним содержимым. Кандидат может обслуживать
запросы до завершения health gate; откат не отменяет уже выполненные запросы.

## 5. Остановить, перезапустить или удалить

Во втором терминале:

```sh
"$x10_prefix/bin/x10" stop
```

Дождитесь завершения `run` в первом терминале. Для следующего запуска снова
выполните там `run`, дождитесь `running`, затем во втором терминале выполните
`bind` и `status --human`.

Новый запуск создаёт новую сессию с последним подтверждённым содержимым.
`history` показывает текущую сессию; прежние журналы остаются в
`runs/<session>/.x10-control`. Это отдельные сохранённые истории, не одна
непрерывная цепочка между master-процессами.

Для полного удаления после `stop`:

```sh
"$x10_prefix/bin/x10" uninstall
```

Удаление включает журналы установки. Сохраните нужные данные заранее.
При живом master, неизвестных файлах или конфликте состояния команда
отказывает в удалении. Не удаляйте lock/state вручную ради успешного результата;
порядок проверки и `recover` описан в [control/README.md](control/README.md).

Аварийное завершение native master записывается как `faulted` и блокирует
автоматический запуск, `stop` и удаление. Например, после SIGKILL оставшиеся
workers ещё могут обслуживать запросы. Такой случай требует проверки процессов
и сохранённых записей оператором; alpha не удаляет осиротевшие процессы автоматически.

## Подключить настоящее локальное приложение

Это отдельный явно выбранный режим **новой** установки. Без `--upstream-port`
сохраняется описанное выше native-демо. Сначала остановите прежнюю установку,
если она использует те же порты. После сборки создайте другой private prefix:

```sh
x10_app_prefix="$HOME/nginx-x10-app"
node x10/alpha/cli.mjs install --prefix "$x10_app_prefix" --port 8088 --health-port 8089 --upstream-port 9090
```

Порты должны быть различными, десятичными, от 1024 до 65535. Опция принимает
только порт HTTP-приложения на `127.0.0.1`, не URL/hostname/credentials.
У приложения нужен отдельный идемпотентный `GET /ready`. `install` только готовит
конфигурацию: успешный `installed` не означает, что приложение запущено или здорово.

Для проверки пути можно явно запустить комплектное ограниченное приложение.
В первом терминале:

```sh
x10_app_prefix="$HOME/nginx-x10-app"
node "$x10_app_prefix/lib/alpha/upstream-example.mjs" --port 9090
```

Дождитесь `outcome: upstream_example_listening`. Пример слушает только loopback:
`GET /ready` отвечает `ready\n`, `GET /` — `NGINX X10 upstream example\n`,
`POST /echo` возвращает полученные bytes (не более16MiB, до4 одновременных echo),
`GET /stream` передаёт8MiB с backpressure. Это пример процесса приложения,
а не бизнес-readiness, авторизованный сервис или законченный Production V1.

Во втором терминале:

```sh
x10_app_prefix="$HOME/nginx-x10-app"
"$x10_app_prefix/bin/x10" run
```

После проверенного `running` — в третьем:

```sh
x10_app_prefix="$HOME/nginx-x10-app"
"$x10_app_prefix/bin/x10" bind
curl --fail --show-error http://127.0.0.1:8088/__x10_health
curl --fail --show-error http://127.0.0.1:8088/
printf 'payload\n' | curl --fail --show-error --data-binary @- http://127.0.0.1:8088/echo
"$x10_app_prefix/bin/x10" apply --file "$x10_app_prefix/examples/candidate-b.json"
"$x10_app_prefix/bin/x10" history
```

HTTP-трафик проходит через native NGINX к приложению на9090; Node-пример —
отдельный upstream. Proxy не делает автоматический retry. В этом режиме bind/apply
проверяют HTTP200 через managed `/__x10_health` и текущий revision header, но не
сравнивают тело `/ready` и не доказывают состояние БД/бизнес-операций. `status`
по-прежнему наблюдает runtime/revision, а не непрерывную health приложения.
Native self-check на8089 может оставаться200 при недоступном upstream.

Комплектный `candidate-b.json` сохраняет proxy/readiness URL и добавляет
`X-X10-Example: application-b`. Он не заменяет приложение demo-ответом. Для revert
возьмите реальный ID из истории. После штатного stop/run сохраняется только
проверенный last-confirmed input; новый master нужно снова bind.

Остановите native через `bin/x10 stop`, дождитесь выхода его `run`, затем Ctrl-C
в терминале примера. После этого удаляйте установку по прежним правилам. Это
foreground-путь с несколькими терминалами, ещё не управляемый сервис G3.

## Локальный tar bundle

После проверенной сборки можно упаковать бинарник, CLI и лицензии:

```sh
node x10/alpha/cli.mjs pack --output x10/.build/dist/nginx-x10-linux-alpha.tar.gz
```

В существующей личной папке на совместимой Linux-машине:

```sh
tar -xzf nginx-x10-linux-alpha.tar.gz
node nginx-x10-alpha/install.mjs install --prefix "$HOME/nginx-x10-local" --port 8088 --health-port 8089
# Либо новый prefix в режиме приложения:
node nginx-x10-alpha/install.mjs install --prefix "$HOME/nginx-x10-app" --port 8088 --health-port 8089 --upstream-port 9090
```

Распакованный installer проверяет состав bundle и не требует исходного git checkout
или build tree. Комплектный upstream-пример запускается из установленного
`lib/alpha/upstream-example.mjs`, как выше. Используйте один выбранный install
с новым prefix; две команды выше показывают альтернативы. Ранние bundles могут
не содержать новую опцию/пример и не считаются её проверенной поставкой. Node.js 22+, `ldd` и совместимые динамические библиотеки всё ещё
нужны. Это не универсальный static package. Локальный архив остаётся в ignored
build-папке; artifact CI создаётся отдельно из checkout публичного runner.
CI также сохраняет sidecar `.sha256`; это контрольная сумма, а не подпись.
Постоянный versioned alpha archive и независимый replay именно опубликованных
файлов ещё требуют отдельной приёмки G2. Успех локального tar не закрывает этот
gate, G3–G8 или Production V1.

## Native API — только по явному выбору

Обычный `run` не открывает control API. Если ваша Linux-среда поддерживает
Unix sockets, можно после остановки запустить его явно:

```sh
"$x10_prefix/bin/x10" run --control-socket "$x10_prefix/control.sock"
```

После нового `bind` во втором терминале:

```sh
"$x10_prefix/bin/x10" inspect-generations --control-socket "$x10_prefix/control.sock"
```

Socket должен быть новым абсолютным путём непосредственно внутри установки.
TCP management listener и автоматический fallback не включаются. Generation
показывает учёт процессов master, а не здоровье приложения или полный drain.

Профиль и ограничения alpha, ошибки конфликтов и восстановления следует
проверять вместе с [STATUS.md](STATUS.md). Ускорение «10×» не подтверждено.
