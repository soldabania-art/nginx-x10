# G3: подготовка systemd user unit

Это генератор recipe, не установленный и не принятый сервис. Нативный data plane,
существующий alpha lifecycle и readiness-контракт сохраняются. Генератор не
запускает systemctl, не устанавливает unit и не меняет автозапуск или linger.

## Создание

Перед планированием активации отдельно проверьте prerequisites тестового хоста:

```sh
node x10/service/preflight.mjs
```

Это read-only helper из source checkout, а не установленная часть alpha bundle.
Он не создаёт unit, не запускает сервис и не меняет systemd, linger, учётные
записи или среду владельца. Запускайте его обычным пользователем на Linux,
в контексте того же UID и его локального user-manager. Не используйте sudo
или другую учётную запись, чтобы превратить отказ в успешный результат.
Root получает явный отказ до обращения к manager.

Helper использует фиксированный проверенный systemctl и локальный user bus;
PATH shim и унаследованный удалённый адрес D-Bus не выбирают менеджер.
Он требует ограниченный структурированный ответ manager с версией, состоянием
и ControlGroup, соответствующим текущему UID. Exit 0 с текстом-заглушкой,
неполным или противоречивым ответом не означает доступность manager.
Timeout, слишком большой вывод, отсутствующий bus или ошибка дают ненулевой
exit и фиксированный reason code, без raw stdout/stderr или environment dump.
Состояние degraded показывается явно и не называется здоровым.

Даже `managerAvailable:true` подтверждает только эти предварительные условия.
Оно не подтверждает установленный unit, запуск native, readiness/TLS, restart,
drain, отсутствие orphan или Production V1. Успешные синтетические ответы в
тестах parser также не являются наблюдением живого user-manager.
На недоступном хосте сохраните отказ и используйте разрешённую совместимую
тестовую среду; helper сам ничего не устанавливает и не исправляет.

Проверки контракта helper выполняются отдельно:

```sh
node --test --test-reporter=tap x10/service/preflight.test.mjs
```

CI запускает именно эти проверки, а не принимает этим реальный сервис.
Набор отдельно сохраняет очищенное наблюдение фактического CLI на текущем
хосте. Отказ prerequisites допускает успешную проверку самого контракта
отказа; это не успешный service gate и не признак доступного user-manager.
Поддержан только локальный canonical runtime `/run/user/<UID>` с частным
каталогом, принадлежащим текущему UID, и его Unix socket `bus`. Другие
расположения, namespace layouts и удалённые managers явно не принимаются.
В текущей локальной UID0 среде PATH-команда systemctl возвращала exit0
с сообщением об отсутствии systemd. Фиксированный настоящий executable
отказал с exit1 из-за отсутствующего user bus. Эти разные наблюдения
сохраняются отдельно от прежнего ENXIO и не доказывают его причину.

## Генерация recipe

Нужен существующий private0700 alpha prefix и точный canonical Node executable,
записанный при его установке. Передайте пути явно; lookup через PATH не нужен:

```sh
umask 077
node x10/service/user-unit.mjs --prefix /absolute/private/alpha \
  --node /absolute/recorded/node > candidate.service
```

Проверяйте exit code. При отказе вывод — фиксированный JSON, а не unit; такой
файл нельзя передавать systemd. Генератор проверяет prefix/launcher/Node только
в момент генерации. Доверенный оператор обязан заново принять изменённые Node,
библиотеки или installation bytes. Hash не является OS fence от другого
процесса того же UID. В unit используются установленные файлы, не source checkout.

## Семантика и допуск

Type=exec означает запуск Node, а не готовность native, приложения или TLS.
В recipe нет ExecStartPost bind: запуск bind до завершения native startup может
попасть на alpha lock. Автоматическое ожидание readiness требует отдельного
установленного bounded helper и его приёмки. После установления identity
оператор должен отдельно выполнить exact Node и launcher:

```sh
/absolute/recorded/node /absolute/private/alpha/bin/x10 bind
```

До успешного bind сервис не считается готовым к использованию. При отказе
проверьте status/logs и выполните stop; не повторяйте run и не очищайте lock
вслепую. Recipe не меняет health в успешный только по active(systemd).
Проверка/установка unit, запуск и повторный старт на nonroot Node22 test host
пока не приняты; пример генерации не является инструкцией production deploy.

Restart=no исключает автоматический цикл после faulted exit. Явный restart
разрешён операторскому lifecycle только после подтверждённого stop; faulted
master/orphan требуют ручной проверки identity и отказа от автоматического
restart/uninstall. ExecStop вызывает установленный alpha stop. При остановке
wrapper получает SIGTERM и передаёт verified native SIGQUIT. KillMode=process
и SendSIGKILL=no не позволяют systemd принудительно убить всю неизвестную группу.

TimeoutStopSec — бюджет ожидания менеджера, не обещание уничтожения всех
процессов. Slow drain, зависший kernel, abnormal master или orphan могут оставить
процессы; требуется явная проверка и только собственный bounded cleanup.
Не применяйте killall, общие rm или изменение чужих units. Journald может
содержать private paths/PIDs/runtime diagnostics; сырые логи в Git не публикуют.

## Открытые gates

Static verify и refusal tests не доказывают start/stop/restart/disconnect,
применение конфигурации, recovery, slow drain или TLS. В текущем проходе
readonly systemctl probe завершился exit0 в UID0 среде, однако user-mode
static verify отказал при инициализации с ENXIO. Эти наблюдения не подтверждают
работоспособность user manager или nonroot Ubuntu24.04/Node22 target acceptance;
unit не запускался. Прежние наблюдения сохраняются исторически. Downstream TLS, verified upstream CA/hostname,
автоматический readiness gate и реальный lifecycle требуют следующих проверок.
G2 permanent archive/published-file replay и Production V1 остаются открыты.


## Exact hosted recipe compatibility

Implementation `0daf4086` passed the required user-unit recipe tests and existing
native compatibility jobs on Node22 in both exact push/PR runs.
[Receipt](../evidence/g3-service-recipe-hosted.json) preserves actual artifacts,
identities and skips. This accepts generation/refusal compatibility only: no
service was installed or activated by those recipe tests. The local user-mode
static verifier ENXIO remains unresolved; system-mode parser success does not
accept a user-manager deployment. Manual bind and all runtime/TLS gates above
remain mandatory. Permanent alpha distribution and Production V1 remain open.


## Installed wait-bind helper: compatibility before automatic startup

New verified alpha installations provide `wait-bind --timeout-ms 10000`.
Use it explicitly with the recorded Node path and installed launcher after
starting native. It waits for startup and then performs one existing bind;
see [alpha limits](../alpha/README.md#installed-startup-wait-bind-g3-partial).
A timeout/cancellation during bind may leave a committed binding and must be
inspected. Health, identity and integrity refusals are not retried.

The current unit generator remains unchanged and has no ExecStartPost. The
helper's local/CI acceptance does not accept automatic systemd startup health:
that integration still requires actual manager cancellation/failure/cleanup and
nonroot target tests. Keep manual startup acceptance and the existing stop and
faulted/orphan rules until those gates are satisfied. No service is activated
by generating a unit or by these documentation changes.
