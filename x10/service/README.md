# X10: systemd user recipe и приёмочные fixtures

Для abnormal master exit, `faulted`, orphan workers или неизвестных locks
используйте [incident runbook](INCIDENT-RUNBOOK.md). Он сохраняет исходный
prefix на месте и различает безопасный отказ, условное восстановление из
прежнего подтверждённого HTTP backup и ещё не принятую полную recovery.
`info/status/history` не являются начальной диагностикой без записи locks;
`recover` не очищает faulted lifecycle. При неизвестном владении ресурсами
результат — `STOP_UNRESOLVED`, а не разрешение restart или uninstall.

Генератор recipe выдаёт предложенный unit и не запускает systemctl, не
устанавливает сервис, не меняет автозапуск или linger. Отдельный source helper
`lifecycle-check.mjs` проверяет временный сервис на разрешённом nonroot хосте;
его фактические результаты относятся только к точным проверенным исходникам.
Нативный data plane, alpha lifecycle и readiness-контракт сохраняются.

В этом документе сохранена хронология реализации и прежних отказов. Слова
«candidate» и «pending» в исторических разделах относятся к указанному там SHA;
актуальную точку продолжения задают [checkpoint](../continuum/BACKGROUND.json)
и [gates](../continuation-2026-10-24/GATES.json). Проверенный normal-service путь
с TLS, restart, journal и owned cleanup остаётся узкой приёмкой, не всем G3/V1.
[Exact receipt245](../evidence/g4-restored-http-hosted.json) отдельно принимает
восстановленный foreground HTTP fixture; восстановленный managed service требует
собственной фактической проверки ниже. TLS backup и package rollback не приняты.

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


## Ephemeral basic lifecycle checker

The source helper `lifecycle-check.mjs` is an acceptance harness for a fresh
authorized nonroot Linux test host. It is not installed in the alpha bundle
and does not deploy a permanent service. Supply the exact trusted archive
and checksum; the helper performs its own fresh readonly manager preflight
before service operations. Do not use sudo, switch accounts, create a
manager, change linger or alter security settings to turn a refusal into
success.

Run from the source checkout with the recorded Node executable:

```sh
node x10/service/lifecycle-check.mjs --archive accepted-alpha.tar.gz \
  --sha256 REPLACE_WITH_EXACT_64_LOWERCASE_HEX_SHA256
```

Use a trusted expected checksum obtained with the intended archive. A
checksum proves byte consistency, not an authenticated publisher signature.
The checker verifies bounded archive consistency before extraction. Both
relative and absolute archive paths are explicit inputs; runtime execution
uses the extracted installation rather than source-checkout alpha files.

The exact output contract and counts are recorded with the checker source
and [local evidence](../evidence/g3-service-lifecycle.json). Missing manager,
root execution, invalid input, a failed operation or incomplete cleanup must
remain an explicit nonzero result; refusal is not a passed service gate.

`actualUnitStarted:false` and `runtimeUnitLinked:false` mean those actions
were not confirmed. After a timeout or ambiguous mutation, false does not
prove nothing happened. Cleanup must requery the exact owned unit, link and
runtime identities. Only the actual local `nonroot_required` refusal in
preflight, before archive access or any mutation, establishes zero local
service actions.

The helper generates an unchanged guarded recipe for its private installation,
temporarily links only its unique runtime unit, and never enables it. It
uses explicit installed wait-bind after start: Type=exec/active proves process
execution, not native/application/TLS readiness. No ExecStartPost readiness
hook or automatic production startup acceptance is introduced. Basic stop
and a new service session are checked separately from the first startup.
This is a stop/start path, not the manager's single restart operation.
Each session checks an exact body,65551-byte upload echo and65537-byte stream.

Cleanup is limited to its own unit, exact installation/session identities,
processes and fixtures. If native cleanup cannot be confirmed, retain the
private prefix for diagnosis rather than deleting it or signalling unknown
processes. Do not issue killall or global systemctl reset-failed/restart.
Raw journald/native diagnostics can contain paths and process identifiers;
only allowlisted counts, hashes and fixed result codes belong in Git.

The49-test local authored suite includes one actual root-only refusal. On a
nonroot runner this case is explicitly skipped:49total/48PASS/1SKIP is
expected contract accounting. The separate actual service CLI step remains
mandatory; a skipped root test or refused prerequisite is not service PASS.

Local pure/refusal tests and root rejection do not prove live nonroot service
execution. Required exact CI must report actual fresh-host start/request/
explicit wait-bind and stop/start with a fresh session and owned cleanup before
that narrow lifecycle is accepted. Actual logging, the manager restart
operation, failed-start, cancellation, slow drain,
orphan recovery, operated TLS, package upgrade/rollback, permanent release/
replay, soak and Production V1 remain separate open gates.


## Exact basic lifecycle attempt: installation failed

Both actual mandatory CI service attempts for `0ade140e` failed at phase
`install` with fixed code `lifecycle_failed`; readonly nonroot manager
prerequisites passed. The sanitized result hides the underlying exception,
so no exact inspection/ACL guard or service repair is established by it.
The [receipt](../evidence/g3-service-lifecycle-hosted.json) retains preceding
compatibility PASS separately from the required service FAIL. Do not retry
unchanged CI blindly or weaken ownership/integrity checks to get past it.
Any bounded local install-only diagnosis and resulting source change need
independent review and exact new CI; no local UID0 result accepts a nonroot
manager/service. Start/link false flags are unconfirmed status generally,
not proof no ambiguous action occurred. Only exact control flow supports
the narrower pre-link inference here. Actual logging, restart, adverse
lifecycle, combined TLS, package recovery and Production V1 remain open.


## Bounded recipe-inspection diagnostics

The checker distinguishes a fixed recipe-inspection refusal from a generic
install failure and can report bounded allowlisted selected-Node prerequisite
booleans. These observations are diagnostic only. They cannot accept an
installation, replace the authoritative recipe inspector, or justify
copying/chmod/chowning Node to bypass its checks. Original ownership,
integrity, identity and admission guards remain mandatory.

An actual local UID0/Node24 install-only diagnostic found the selected Node
owner outside root/currentUID while30 other checks passed; the unchanged
inspector correctly refused. No manager, unit or serving native process ran.
Pack/install -V/config validation is separate from serving. This does not
identify the exact prior nonroot Node22 CI exception. The new diagnostic
source still requires exact hosted verification and actual service evidence.

The current diagnostic contract has67 tests locally, all passing. The
original49-test accounting above belongs to the preceding implementation.
On a nonroot runner the current root-only refusal case is expected to skip:
67total/66PASS/1SKIP. The separate real service command remains mandatory
and a refusal or skip does not accept the service lifecycle.


## Independently verified official Node dependency

The supported service recipe continues to refuse unsafe selected Node
ownership or modes. The current exact239 CI observed an unsatisfied mode
predicate with accepted ownership and refused before service activation.
Do not copy or chmod/chown that rejected global cache executable to obtain
a PASS. The caller supplies the separately authenticated official archive to the
new dependency tool, which prepares a new owned private prefix; all existing admission checks remain
mandatory for the installed service.

The exact Node version, archive hash/URL, public release key and signed
checksum statement are pinned in `node-runtime-pin.json` and `keys/`. A
version/key/pin update requires a separate provenance review and exact
archive/runtime verification; it is not a cosmetic metadata update. Public
PGP material is verification input, not a private key or login credential.
Signature verification and byte checks are separate from actual extraction,
Node execution, host ABI compatibility or service acceptance. No default
keyring, keyserver, new account or global security setting is involved.

The helper performs no network download. Its caller supplies the fixed
official archive; the required CI downloads only the pinned official URL.
The helper verifies the signed checksum statement and archive bytes before
preparing only the selected Node executable and its LICENSE. It never
materializes arbitrary archive links or modifies an existing cache.

The prefix parent must already be canonical, owned by the current UID and
private0700; the requested dependency prefix must not exist. Use explicit
absolute paths with the trusted bootstrap Node:

```sh
node x10/service/verified-node.mjs \
  --archive /absolute/private/node-v22.23.3-linux-x64.tar.xz \
  --prefix /absolute/private/dependencies/node22
```

The dependency must remain available while the service is running. Cleanup
requires the trusted coordinator to await the unchanged checker child and
record its actual successful service cleanup, together with the prepared
Node hash and installation identity. A fabricated JSON receipt is not
verification. The receipt is a same-UID procedural assertion, not an OS
process fence or protection from a malicious process with that UID.

```sh
node x10/service/verified-node.mjs --cleanup \
  --prefix /absolute/private/dependencies/node22 \
  --service-evidence /absolute/private/service-cleanup.json
```

On failed, cancelled, ambiguous or unconfirmed service cleanup, the
dependency is retained. Remove no unknown prefix and do not signal broad
process groups to force cleanup. The explicit cleanup command accepts only
its exact recorded owned files and identities.

Local validation has not downloaded or executed the official Node archive.
The required exact CI must verify real archive bytes and the prepared Node,
then invoke the unchanged service lifecycle checker with that Node. Unit
status or a successful preparer alone cannot accept application readiness,
service cleanup or Production V1. Keep owned dependency lifetime through
service stop/cleanup; remove only verified owned files and retain diagnostic
state on uncertain cleanup. Detailed invocation and actual evidence are
recorded with the helper and [checkpoint](../evidence/g3-verified-node.json).

Historical0ade install exception and local Node24 owner refusal remain
separate from the current Node22 mode-policy observation. Logging, single
manager restart, failed start, cancellation, slow drain, orphan recovery,
combined TLS/service, package rollback, permanent distribution/replay, soak
and final Production V1 remain open.


## Primary failure and bounded first-start diagnostics

A failed service attempt can fail again during cleanup. The top-level
compatibility result remains separate from an additive first primary
failure record and bounded cleanup failure observations. First-start
command outcomes and unit-state facts use fixed enums/booleans only; raw
errors, command output, unit paths, session IDs and PIDs are not published.
These diagnostics cannot confer service authority or replace any existing
unit/launcher/native identity, readiness or cleanup check.

`primaryFailure` is null or a fixed record with phase, subphase, code and
systemErrorClass. Its first captured primary is retained even if cleanup
fails later. `cleanupFailures` retains at most8 fixed stage/code entries;
its count saturates at32 and an explicit truncated flag marks missing later
entries. Missing entries do not prove an action or failure did not happen.

`startDiagnostics` records bounded function-entry attempts, progress and
at most8 fixed outcome/state observations, with count saturation32 and
explicit truncation. An attempt counts an entered checker function; it is
not proof a systemctl start command was issued or a unit physically started.
Command termination and unit state use fixed categories/presence booleans.
`systemErrorClass` classifies an observed own Error.code only: it does not
prove an OS syscall, kernel condition, ACL diagnosis or historical cause.

Both actual700 service attempts reported cleanup_unconfirmed at first_start
after a confirmed runtime link. The original error was overwritten by old
cleanup handling and is unknown. A false actualUnitStarted flag means an
unconfirmed start; it does not prove no physical start or no side effect.
All service cleanup flags were unconfirmed except application sockets0.
Keep the authenticated private Node runtime available for possible ExecStop
when cleanup is uncertain. No runtime deletion or final provider cleanup
is inferred from a failed child report.

The actual signed archive/private Node preparation succeeded narrowly in
those jobs and all seven Node policy predicates passed. That result does
not accept service startup, readiness, stop or complete Node/service profile
compatibility. The new diagnostics require their own exact CI; local pure/
synthetic tests and actual root refusal are separate evidence. Full service
operation, logging, manager restart, adverse cleanup, TLS, package rollback,
permanent distribution, soak and Production V1 remain open.


## Known owned fragment identity diagnostics

An authoritative manager property can name a fragment differently from the
expected unit-file string. A mismatch alone does not establish whether the
fragment is the known runtime link, an equivalent owned file or a different
file. The original loaded/unit-fragment guard remains mandatory.

Additional diagnostic match facts use fixed enums and booleans and refer
only to the already known owned unit and runtime-link paths. No raw path,
process identifier, file identity number, command output or exception is
published. These observations do not grant authority, allow an alias, alter
start or cleanup actions, or prove service absence and physical cleanup.
A manager-returned foreign path must not become a path to inspect.

Both prior exact7d1 jobs observed a loaded/inactive/dead unit with a present
fragment and refused unit_fragment_identity before the checker's own start
request. They did not expose actual paths or prove canonical equivalence.
Cleanup retained the same refusal code but no separate state snapshot; its
failed branch remains unknown. The private verified Node remains retained
when service cleanup is uncertain. Original700/0ade errors remain separate.

The new exact source requires its own actual nonroot CI. Local synthetic
contracts, original-path/runtime-link/foreign-path refusal controls and
independent review remain separate from service/Production V1 acceptance.


## Verified known owned fragment spelling

The service checker requires loaded state and exactly either the owned
unitFile path or the already known runtimeLink path. Unrelated paths are
refused before additional filesystem access; no manager-supplied path is
passed into a filesystem operation. This is a narrow identity admission
rule, not permission to trust arbitrary aliases.

For the exact runtime-link spelling only, the checker resolves the already
known owned unit and known link. The unit must be canonical and the link
must resolve to that exact owned unit. For both accepted spellings, every
original runtime-parent, symlink owner/target and unit owner/mode/content
hash check runs freshly again after the manager property response and
fragment verification. No device/inode/link-count policy or atomic OS fence
is added. Trusted same-UID operator limitations remain.

The bounded fragmentIdentityDiagnostics observation precedes this added
canonical verification. Its canonicalIdentity:not_measured describes the
pre-validation snapshot. It must not be interpreted as evidence that the
later check ran, failed, or was absent for the entire new service attempt.
The fixed diagnostics schema and privacy bounds remain unchanged.

Both original exactf434 service attempts showed loaded/runtime_link in
lifecycle and cleanup with preceding owned checks verified, but canonical
identity was not measured and the old strict spelling guard refused.
Cleanup remained unconfirmed and private Node was retained. This evidence
justifies testing the new known-owned equivalence rule; it does not accept
service operation. Local owned filesystem and synthetic manager controls
remain distinct from actual nonroot service CI, cleanup and Production V1.


## Explicit automatic startup readiness

The user-unit recipe has an explicit autoReadiness option. Missing or false
retains the previous generated unit bytes. When selected, an ExecStartPost
command invokes the pinned absolute Node and installed launcher wait-bind
with its fixed10000ms budget. The manager start transaction must complete
that installed command. The existing service ownership, identity, private
control, timeout and cleanup rules remain required. To select this rendered
recipe explicitly, append --auto-readiness to the existing user-unit CLI
--prefix and --node arguments.

The acceptance harness selects this option and no longer manually invokes
wait-bind after starting the service. It independently inspects the installed
bound session after successful manager start before native inventory, and
retains the original fresh later bound status check after native observation.
The readiness counter increments only at that original later check, before
the existing proxy/upload/stream and stop/cleanup checks. readinessAutomated is set when the
recipe is configured, before unit write, link or manager startup; automaticReadinessAccepted and full service
or Production V1 acceptance remain separate evidence-based decisions.

Both prior exactd119 jobs passed the narrower basic service fixture using
manual installed readiness, two separate start/stop sessions and full owned
service/private Node/bootstrap cleanup. This accepted basic path is not one
manager restart, logging, adverse startup/cancel/drain/orphan acceptance or
combined service TLS. The changed option requires its own exact actual
nonroot CI; local controls and source review alone do not prove it ran.

[systemd255 service semantics](https://github.com/systemd/systemd/blob/v255/man/systemd.service.xml)
allow startup to fail on a failed or timed-out ExecStartPost before the unit
is fully active; ExecStop can then be skipped. Actual failed-start and
cancellation cleanup require separate acceptance, and uncertain service
cleanup must retain the private Node needed by owned stop operations.


## Cleanup facts belong to the current attempt

The checker clears managerStopped, launcherExited, nativeGroupsAbsent,
listeningPortsClosed and controlSocketAbsent before every startAndServe
and stopOwned attempt. This includes stopOwned during finally cleanup.
A previous successful stop cannot confirm cleanup after a later start or
failed stop. False means current-attempt unconfirmed; it does not prove
that a resource is physically present. Existing checks alone can establish
new true values. Historical counters and the other cleanup fields retain
their original meanings.

Both prior exact1eb jobs completed their first automatic service cycle,
then failed the second manager start. Their five true flags came from the
first stop, while runtime-link/install/temp removal remained false and the
private Node was retained. Those original artifacts are preserved; they do
not prove final cleanup. The hook cause and failing inventory record are
unknown. This reporting change does not alter or repair service startup.

No manager or hook telemetry is added. Main-process exit metadata cannot
stand in for the post-start command result, and raw ExecStartPost records
must not be exposed. Further diagnosis needs bounded direct installed-hook
outcomes and an owned startup rendezvous, with unknown-state retention.
Actual repeated automatic lifecycle and final cleanup require exact new
CI; local freshness controls do not accept an actual service or V1.


## Bounded owned post-start record observations

The checker observes the already known owned unit ExecStartPost property
before attempting startup and after a failed manager start. Owned-unit and
link checks guard the bounded read before and after it. Parsing accepts only
the expected pinned installed Node, launcher and argv grammar. Public output
contains finite allowlisted classifications, never raw serialized records,
command/error output, process identifiers, start-time values or host paths.

hookStatusDiagnostics retains at most4 attempt/stage observations, with
explicit truncation. Unsupported, malformed, ambiguous, never-run and
incomplete records remain unknown. Accepted exited records expose only
a finite exitStatus0..255; signal records expose a fixed signal class.

recordChangedSincePreStart compares only the private PID/start-time tuple
and returns true, false or unknown. It does not compare the entire command
record or its outcome. It is not a fresh invocation ID or proof that
this attempt invoked, owns or observed completion of that hook. A matched
command record or changed process/time metadata does not confer authority.
Main-process exit metadata cannot substitute for the post-start command.

All property-query, parsing and diagnostic ownership-check failures are
best-effort unknown observations; they cannot replace the primary startup
error or cleanup result, authorize actions, or delete an uncertain runtime.
After the diagnostic await, normal full ownedProperties(false) checks run
again and require inactive state with MainPID0. This is a real admission
gate; its errors are not best-effort diagnostic failures. Cancellation is
then checked after that awaited revalidation and before manager start.
Cancellation while observing an already failed start must not overwrite that original unit_start_failed error. These added
authority/state and cancellation gates protect the new await window. Added
recheck queries suppress collector observations only; authority checks and
existing collector bounds remain required, as do normal mutating commands
and cleanup rules.

Accepted property text is limited to16384 bytes; the existing execFile
maxBuffer remains256KiB. Each complete observation has two owned property
queries plus one hook-property query, each with2500ms configured timeout.
Two pre-start observations, one failed-start observation and two mandatory
post-observation authority rechecks add up to11 manager queries and27.5s
summed configured timeouts in that flow. Filesystem work and scheduling
are additional; this is not measured latency or a hard wall-clock limit.


Both prior exactd697 runs completed one first automatic cycle, then failed
the second manager start. Their five cleanup confirmations were false,
correctly unconfirmed, and Node/bootstrap remained retained. Hook cause and
failing inventory record remain unknown. The new record observations are
diagnostics, not startup repair. Actual hook-query evidence and full repeated
automatic lifecycle require exact new CI; an owned installed-hook outcome or
rendezvous mechanism and complete service/V1 gates remain separate work.


## Prepare the startup session before automatic readiness

When autoReadiness is explicitly true, the generated unit first invokes the
pinned absolute Node and installed launcher prepare-run as ExecStartPre.
The existing ExecStart run and ExecStartPost wait-bind commands retain their
arguments. With the option absent or false, default unit bytes are unchanged.

Use a newly verified bundle that provides prepare-run. Older installed CLI
versions refuse the unknown command before ExecStart; default manual recipes
remain byte-compatible. The installed prepare-run command accepts no options. Under the existing
alpha lock it runs the same stopped/prepared session checks and last-confirmed
revision integrity checks already used by run. A stopped session advances to
a newly prepared session; an already prepared session is reused. Preparation
neither launches native code nor binds health. Its success therefore reports
nativeStarted:false and readinessChecked:false, not service readiness.

This ordering publishes the guarded session before run and wait-bind can race.
General wait-bind still refuses stopped/faulted sessions and changed registries;
it does not follow an arbitrary new session or retry a changed authority.
Existing runtime/dependency/lock/session limits remain required. Partial durable
writes need inspection; this adds no atomic rollback or same-UID process fence.

The deterministic baseline control exercises a possible early-hook ordering.
It does not establish that ordering as the cause of the previous hosted failure.
Both exact ee464 service workflows remained FAIL with unconfirmed final cleanup.
Their post-failure hook record showed exit1 with unknown freshness/invocation;
the semantic cause and actual failing cleanup inventory record remain unknown.
The new recipe and installed command require exact new nonroot CI before
repeated automatic startup or complete owned cleanup can be accepted.


## One manager restart and bounded owned journal observations

The actual service checker now extends the two-cycle baseline with one
systemctl restart while the second service session is active. Fresh owned
unit authority and cancellation are checked before the manager mutation.
The retired launcher and recorded native master/group must be observed gone,
and the replacement must establish a distinct session and current binding
before its readiness/proxy/upload/stream checks can count as complete.
A stop followed by start is not substituted for this manager restart.

Journal verification reads only already-readable records with three exact
conjunctive UID, private user-unit and current-invocation field matches.
It adds no ACL/group/configuration changes or unfiltered fallback. Records must have matching
attribution and include a recognized launcher
marker; malformed, foreign, missing, over-limit or timed-out output refuses.
Raw journal records, messages, invocation IDs, process IDs, host paths,
timestamps and sensitive fingerprints are not published. Private invocation
values are observation inputs, not an OS fence against another same-UID
process or evidence of complete audit-history coverage. Journal metadata
can be cached and stale; the caller revalidates live authority around reads.

The Node cleanup receipt requires the exact new checker profile and complete
owned cleanup. A timeout, incomplete replacement, uncertain old-process exit,
missing journal proof or unconfirmed cleanup retains the runtime needed for
safe inspection. This does not introduce forced cleanup or persistent units.

Both exact401209 workflows had already passed two automatic basic sessions
and complete service/private Node cleanup. That narrow result remains
separate from this new restart/journal implementation, whose exact resulting
nonroot CI must still be reconciled. Earlier startup failures and unknown
historical causes are retained; later success does not reconstruct them.
Full G3, adverse paths, combined service/TLS, package rollback/recovery,
permanent distribution, security/soak and Production V1 remain open.

Local post-pin verification passed333 contract tests:246 lifecycle,36 journal
and51 cleanup-receipt controls, separately from191 independent source proofs.
These are not actual manager restarts or target-host acceptance. New exact
nonroot CI must establish the changed operational path and complete owned cleanup.


## Journal formatter sequence metadata compatibility

The bounded journal parser now recognizes the optional __SEQNUM and
__SEQNUM_ID metadata names emitted automatically by the public systemd255
JSON formatter. They use the same existing scalar metadata shape/bounds
checks and remain ignored private formatting data. Required UID/user-unit/
invocation/message attribution, duplicate and unknown-field refusals, raw
record privacy, query arguments, retry limits and live authority checks are
unchanged. The entire module restores its baseline by removing only these
two literal names. No checker pin or workflow adjustment is part of this fix.

Before the edit, a fixed synthetic attributed running transcript containing
all six standard formatter metadata fields refused journal_response_invalid.
The candidate accepts that transcript while preserving malformed/foreign/
unknown/oversized controls. The actual rejected raw record from earlier CI
was not captured: this counterexample does not establish which field or
condition caused either historical journal refusal.

Both exacta03 native workflows failed at first_start/journal_read after one
observed startup/readiness/proxy/upload/stream pass, before any restart or
journal acceptance. Six process/socket/link cleanup confirmations and unit
removal were true; installation and temporary roots were retained. No cleanup
failure was recorded. Private Node/bootstrap were retained with no dependency
cleanup receipt. Earlier401209 two-cycle success remains separately scoped.
New exact CI must verify the parser with real journal/restart/cleanup evidence;
Production V1, full G3, adverse recovery and package/release gates remain open.


## Partial downstream HTTPS with a real operated service

This bounded acceptance milestone exercises downstream HTTPS on the real
nonroot operated gateway while its application origin remains HTTP. The
unchanged release contract and profile require both downstream HTTPS and a
verified HTTPS origin. This milestone therefore remains partial and cannot
accept the full TLS service, G3 or Production V1. Neither contract nor profile
is narrowed to relabel this intermediate result as complete.

The candidate fixture prepares private test PKI and a high loopback HTTPS
listener using existing installed management. It must exercise successful
CA/hostname verification with exact payload exchange and explicit wrong-CA
and wrong-host refusal across the three-session/one-manager-restart path.
Trust verification must remain enabled; a successful TCP connection or a
certificate file alone is not an accepted TLS exchange.

The acceptance path retains exact unit/launcher/native identities, fresh
replacement session/binding and bounded journal checks. Dependency cleanup
requires the exact new TLS proof profile, closed owned TLS listener and
confirmed private fixture/service/runtime cleanup. Unknown resource ownership
or incomplete cleanup retains evidence and the runtime needed for inspection.
Raw certificates/keys, runtime logs, process identities and host paths stay
private; public evidence contains finite results and allowed counts/hashes.

Exact06e4 had already passed the HTTP-only three-session manager-restart and
journal path with complete owned cleanup. That narrow result does not accept
this new downstream HTTPS path or the unchanged contract's combined TLS legs.
New exact nonroot CI is required. Earlier a03 raw journal rejection remains
unknown and preserved in history despite later scoped success.


Local post-pin verification passed384 contracts:267 lifecycle,45 journal,
16 TLS fixture and56 dependency controls, with no skips/failures and empty
stderr. Independent review recorded135 separately classified proofs.
The16 helper tests mix real owned Node HTTPS/PKI and synthetic event controls;
they are not16 service installations. A stronger late-callback control first
failed15PASS/1FAIL on duplicate cleanup; settled guards then passed16/16.
No late promise success or managed-service failure was observed in that test.

The required managed-service counters are three HTTPS sessions. Per session,
one TLS1.2 and one TLS1.3 GET give six body checks and three version-specific
GET checks per protocol. Three uploads and three streams use TLS1.3, producing
12 verified positive certificate requests in total. Wrong-CA and wrong-host
refusals are three each. These are distinct observation units, not counts of
all handshakes or independent deployment scenarios. Actual service evidence
requires the new exact nonroot CI; full both-leg TLS remains open.


## Combined HTTPS-origin service candidate; exact CI pending

Prior exact1e6 push and PR native workflows passed the scoped downstream HTTPS service with HTTP
origin. Each observed three TLS sessions, one real manager restart, three attributable journals,
twelve verified positive certificate requests and three wrong-CA plus three wrong-name refusals.
All nine service cleanup confirmations, private Node/bootstrap removal and zero remaining
application sockets were observed. These are distinct request/session units, not twelve
installations. Earlier HTTP-only06e4 acceptance and a03 unknown raw journal rejection remain
unchanged in history.

The new local candidate combines downstream HTTPS with a verified HTTPS origin. Its owned relay
queries regular native HTTP /ready with an immutable per-candidate marker; it neither borrows
direct-origin readiness nor native management self-health. Tags correlate the candidate input;
they are not authentication, all-worker fencing or atomic cutover. Ordinary application traffic
remains native NGINX. Existing release contract/profile, TLS helper,
native/controller/alpha/recipe/preflight/journal sources are unchanged.

Actual local combined tests:474/474 PASS, zero FAIL/SKIP/cancel/TODO and empty stderr:328
lifecycle,45 journal,16 unchanged downstream TLS helper,23 new origin helper,62 dependency
receipt controls. Independent review passed229 bounded controls:45 real owned Node origin
TLS/fake-native relay,107 extracted harness,13 lifetime and64 boundary/receipt controls. Root
checked10 source/pin/contract conditions and7 workflow conditions;518 other protected files were
byte-identical. Proof units are separate from test counts and do not count installations.

The managed-service candidate requires three distinct combined origin body/upload/stream
sessions. Three separate bad upstream CA/name/plaintext candidates each require independent
good-origin reachability, exact installed rollback, fresh candidate-tag native502, restored HTTP
and downstream HTTPS payloads, and zero application POST replay. One direct-origin counter is
the initial check; downstream twelve positive certificate requests exclude three additional
restored-path probes. Four extra origin/relay server-and-port cleanup booleans augment prior
cleanup guards. Direct helper exact-leaf checks do not claim native leaf pinning.

Two initial test assertions failed and remain recorded:the harness expected object omitted
origin_negative, and the missing-marker test helper defaulted undefined to a valid marker.
Corrections changed test expectations/inputs without changing runtime admission. Final
harness328/helper23 passed. A separate read-only unchanged-file inventory refused the already
edited coordinator workflow; corrected518-file scope excludes it. These observations do not
identify any historical managed-runtime failure cause.

Local Node24 UID0 fixtures, pure contracts and source-extracted controls do not accept actual
Node22 nonroot managed combined TLS. Exact resulting CI is pending and may fail. Require
complete owned origin/downstream TLS/relay/PKI/service/private Node cleanup. Same-UID trust and
user-space timeout limits remain; no complete secret-erasure claim. Full G3, adverse
startup/drain/recovery, separate config/package rollback, permanent distribution, independent
release acceptance,60-minute soak and Production V1 remain open. Deferred Continuum and full
native roadmap remain preserved.


## Unhealthy startup refusal and guarded recovery candidate

Prior exact dd6c push40185635547 and PR40185637960 native workflows completed
success with all31 required actual steps. Each observed three combined downstream
HTTPS and verified HTTPS-origin sessions, one manager restart, three attributable
journal checks, bad upstream CA/name/plaintext refusal with rollback and all13
owned service cleanup confirmations. Private Node/bootstrap removal was also
confirmed. Fresh review reused approved archives and passed80 separate proofs;
research PR actually ran21/7/27/48 while push runtime was skipped. No unchanged
runtime rerun was requested. This accepts the scoped prior path, not full G3/V1.

The new acceptance candidate deliberately refuses startup while its owned HTTP
application returns503 for readiness. It first holds the owned health response
long enough to capture the activating unit, launcher/native session, invocation
and post-hook identity. After explicit refusal, acceptance requires exact manager
exit1/failed exit-code and known current post-hook exited1. A timeout, signal,
foreign/stale identity, malformed record or missing observation cannot substitute.
Observed503 and hook exit1 do not exclude every possible internal failure cause.
Captured values remain private; published output uses bounded counts and booleans.

Before the application becomes healthy, the checker requires no binding or pending
transaction, a stopped captured session, exited owned launcher, absent native
groups and closed gateway/health/control resources. Only that exact hash/owner/link
verified failed unit may be reset after a final absence check. The first healthy
start must use fresh session, invocation and launcher identities. The failed
session is retained in cleanup inventory and is not one of the three successful
TLS/readiness/I/O sessions. No broad reset, direct kill or manager-setting change
is added. The normal combined TLS/restart/journal/final cleanup path remains.

The narrow report requires failedStartChecks1 and all11 failedStartProof booleans.
Strict dependency cleanup rejects prior/missing/partial proof receipts and retains
private runtime on unknown outcomes. Broad failedStartAccepted, serviceAccepted
and productionAccepted remain false. Source hashes, final actual local counts,
separate independent reviews and any adverse drafts are in
[failed-start evidence](../evidence/g3-service-failed-start.json).

Local root contracts and source-extracted controls do not execute the nonroot
managed service. Exact resulting CI is pending and may fail. Native, controller,
alpha, unit recipe, release contract/profile and prior TLS/journal helpers are
unchanged. Same-UID trust, user-space timeouts and PID-to-signal limits remain.
Prior a03 raw journal rejection cause and older failure interleavings are still
unknown; later success does not explain them. Full adverse startup/cancel/drain/
orphan recovery, package upgrade/rollback/backup restore, permanent distribution,
security acceptance,60-minute soak and Production V1 remain open. Deferred
Continuum and the full native roadmap are preserved.


## Controlled held-response graceful-stop candidate

Both exact13d native workflows completed success with all31 required actual steps.
Each observed one deliberate unhealthy readiness startup refusal, all11 owned
failure/retirement/recovery proofs and a fresh healthy start. The three normal
combined downstream HTTPS and verified HTTPS-origin sessions, one manager
restart, three attributable journal checks and all13 final cleanup confirmations
also passed, with private Node/bootstrap removal. Fresh82-proof review reused
approved archives and logs. Research PR actually ran21/7/27/48; push runtime was
skipped. These are separate observation units, not four accepted installations.
The broad failed-start and complete G3/V1 contracts remain unaccepted.

The new candidate starts one controlled held response on the owned HTTPS origin
and pauses a verified downstream TLS client after its initial response bytes.
Within the same third healthy service session, it captures owned unit, session,
invocation, launcher and native identities, then issues one manager stop. Before
release, it must observe that command pending, the exact unit deactivating, the
owned native group still live and the response incomplete. These observations
must bracket the same identities; stale or unrelated processes grant no authority.

Only then may the origin release its held suffix and the client resume. The full
response must complete with exact payload and verified downstream TLS, followed
by completed manager stop and fresh absence of captured launcher/native groups,
gateway/health/TLS ports and the control socket. Cancellation, timeout, premature
close, payload mismatch, foreign/stale identity or unknown cleanup must fail
closed and retain private runtime. All previous startup-refusal, combined TLS,
restart/journal, callback lifetime and final cleanup guards remain required.

A report requires controlledSlowDrainChecks1 and all14 narrow proof booleans.
The dependency cleanup profile refuses old, missing or partial drain evidence.
Final source hashes, actual local test counts, independent review and preserved
adverse drafts are recorded in
[slow-drain evidence](../evidence/g3-service-slow-drain.json).

This is a controlled held-origin response and paused-client graceful-stop check.
It does not establish pure network backpressure, every slow-client/drain case,
slow upload, abnormal/orphan recovery, resource/performance acceptance or the
predeclared60-minute soak. Broad slowDrainAccepted, serviceAccepted and
productionAccepted remain false. Local Node contracts/loopback helpers and
source-extracted checks do not execute the actual nonroot managed native service;
exact resulting CI is pending and may fail.

Native/controller/alpha, unit recipe, journal/downstream TLS helper and release
contract/profile remain unchanged. Same-UID trust, user-space timeout limits and
PID-to-signal races remain explicit. Earlier adverse evidence and unknown raw
historical causes are preserved. Distinct package upgrade/rollback/backup restore,
permanent distribution, independent release acceptance, full G3/V1 and semantic
Continuum remain open; the next portfolio project remains waiting.


## Controlled APPLY interruption and explicit recovery candidate

Both exactf9 native workflows completed success with all32 required actual steps.
Each observed one controlled held-HTTPS-origin response and paused verified-TLS
client graceful stop, all14 narrow drain proofs and exact payload completion.
The prior startup refusal/all11 proofs, three healthy combined TLS sessions, one
manager restart, three attributable journal checks and all13 final cleanup
confirmations also passed, including private Node/bootstrap removal. Fresh86-proof
review reused approved archives and logs; research PR actually ran21/7/27/48,
while push runtime was skipped. These scoped observations do not accept every
slow-client state, network backpressure, recovery failure or Production V1.

The new candidate interrupts one installed APPLY CLI while a unique candidate's
native readiness probe is held and its durable transaction is reload_requested.
Before signalling, it must match the fresh current last-confirmed revision,
candidate/input/fragment/history relation, service/native/session/invocation and
the two exact owned operator processes plus their two captured lock inodes.
Only the captured operator process group receives SIGTERM; the service continues.
A timeout or broad process search is not accepted as confirmed interruption.

Both stale locks must remain after those operators exit. Installed recover must
first refuse alpha_locked without changing the transaction. The test helper then
models the existing documented trusted-operator manual-inspection step: after
confirming the recorded lock owners and their process group absent, remove only
the same two inspected fixture-owned lock inodes. This helper action is confined
to its disposable installation; no installed automatic lock-reaping API is added.
An unknown, replaced, foreign or still-owned lock must remain untouched.

Explicit installed recover must return exit1/rolled_back/explicit_recovery with
the expected candidate/previous-revision relation, clear pending and restore
exact HTTP and verified HTTPS content. The same live owned service/session/
invocation must remain, application POST counts must not advance, and repeated
recover must return nothing_pending. A report requires operatorInterruptionChecks1
and all14 narrow operatorInterruptionProof booleans; strict dependency cleanup
must refuse prior, missing or partial interruption receipts. Previous failed-start,
controlled drain, combined TLS/restart/journal and final cleanup guards remain.
Final hashes, actual local counts, independent reviews and adverse drafts are in
[interruption evidence](../evidence/g3-service-operator-interruption.json).

This is one controlled APPLY-CLI interruption and explicit recovery scenario.
It does not establish automatic production stale-lock cleanup, all crash/storage/
orphan states, binary/package rollback, all-traffic atomic cutover or reversal
of application side effects. Local root contracts and loopback/helper checks do
not execute the actual nonroot managed native service; exact resulting CI remains
pending and may fail. Broad operatorInterruptionAccepted, serviceAccepted and
productionAccepted remain false.

Native/controller/alpha, unit recipe, prior slow-client/journal/downstream TLS
helpers and release contract/profile remain unchanged. The manual-inspection
rules in alpha/control documentation still apply to real operators. Same-UID
trust, user-space timeout limits and PID-to-signal races remain explicit. Earlier
adverse evidence, unknown historical causes and the prior expired-lease safe
resume record are preserved. Full G3/V1, abnormal/orphan recovery, distinct package
upgrade/rollback/backup restore, permanent distribution, independent release
acceptance,60-minute soak and semantic Continuum remain open.


A local process-fixture draft timed out because its PID namespace and mounted
/proc view differ. Some own private fixture prefixes were removed before process
absence was proven; old cleanup remains FAIL/UNKNOWN. The final helper refuses
this profile before any spawn. Nine physical group cases are SKIP locally, not
PASS; exact supported-host CI must run all18 without skips. No namespace entry,
host-PID signals or permission changes were used. Later CI success cannot erase
this earlier local cleanup uncertainty.


## Interruption failure diagnostics and owned-fixture containment candidate

Exact3bf native CI had mixed actual outcomes. Push40209963590/job121218936536
FAILED required service step28 during operator_interruption: the primary failure
was operator_fixture_not_held after the first four of14 interruption proofs.
Cleanup separately recorded unit_stop_unconfirmed; nine final cleanup flags
remained unconfirmed, no private Node cleanup receipt existed and bootstrap
retained its runtime/root. False flags mean unconfirmed, not observed presence.
PR40209966500/job121218941776 passed its scoped operator recovery, controlled
drain, startup refusal, three combined TLS sessions, restart/journals and13 final
cleanup confirmations with private Node/bootstrap removal. Both actual operator
suites ran18 tests without skips. The implementation is not accepted by the PR
success. The92 factual audit checks reconcile observations, not92 runtime passes.

Research PR actually ran21/7/27/48 while push runtime was skipped. Those separate
passes do not override native service failure. Earlier local operator fixture
cleanup remains FAIL_UNKNOWN, including the previously recorded prematurely
removed private prefixes; later hosted evidence cannot repair that uncertainty.
The exact historical not-held interleaving/internal cause remains unknown.

The new candidate adds bounded, finite interruption-step/guard observations and
failed-fixture containment. Diagnostics publish no raw paths, process identifiers,
command output, private pending/configuration bytes or secrets and grant no
lifecycle authority. The existing1000ms held-probe and350ms hook budgets remain;
no timeout extension or same-SHA rerun is used to relabel the failed result.

Failure containment must stay within the already captured owned operator group,
exact captured lock inodes, immutable pending/input identity, original deadline
and current process-absence guards. It cannot rearm a refused capability, acquire
candidate acceptance, blindly clear foreign/stale locks or replace the original
primary error with successful cleanup. Any explicit fixture recovery remains
separate from runtime acceptance. Unknown cleanup retains the installation and
private dependency. The new refusal/containment controls and final frozen hashes,
actual local results and independent review are in
[containment evidence](../evidence/g3-service-interruption-containment.json).

The original push failure and scoped PR success remain separate durable records.
New exact CI is pending and must run all26 operator controls with zero skips.
No actual nonroot managed service is run by
local root contracts or source-extracted controls. Prior startup/drain/TLS/
restart/journal guards, every existing acceptance proof and namespace refusal
remain required. This candidate does not establish the historical not-held cause,
a general automatic lock cleaner, production crash recovery or package rollback.

Native/controller/alpha, unit recipe, origin/slow-client/journal/downstream TLS
helpers, release contract/profile and the broad roadmap remain unchanged.
Installed service-recipe distribution is parked until the current required
service failure is understood and accepted runtime evidence is available.
FullG3/G4-G8, permanent release, security/soak, Production V1 and semantic
Continuum remain unaccepted. No other portfolio project is started.


A normal hosted interruption PASS does not prove the separate failure-containment
branch ran. New receipts must retain its attempted/completed disposition and the
first finite hold refusal. If that branch was not exercised, actual managed
failure-containment acceptance remains pending despite passing normal controls.


## Fresh native-route held challenge candidate; exact CI pending

Exactc1cf native CI again had mixed actual outcomes. Push40212661367 completed
its normal scoped service path with all14 operator proofs, controlled drain,
startup refusal, three combined TLS sessions, restart/journals and13 cleanup
confirmations plus private Node/bootstrap removal. PR40212664983 failed the
normal interruption path after the first4 proofs. Its finite first refusal was
terminate_capture/live_probe_gap at347ms with deadlineExpired:false. The primary
operator_fixture_not_held remained unchanged. This does not prove the earlier
3bf failure had the same timing or identify every internal cause.

The PR did execute strict failure containment: all7 containment booleans were
true, disposition contained,11 owned cleanup facts and runtime-unit removal
confirmed, cleanupFailures empty. Installation/temp roots and private Node/
bootstrap were retained; this is scoped containment evidence, not normal-profile
or complete-cleanup acceptance. Both operator26 and failure-QA100 controls passed
without skips. Research PR ran21/7/27/48; push runtime was skipped. Fresh60 factual
audit checks preserve these outcomes separately and do not accept allc1cf.
Earlier3bf pushFAIL/PR scopedPASS and local fixture cleanup FAIL_UNKNOWN remain.

The new candidate requires a runner-owned fresh one-use nonce challenge through
the actual native candidate route. It must bind the response to the current
candidate tag, held request and service/native/pending authority, then reobserve
that authority before signalling. Direct-origin readiness, cached relay state,
a retained sourceHeld Boolean or a response from another candidate/nonce must
not substitute. Nonces and raw response/identity values remain private; public
evidence contains only allowlisted counters, booleans and source bindings.

Normal interruption acceptance additionally requires operatorNativeChallengeChecks1
and exactly6 true operatorNativeChallengeProof fields: nativeRouteObserved,
ownedRequestObserved, relayResponseMatched, candidateBindingMatched,
authorityReobservedBeforeSignal and ownedChallengeClosed. These augment all14
existing operator proofs in strict dependency cleanup receipts. A failed or
contained attempt cannot increment that successful counter or obtain challenge
acceptance. The1000ms hold,350ms hook,8s fixture and original10s operator helper
budgets remain unchanged. Strict captured-only containment, cancellation,
primary-error preservation and every older admission guard remain mandatory.
Final actual local results, source bindings, reviews and adverse drafts are in
[native challenge evidence](../evidence/g3-service-native-held-challenge.json).

This is freshness evidence for an application/service acceptance fixture. It is
not authentication, malicious same-UID isolation, OS fencing or a Continuum/TLS
state-transfer result. Wrong/stale/replayed nonce, wrong candidate, timeout,
malformed response, closed challenge or lost current authority must fail closed.
The new actual nonroot service CI is pending and may fail; local root contracts,
Node loopback helpers and source-extracted controls cannot accept it.

The operator process helper/test, native/controller/alpha, unit recipe, prior
slow-client/journal/downstream TLS helper and release contract/profile stay
unchanged. Earlier3bf failure and old local FAIL_UNKNOWN are not retroactively
repaired. Installed recipe distribution remains parked until required service
acceptance; fullG3/G4-G8/V1, package rollback, permanent distribution,60-minute
soak and semantic Continuum remain open.


## Native challenge admission and early-failure containment; exact CI pending

Exact0420287 native results remain mixed. Push40215886529 completed its scoped
native challenge, operator recovery, startup refusal, controlled drain, TLS,
restart/journals and complete owned cleanup. PR40215890093 failed before initial
ownership capture with primary origin_challenge_identity and final
cleanup_unconfirmed/unit_stop_unconfirmed. Its containment was no_snapshot;
all six challenge and fourteen operator proofs stayed false. The exact rejected
historical admission predicate is unknown. Fresh51 factual readback checks do
not turn this mixed result into acceptance. Research PR ran21/7/27/48; research
push runtime was skipped. Earlierc1cf scoped containment,3bf mixed outcomes and
local cleanup FAIL_UNKNOWN remain preserved.

This candidate records bounded first-refusal admission stages/reasons, status
classes, matched-field booleans and bounded counters without nonce/tag/header,
body, route, port, PID or raw-error values. Diagnostics cannot grant authority.
Accepted records admission history; after cleanup,
currentPairLive is false and cannot authorize any later action.
Cleanup ownership and the pending snapshot are captured before challenge open,
using only a current stage-restricted initial held probe. Acceptance interruption
still requires the owned current native challenge at both termination stages;
there is no legacy fallback for the acceptance signal. Failed admission keeps
its primary failure and can use only the original strictly captured cleanup
snapshot. Full pending and same-service identity are reread after awaited open.
A late callback, stale identity or expired deadline cannot revive it.

All14 operator and six challenge proofs, strict cleanup receipts and original
1000ms/350ms/8s/original10s budgets remain required. Native/controller/alpha,
operator process helper/test, unit recipe and release contract/profile stay
unchanged. Local contracts and Node bridge controls do not execute the actual
supported nonroot managed native service. Final frozen local integration846/846 passed with zero
skips/failures.
Exact resulting CI remains pending.
See [admission evidence](../evidence/g3-service-challenge-admission.json) for
frozen source bindings, actual local counts, review and adverse draft history.

Installed recipe distribution remains next after required current service
acceptance. FullG3/G4-G8/V1, package rollback, permanent release,60-minute soak
and semantic Continuum remain open. No production or deployment change is
performed by this fixture checkpoint.

The prior lease expired while tree creation was pending. That tree remained
unpublished: no implementation commit or implementation ref update occurred.
This checkpoint resumes from fresh ownership with identical source bytes and
fresh root verification; the original owner work window is unchanged.


## Installed service recipe candidate; exact native service CI pending

Generate the automatic-readiness recipe from a schema2 installation:

```sh
/path/to/node /path/to/install/bin/x10 service-unit --auto-readiness
```

The command emits JSON. Read its unit string as the proposed unit content;
activationPerformed remains false. Omit --auto-readiness for the manual recipe.
These paths are placeholders for the exact recorded Node and installation.
Installing/starting that unit is a separate explicit operator action described
by the existing service workflow; generating a recipe does not accept a service.

Exact89aa native push40265731122 and PR40265734847 completed all34 actual
required steps each. Both passed the scoped normal native challenge/operator
recovery path with all6 challenge/all14 operator proofs, controlled drain,
startup refusal, three combined TLS sessions, restart/journals and all13 cleanup
facts plus private Node/bootstrap removal. Failure containment was not_needed;
its actual failure branch remains unexercised. Final admission diagnostics show
accepted history after closure, not current signal authority. Research PR ran
21/7/27/48; push runtime was skipped. Inherited CLA failure remains unbypassed.
This accepts the scoped89 implementation, not fullG3 or Production V1. Older
mixed failures, unknown historical causes and local cleanup FAIL_UNKNOWN stay.

This candidate adds an immutable service recipe helper to exact schema2 bundle
and install inventories. The installed service-unit command validates the full
installation and recorded Node identity before importing that helper. It prints
structured JSON whose unit field contains the generated unit; it writes no
unit file and performs no linking, enablement, manager start or activation.
The actual service harness obtains its recipe from installed payload, with no
source-checkout fallback. Existing manual/automatic rendered unit bytes remain
unchanged; helper validation and distribution runtime do change.

Strict cleanup receipts now additionally require bundleSchemaVersion2,
installSchemaVersion2 and installedRecipeGenerated:true. These augment all six
challenge/fourteen operator/startup/drain/TLS/restart/journal/cleanup obligations;
they do not substitute for them. An emitted field is not proof until the actual
installed payload is strictly verified. Exact resulting native service CI is
pending; local contracts cannot accept that supported nonroot operated service.
Final frozen local contracts1017/1017 passed; separately selected alpha14/14
passed. Older physical alpha groups were filtered and not run. Native aggregate
and actual managed service were not executed locally. See evidence for units.

Legacy schema1 packages retain their existing commands and source recipe path.
Their original package bytes do not acquire the new installed service-unit
command. The new CLI reading a valid legacy manifest refuses that new command
as service_recipe_unavailable. Exact v1/v2 inventories are selected by declared
schema; mixed or partial helpers, unknown files and mode/link drift are refused.
No in-place conversion, package upgrade/rollback or G4 migration is claimed.
FullG3/G4-G8/V1, permanent distribution, independent published-file acceptance,
60-minute soak and semantic Continuum remain open.

See [installed recipe evidence](../evidence/g3-service-installed-recipe.json).


## Recipe Node fixture prerequisite; product runtime unchanged

Exact195a native push40268333912 and PR40268338245 both failed step20:
19/20 native groups and full alpha76 TAP tests,74PASS/2FAIL. The extracted-bundle
recipe subtest and its parent reflect one nested service_recipe_invalid refusal
at the exact recorded-Node guard. The individual path/version/owner/mode/hash
comparison was not recorded and remains unknown. Selected new controls passing
did not override this full-profile failure. Managed service step29 was skipped;
service/package/archive/bootstrap/Node cleanup reports were absent. Missing
reports do not establish successful actual service execution or cleanup.
Research PR ran21/7/27/48, push runtime was skipped and CLA failure remains.
Prior89 scoped normal native challenge/operator acceptance remains unchanged;
its actual failure containment was unexercised. All older adverse history and
local cleanup FAIL_UNKNOWN remain preserved.

This candidate changes only the alpha test fixture. The checked-bundle path and
synthetic positive recipe fixture share a private owned0500 exact Node copy;
installation records that runtime and recipe generation executes the same copy.
The host executable is not chmoded, replaced or adopted as owned fixture data.
This satisfies the fixture prerequisite without relaxing product validation.
The local observation motivates the fixture change; it does not identify the
specific unrecorded comparison in the historical195 CI refusal.

CLI/helper/archive verifier, actual-service harness, strict cleanup receipts,
workflow and all native/controller runtime bytes remain unchanged. Schema2
inventories and required bundleSchemaVersion2/installSchemaVersion2/
installedRecipeGenerated:true facts remain mandatory, together with all prior
challenge/operator/startup/drain/TLS/restart/journal/cleanup proofs. The actual
new full native/alpha profile and installed-payload managed service CI remain
pending. Local selected16/16 passed with actual exit0; older physical groups and
unchanged runtime contracts were not rerun. These selected fixture controls
cannot accept the full native/service path or erase the195 failure.
FullG3/G4-G8/V1, package lifecycle, permanent release, independent published-file
acceptance,60-minute soak and semantic Continuum remain open.

See [fixture evidence](../evidence/g3-service-recipe-node.json).


## Restored HTTP managed-service candidate — 27 October 2026

The next acceptance fixture uses a stopped, confirmed HTTP service as its
declarative source. It runs before the existing downstream HTTPS change:
the backup contract still refuses an HTTPS input and never exports TLS keys.
The original owned unit must be stopped and retired before a restored service
can reuse the declared ports. The original installation and its records remain
available until target cleanup and the final preservation check.

The installed backup and extracted-bundle restore commands create a different
private installation with fresh installation, session and controller revision
identities. Before startup, the target must have a null binding and its own
single initialized history record. It cannot borrow the source binding, unit,
session, process or history. The exact confirmed HTTP input and declared ports
are retained; no automatic port or external-file remapping is introduced.

The harness obtains the new unit recipe from the restored installed payload.
It links only a new unique runtime unit and leaves it disabled. Automatic
readiness, exact application GET, upload and stream checks must pass on the
restored target. One immediate manager restart must establish another fresh
session and invocation and confirm retirement of the preceding owned processes.
Application POST counts must distinguish delivery from management-command
replay. The existing combined TLS, startup-refusal, interruption, held-response
drain, restart, journal and owned-cleanup obligations remain required afterward
on the restored installation.

A complete candidate report requires five native sessions with matching
readiness/body/upload/stream counts, two manager restarts and six attributable
journal checks. `journalChecks` counts completed checks; each bounded journal
read may issue one to three journalctl queries. Six checks do not mean exactly
six queries. The three combined TLS session observations retain their prior
meaning and count. `restoredHTTPChecks` must equal1 and `restoredHTTPProof`
requires all seven preparation and eleven operated-service/preservation/cleanup
observations. Missing or false proofs cannot accept the path. These are required
observation units, not results inferred from this document or independent installs.

Target stop and native/launcher absence must be confirmed before uninstall.
Exact runtime-link removal and manager readback, both installation removals
and all other cleanup must pass before deleting the temporary root or shared
verified Node dependency. The preservation check compares six selected current
source records: manifest, session registry, current lifecycle, controller state,
history and current revision. Those records, the backup and supplied archive
must remain unchanged before original-source uninstall; this does not inspect
every historical source file. An ambiguous stop, identity mismatch, replaced
link, failed cleanup or cancellation remains a failure and retains diagnostic
state. Cleanup never signals a broad process search or removes unknown units.
Private paths, process/session identities, configuration, backup contents and
raw journal output stay out of public evidence.

The [candidate evidence](../evidence/g4-restored-service.json) records authored
code, frozen source bindings and actual local pure/source controls separately
from exact hosted execution. This local nested PID environment must not run the
physical native, signal, process-group or systemd fixture. Pure controls and
successful parsing do not establish an operated restored service; actual new
supported-host CI is pending and may fail.

Final local selected contracts passed802/802 with zero failures, skips or TODOs
on Node24.22.1. That aggregate includes the84 new controls once:64 pure related-
record controls and20 virtual-I/O controls extracted from the actual functions.
Fourteen independent review controls are separate and are not added to802.
These checks do not execute the supported Node22 managed-service profile.

This is HTTP configuration restore within the same checked package. It does
not establish a transition between meaningfully distinct runtime packages,
TLS-key/PKI restore, application-data/database recovery, arbitrary external-file
portability, automatic stale-lock/orphan recovery or an OS process fence.
Full G3/G4-G8, permanent release, independent published-file replay, security
acceptance, the predeclared60-minute soak and Production V1 remain open.
The earlier mixed CI outcomes, unknown historical causes and local cleanup
FAIL_UNKNOWN remain preserved; later success cannot retroactively repair them.


## Exact restored HTTP managed-service acceptance — 27 October 2026

Implementation831360a9a9770815c660f5bc06d002b92154a1b0 passed native
push40447807340/job122003205464 and PR40447810051/job122003208919:
34 actual successful steps,20 native groups and197 alpha tests each.
Both actual artifacts contain all18 restored proofs,5 successful sessions,
2 manager restarts,6 bounded journal checks and unchanged3 TLS sessions.
All13 cleanup facts, socket absence, unit removal and private Node/bootstrap
removal are verified. Hosted contract results are617PASS/1root-onlySKIP;
the real nonroot service was exercised separately. Failure containment
remains unexercised. Research PR ran21/7/27/48; push runtime skipped, CLA failed.

This accepts only restored HTTP configuration within the same checked
runtime package and the declared temporary systemd-user profile. It does
not accept a distinct-package A-to-B-to-A transition, TLS restore, external
application data recovery, permanent release, soak or fullG3/G4/V1.
The two archives differ in provenance, with the same native binary;
that difference is not a package-upgrade acceptance. Next: implement the
explicit side-by-side package transition/state-compatibility contract and
verify meaningful A-to-B-to-A, preserving known-good files and prior failures.
Evidence: x10/evidence/g4-restored-service-hosted.json.

## Unhealthy operator package and explicit kept-A fallback candidate

The separate `operator-package-fallback.mjs` entry checks one additional HTTP
failure outcome on the supported ephemeral nonroot systemd-user profile. This
is an acceptance fixture for an explicit operator action. It adds no automatic
production fallback command and does not reverse application side effects.

The actual historical A operator first serves input P. Its unit and owned native
processes must retire before distinct B is staged from the retained installation.
Only B's fixture readiness response is held. The checker captures the activating
launcher, native session, invocation and exact readiness hook before releasing a
controlled wrong-body response. A passing outcome requires the known hook's
failure, a null B binding, no B POST effect, and confirmed B resource absence
before its owned failed state and runtime unit can be retired. A timeout or
unknown process identity cannot substitute for that observation.

All retained A files and its backup are compared while B is failed. The operator
then explicitly prepares the SAME retained A installation and starts a third
fresh unit, with fresh session, revision, invocation and binding identities.
Only lifecycle records required by this explicit preparation may change. The
operator code, installation identity, input P and backup remain known-good.
Exact GET, unique POST and streaming observations must preserve prior effects
without replay. The third context does not create a third installation: all
unit contexts are checked before each unique owned prefix is uninstalled once.

This profile has its own strict proof/report schema and separate observation
units: three units, two installations, two successful native invocations, one
failed B attempt, zero manager restarts and two successful bounded journal
checks. Journal checks are not an exact count of journalctl queries; GET checks
are not an exact count of idempotent acquisition attempts. The accepted normal
return profile remains separately bounded at three units, four successful
invocations, one B restart and five journal checks. The original restored-service
18-proof / five-session / two-restart / six-journal-check and TLS requirements
remain unchanged.

The hosted bootstrap must run all three source-pinned children, retain the
separate `service-package-fallback.json` artifact, and admit private Node removal
only after all three strict reports and their owned cleanup pass. A started
attempt, arbitrary JSON, absent report or success-shaped failure does not admit
cleanup. The combined envelope keeps its existing 32 KiB raw-byte bound. The
historical CLI and bootstrap files remain until known dependency cleanup; any
uncertainty retains them.

Authored source and local pure, temporary-file or virtual controls are not
actual managed-service acceptance. Physical native/process-group/signal/systemd
fixtures must run only in the supported hosted CI, not this nested local PID
environment. Exact candidate hosted results are pending. The native NGINX binary
is unchanged; historical A is reassembled, not a permanently published archive.
TLS restore, all-traffic fencing, a complete failure matrix, permanent release,
independent published replay, the 60-minute soak and full G3/G4/V1 remain open.
Earlier c2 and 6401 CI failures and local cleanup FAIL_UNKNOWN remain preserved.


## Exact explicit KEPT-A fallback acceptance — 27 October 2026

Implementation7b32841d28a8b155b5783cef1a0c56337bb45a06 passed both native
contexts: push40497965654/job122168221801 and PR40497972686/job122168235728,
all36 actual steps each. ZIP digests and actual strict reports were checked.
Each fallback report is4653 artifact bytes with13 fields,13 proof sections,
13 phases and19 failed-B facts. The owned B fails the exact readiness hook,
has no binding or POST effects, and fully retires before explicit kept-A
preparation. The same old installation serves P with fresh unit/session/
revision/invocation/binding and unique unretried POST/stream, without replay.

Separate fallback counts are3 units,2 installs,2 successful invocations,
1 expected failed B attempt,0 restarts and2 bounded successful journal CHECKS.
Normal3/4/1/5 and legacy18 restored proofs/5sessions/2restarts/6journalCHECKS/
3downstream+3upstream TLS sessions remain verified separately. All owned
resources and private Node/history/bootstrap were removed after all3 strict
source-pinned reports succeeded. These CHECKS are not exact raw query counts.

Native20 groups,alpha617,TLS76,normal544/fallback545/Node138 TAP passed each;
legacy617passed/1root-onlyskip and official1105pass/25skip/1expectedTODO/
0unexpectedFAIL remain separate. Research PR actually ran21/7/27/48;
push research runtime skipped; CLA failed. New fixture success does not erase
c2/6401 failures or local FAIL_UNKNOWN, or establish a native binary upgrade.

Only the named explicit operator fallback is accepted. Same-UID trust,
unsigned pins and checked historical CLI reassembly limits remain. The next
operator gap is a reviewed faulted/orphan incident runbook using existing
strict refusals and confirmed backups, not automatic reaping or lifecycle
editing. Release-record step completeness/cap also needs reconciliation.
Permanent release, independent published replay,60minsoak, full recovery/
security, TLS restore,fullG3/G4/V1 and semantic Continuum remain OPEN.
Evidence: x10/evidence/g4-kept-a-fallback-hosted.json.
