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
