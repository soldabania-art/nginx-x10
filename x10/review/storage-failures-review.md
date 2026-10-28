# Controller storage-failure review

Review date: 23 October 2026. Baseline development commit:
`43618ecca59fe802620f810a13f083554952bd7d`.

This review covers the local controller's recorded event-commit boundaries,
initialization reconciliation and selected filesystem error paths. It does not
certify general ACID semantics, power-loss durability, a complete storage-fault
matrix or an all-traffic native reload fence. Production NGINX C is outside this
change's implementation scope.

## Existing contracts read

- `x10/control/manager.mjs`: private path/lock checks, atomic replacement,
  history hash chain, event intent, explicit recovery, native identity and health
  guards, initialization cleanup and apply/rollback exception paths.
- `x10/test/control.test.mjs`: the original transactions and milestone-3 real
  SIGKILL interception at synced intent/history/state/removal boundaries.
- `x10/control/README.md` and `handover-boundaries.md`: explicit operator stale
  lock handling, no recovery of unknown partial history, sampled readiness and
  untested initialization crash boundary.

## Review questions

1. Distinguish process death after a completed syscall from a syscall reporting
   an I/O error. A failed sync or rename may leave new bytes visible; a failure
   must not be relabeled a successful original apply.
2. Once a durable event intent is present, preserve the matching pending stage
   rather than overwrite it during generic error handling. Recovery must still
   validate the exact event/state/revision/history relationship before writing.
3. Initialization reconciliation must remain unbound, pass native syntax and
   file guards, avoid starting a daemon, and be idempotent. An interrupted
   partial initialization without the required records must remain explicit.
4. Partial history must not be silently truncated, completed by guessing, or
   counted as a passing recovery. Operator config edits, binary replacement,
   stale master identity and regressed health remain conflicts.
5. Filesystem interception belongs only in test subprocesses. Tests must record
   that the requested real operation/boundary was reached, assert the injected
   error actually fired and check durable bytes, history counts and resources.

## Initial observation

The baseline apply rejection/rollback error handler could write
`pending.stage = "ambiguous"` after an event intent has already been saved. That
contradicted the event-specific pending stage required by `validateCommit`.
The previous README explicitly records this refusal boundary. A small fix is
appropriate only with a real prior-manager counterexample and preserved
partial-write/conflict refusal. The final candidate and its actual prior-manager
counterexample satisfy that gate.

## Candidate implementation inspected

The candidate keeps the existing schema and hash-chain format. Its small
production change classifies failures inside event persistence and terminal
pending removal as `event_commit_incomplete`. Both apply exception paths
propagate that marker, so a storage error cannot trigger another rollback or
replace the matching transaction stage merely because the write reported an
error. The original apply still reports failure; later successful reconciliation
is a separate maintenance outcome.

Recovery now syncs an already-present complete history record before advancing
state or removing intent. The root reviewer identified why this retry is
necessary: seeing a full append does not establish that its previous file sync
succeeded. If the after-state is already visible, the candidate also syncs that
state file and its directory before unlinking the intent. This preserves the
intended ordering when the previous state rename became visible but its
directory sync reported failure. Those checks are stronger than relying only
on the final directory sync after intent removal.

The inspected test worker records which named fault fired and whether its
underlying sync ran. Before-sync EIO deliberately omits the real sync; after-sync
EIO is separately identified. A partial append actually writes and syncs a
strict record prefix, then reports EIO. Recovery must leave that partial tail
visible and refuse it, rather than guess or truncate. Snapshot assertions
describe visible file bytes, not direct stable-media measurements.

Review feedback also added terminal pending-removal errors, initial
state-directory-sync errors for both terminal outcomes, exact confirmed revision
equality (to exclude a fresh activation), and an accurate partial-tail byte
count separate from an earlier completed `apply_started` record.

## Independent initialization experiment

A separate ignored review subprocess intercepts only test-side filesystem
functions, waits until the real sync at the chosen initialization boundary has
completed, and then receives SIGKILL. Its parent calls the production recovery
API and checks history, binding, files and a second recovery. The experiment
passed on the final manager SHA-256
`209a47ab92ac387442c628c36e69d70494f8e5ba41886a8ac919ca405e735c60`
and native binary SHA-256
`66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`.

| Synced boundary before SIGKILL | First recovery | History | Binding | Second recovery |
| --- | --- | --- | --- | --- |
| Event intent | `reconciled` | Exactly one `initialized_unbound` event | Null | `nothing_pending` |
| History append | `reconciled` | Exactly one `initialized_unbound` event | Null | `nothing_pending` |
| State replacement | `reconciled` | Exactly one `initialized_unbound` event | Null | `nothing_pending` |
| Intent removal | `nothing_pending` | Exactly one `initialized_unbound` event | Null | `nothing_pending` |

Operator config and managed fragment bytes were unchanged. No lock removal was
needed: initialization does not acquire the later operation lock. The reviewer
initially expected no PID file, but that test assumption was wrong. Native
`-t` deliberately opens/creates an **empty** PID file in `ngx_create_pidfile`
(`src/core/ngx_cycle.c`) and does not write a running PID under
`ngx_test_config`. The corrected control requires that file to remain empty;
it does not delete it to make an assertion pass. No controller defect was
inferred from this syntax-test side effect.

## Independent executed storage group

The reviewer independently ran the final author's storage group with:

```sh
env -u X10_CONTROL_STORAGE_EVIDENCE -u X10_CONTROL_EVIDENCE \
  -u X10_CONTROL_RECOVERY_EVIDENCE \
  node --test \
  --test-name-pattern='native initialization and injected storage failure boundaries' \
  x10/test/control.test.mjs
```

The process exited zero, with **33 passing Node tests**: 32 behavior scenarios
and one parent test, zero failures, and empty stderr, in about 26.4 seconds.
This independent command selected the default console/spec reporter, so its
transcript is not relabeled TAP. It executed the same final scenario source
whose author-produced TAP/evidence was separately inspected. Manager, test,
README and binary hashes were unchanged before and after the independent run.
Every selected case includes native shutdown and private-prefix cleanup; the
author's final JSON also records 32 native master exits with code zero and no
terminating signal. The reviewer's fixture processes have stopped.

The independently read [storage evidence](../evidence/control-storage-fixed.json)
contains two explicit protection failures against the unchanged previous
manager from `43618ecca59fe802620f810a13f083554952bd7d`:

- A rejected event's full history append followed by injected sync EIO left
  pending marked `ambiguous`. Both old and new recovery correctly refused that
  already contradictory old intent with `commit_integrity`; the new controller
  prevents creating that contradiction during the failed operation.
- After a full applied history append whose sync was deliberately omitted and
  reported EIO, old recovery returned `reconciled` without calling the forced
  history-sync retry at all. This is a reproduced missing durability operation,
  not an observed power-loss incident. The candidate attempts that retry; a
  second injected EIO leaves the visible files and intent unchanged, and a
  subsequent successful recovery commits exactly one event.

The final matrix also checks four initialization SIGKILL boundaries, ordinary
initialization I/O cleanup with the empty-PID side effect explicit, ten terminal
fault points for each of `rejected` and `rolled_back`, required existing-state
file/directory sync retries, and partial appends in apply and recover. Terminal
cases require the original confirmed revision, a single matching terminal event,
and no fresh activation. Partial tails remain present and cause refusal.

The author reports a complete controller run of 66 passing TAP assertions
before final evidence-label precision edits; the final exact-file targeted
storage group passed 33/33 TAP. The reviewer did not execute the full controller
suite and does not combine these overlapping runs into additional scenarios.
A later aggregate/hosted CI run is a separate gate owned by the root agent.

## Frozen reviewed identities

| File | SHA-256 |
| --- | --- |
| `x10/control/manager.mjs` | `209a47ab92ac387442c628c36e69d70494f8e5ba41886a8ac919ca405e735c60` |
| `x10/test/control.test.mjs` | `6513ae9da2d68514a1284776838842c1eea1cd36048d15dba92ef19d94ea6965` |
| `x10/control/README.md` | `761bf56b805a0c79b36b2605259f9aaa204d7f281266fa6fbd1c119e088411a0` |

The independent initialization and selected storage runs identify the same
native binary SHA-256 `66ba1756a76b91929b0205071c7504a1f7086348af8a61593ef5141e044b9bcf`.

## Result and remaining boundaries

No unresolved blocker was found in the reviewed controller change at these
identities. The new error classification is an observable, documented API
behavior: a failed original apply remains failed even when later explicit
recovery completes its recorded state transition.

The tests inject errors at the Node filesystem operation boundary. They exercise
real file writes/syncs and real process deaths where stated, but do not make a
kernel, storage device or power supply fail. Unsupported interleavings, partial
history, missing/contradictory old intent, external config/includes, hostile
same-UID races and stale native identity remain outside automatic recovery.
Unbound initialization's ordinary I/O cleanup can retain an empty native-test
PID file requiring operator inspection before a new initialization. Stale lock
removal remains explicit. Sampled health and this journal ordering do not
provide a global traffic cutover, undo application requests or establish a
performance improvement.
