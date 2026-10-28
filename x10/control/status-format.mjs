// Human presentation of the existing JSON status; no extra health assertion.
const text = value => String(value ?? 'unavailable').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 512);
const actions = {
  locked: 'Inspect the operation holding the lock. Remove a stale lock only after confirming that exact process exited.',
  pending: 'Inspect the unresolved transaction, then use recover before another apply.',
  commit_pending: 'An event commit is incomplete. Inspect the state and run recover.',
  event_commit_incomplete: 'Inspect the preserved transaction and use explicit recover; do not erase its records.',
  unbound: 'Verify the explicitly started registered native master, then run bind.',
  runtime_identity: 'Inspect the PID file, registered executable and original master lifetime. Automatic rebinding is not performed.',
  runtime_namespace: 'Run the controller in its initialized PID namespace.',
  operator_config_changed: 'Inspect and reconcile nginx.conf with the registered configuration before applying changes.',
  fragment_changed: 'Inspect the managed fragment and journal; reconcile known bytes before recovery.',
  generation_endpoint: 'Select exactly one explicit private control socket or 127.0.0.1:port owned by the bound master.',
  generation_schema: 'Confirm that this native build supports the generations schema. Do not treat unverified metadata as readiness.',
  generation_unavailable: 'Confirm the selected native build and explicitly opened control endpoint. The command does not open one.',
  generation_timeout: 'Inspect the selected master and endpoint. The diagnostic timed out without changing configuration.',
  ENOENT: 'Check the --state path and referenced files. Initialize a new private prefix only if that is intentional.',
};
export function formatStatusError(result) {
  const code = result.code || 'error';
  return `NGINX X10 status\nError [${text(code)}]: ${text(result.error)}\nNext: ${actions[code] || 'Inspect this error and the registered state before attempting changes.'}\n`;
}
export function formatStatus(result) {
  if (result?.ok !== true) return formatStatusError(result || {});
  const runtime = result.runtime || {}, lines = ['NGINX X10 status', `State: ${text(result.state)}`,
    `Last confirmed revision: ${text(result.lastConfirmedRevision)}`];
  if (!result.binding) lines.push('Master: unbound');
  else lines.push(`Master: bound PID ${text(result.binding.pid)} (proc PID ${text(result.binding.procPid)}); identity ${runtime.identityValid ? 'verified' : 'not verified'}`);
  if (!result.binding) lines.push('Revision header probe: not performed (unbound)');
  else if (!runtime.observedRevision) lines.push('Revision header probe: no revision header observed');
  else lines.push(`Revision header probe: ${text(runtime.observedRevision)} (${runtime.observedRevision === result.lastConfirmedRevision ? 'matches last confirmed revision' : 'MISMATCH with last confirmed revision'})`);
  if (runtime.error) lines.push(`Runtime observation error: ${text(runtime.error)}`);
  lines.push(`Operator config: ${result.configUnchanged ? 'unchanged' : 'CHANGED'}`,
    `Managed fragment: ${result.fragmentMatchesLastConfirmed ? 'matches last confirmed revision' : 'CHANGED'}`,
    `Transaction: ${result.pending ? `PENDING (${text(result.pending.stage)})` : 'none pending'}`,
    `History: ${result.history?.integrity ? 'verified' : 'not verified'}; ${text(result.history?.entries)} entries`,
    'Health and listener drain: not checked by status. A revision header is an observation, not a readiness acknowledgment.');
  const next = [];
  if (result.pending) next.push(actions.pending);
  if (!result.configUnchanged) next.push(actions.operator_config_changed);
  if (!result.fragmentMatchesLastConfirmed) next.push(actions.fragment_changed);
  if (!result.binding) next.push(actions.unbound);
  else if (!runtime.identityValid) next.push(actions.runtime_identity);
  else if (runtime.error || runtime.observedRevision !== result.lastConfirmedRevision) next.push('Inspect the serving revision and native error log before applying another change.');
  lines.push(`Next: ${next.length ? next.join(' ') : 'No discrepancy was observed by these status checks. Use explicit health and listener diagnostics when needed.'}`);
  return lines.join('\n') + '\n';
}
