#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { initialize, bind, apply, revert, recover, status, history, snapshotListeners, inspectListeners, inspectGenerations } from './manager.mjs';
import { formatStatus, formatStatusError } from './status-format.mjs';

const help = `NGINX X10 local native controller (Linux, Node >=22)

  node x10/control/cli.mjs init --spec settings.json --file candidate.json
  node x10/control/cli.mjs bind --state /private/prefix/.x10-control
  node x10/control/cli.mjs apply --state /private/prefix/.x10-control --file candidate.json
  node x10/control/cli.mjs revert --state /private/prefix/.x10-control --revision ID
  node x10/control/cli.mjs recover --state /private/prefix/.x10-control
  node x10/control/cli.mjs status --state /private/prefix/.x10-control [--human]
  node x10/control/cli.mjs history --state /private/prefix/.x10-control
  node x10/control/cli.mjs snapshot-listeners --state /private/prefix/.x10-control
  node x10/control/cli.mjs inspect-listeners --state /private/prefix/.x10-control --file snapshot.json

  node x10/control/cli.mjs inspect-generations --state /private/prefix/.x10-control --control-socket /private/prefix/control.sock
  node x10/control/cli.mjs inspect-generations --state /private/prefix/.x10-control --control-address 127.0.0.1:PORT

inspect-generations queries an explicitly opened endpoint; it never opens one.
Generation metadata is not readiness or listener-drain acknowledgment.
init never starts NGINX. Start the explicit native master yourself, then bind.
Output is JSON by default; status --human changes presentation only.
Rejected/rolled-back/ambiguous requests have nonzero exit.
See x10/control/README.md for the include boundary and recovery limitations.
`;

async function load(file) {
  if (!file) throw new Error('A required JSON file argument is missing');
  const bytes = await readFile(file);
  if (bytes.length > 2 * 1024 * 1024) throw new Error('JSON input exceeds 2 MiB');
  return JSON.parse(bytes.toString('utf8'));
}

let humanStatus = false;
try {
  const { values, positionals } = parseArgs({ options: {
    help: { type: 'boolean', short: 'h' }, state: { type: 'string' }, spec: { type: 'string' },
    file: { type: 'string' }, revision: { type: 'string' }, human: { type: 'boolean' },
    'control-socket': { type: 'string' }, 'control-address': { type: 'string' },
  }, allowPositionals: true });
  if (values.help) console.log(help);
  else {
    const [command] = positionals;
    humanStatus = command === 'status' && values.human === true;
    if (values.human && command !== 'status') throw new Error('--human is supported only for status');
    if ((values['control-socket'] !== undefined || values['control-address'] !== undefined) && command !== 'inspect-generations')
      throw new Error('Control endpoint options are supported only for inspect-generations');
    if (positionals.length !== 1) throw new Error('Exactly one command is required; use --help');
    if (command !== 'init' && !values.state) throw new Error('--state is required');
    let result;
    switch (command) {
      case 'init': result = await initialize(await load(values.spec), await load(values.file)); break;
      case 'bind': result = await bind(values.state); break;
      case 'apply': result = await apply(values.state, await load(values.file)); break;
      case 'revert': result = await revert(values.state, values.revision); break;
      case 'recover': result = await recover(values.state); break;
      case 'status': result = await status(values.state); break;
      case 'history': result = await history(values.state); break;
      case 'inspect-generations': result = await inspectGenerations(values.state, { controlSocket: values['control-socket'], controlAddress: values['control-address'] }); break;
      case 'snapshot-listeners': result = await snapshotListeners(values.state); break;
      case 'inspect-listeners': {
        const saved = await load(values.file);
        if (saved?.ok !== true || !saved.snapshot) throw new Error('Expected the complete JSON output from snapshot-listeners');
        result = await inspectListeners(values.state, saved.snapshot);
        break;
      }
      default: throw new Error('Unknown command; use --help');
    }
    if (humanStatus) process.stdout.write(formatStatus(result));
    else console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
  }
} catch (error) {
  const result = { ok: false, code: error.code || 'error', error: error.message };
  if (humanStatus) process.stdout.write(formatStatusError(result));
  else console.log(JSON.stringify(result, null, 2));
  process.exitCode = 1;
}
