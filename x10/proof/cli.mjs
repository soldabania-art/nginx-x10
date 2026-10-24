#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { ProofError, readContract, verifyContracts } from './runner.mjs';

export async function main(argv = process.argv.slice(2)) {
  let controller;
  const abort = () => controller?.abort();
  try {
    const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, strict: true,
      options: { contract: { type: 'string' }, baseline: { type: 'string' }, candidate: { type: 'string' },
        binary: { type: 'string' }, manifest: { type: 'string' }, help: { type: 'boolean' } } });
    if (values.help) { process.stdout.write('node x10/proof/cli.mjs check --contract FILE [--binary FILE --manifest FILE]\nnode x10/proof/cli.mjs compare --baseline FILE --candidate FILE [--binary FILE --manifest FILE]\n'); return; }
    const command = positionals[0];
    if (positionals.length !== 1 || !['check', 'compare'].includes(command)
      || (command === 'check' && (!values.contract || values.baseline || values.candidate))
      || (command === 'compare' && (values.contract || !values.baseline || !values.candidate))) throw new ProofError('arguments', 'Use check --contract or compare --baseline --candidate', 'invalid_input');
    // Validate all untrusted declarative input before probing/executing any binary.
    const input = command === 'check' ? { contract: await readContract(values.contract) }
      : { baseline: await readContract(values.baseline), candidate: await readContract(values.candidate) };
    controller = new AbortController(); process.once('SIGINT', abort); process.once('SIGTERM', abort);
    const result = await verifyContracts({ ...input, binary: values.binary, manifest: values.manifest, signal: controller.signal });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); process.exitCode = result.passed ? 0 : 1;
  } catch (error) {
    if (controller?.signal.aborted && !(error instanceof ProofError)) error = new ProofError('interrupted', 'Verification interrupted');
    if (String(error.code).startsWith('ERR_PARSE_ARGS_')) error = new ProofError('arguments', 'Unknown or incomplete CLI arguments', 'invalid_input');
    const known = error instanceof ProofError;
    const outcome = known ? error.outcome : 'verification_error';
    // Never copy raw OS/child errors (which contain local paths/config/logs) into public output.
    process.stdout.write(`${JSON.stringify({ schemaVersion: 1, kind: 'nginx-x10-contract-verification', passed: false,
      outcome, code: known ? error.code : 'execution_failed', message: known ? error.message : 'Verification could not complete', aiIntegration: false }, null, 2)}\n`);
    process.exitCode = outcome === 'unsupported' ? 3 : 2;
  } finally { process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
