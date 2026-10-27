#!/usr/bin/env node
// Fixed explicit kept-A fallback fixture entry. Import grants no fixture execution authority.
import { realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { mainFallback } from './operator-package-return.mjs';
export { mainFallback as main };
let invoked = false;
try { invoked = Boolean(process.argv[1]) && await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url)); } catch { /* No import authority. */ }
if (invoked) { const result = await mainFallback(); process.stdout.write(JSON.stringify(result) + '\n'); process.exitCode = result.ok ? 0 : 1; }
