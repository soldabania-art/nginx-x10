// Validates declarations only. It never fetches evidence, verifies a signature,
// runs a package, grants a lease, or accepts a production release.
import { readFileSync, openSync, closeSync, fstatSync, readSync, realpathSync, constants } from 'node:fs';
import { fileURLToPath } from 'node:url';

const schema = JSON.parse(readFileSync(new URL('./release-record.schema.json', import.meta.url)));
export const MAX_RECORD_BYTES = 262144;
// Current native job receipt in observed execution order, including setup and
// post-actions. This is a bounded declaration contract, not a workflow query
// or authentication of the external job. Keep it aligned with the pinned
// configured steps and independently recorded actual job receipts.
export const MAX_EXECUTED_STEPS = 64;
export const REQUIRED_NATIVE_CI_STEPS = Object.freeze([
  'Set up job',
  'Run actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd',
  'Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
  'Validate release-record contract and refusal controls',
  'Validate alpha archive refusal controls',
  'Validate guarded user-service recipe',
  'Validate fail-closed user-manager preflight',
  'Validate actual-service harness refusal controls',
  'Validate bounded owned-service journal observations',
  'Validate bounded downstream HTTPS fixture controls',
  'Validate bounded verified HTTPS origin fixture controls',
  'Validate bounded paused TLS client controls',
  'Validate owned operator interruption controls',
  'Validate failed interruption containment controls',
  'Validate authenticated Node dependency refusal controls',
  'Validate managed operator-package return refusal controls',
  'Validate managed unhealthy-package fallback refusal controls',
  'Build dependencies and optional test clients',
  'Install pinned HTTP3 interoperability client',
  'Install independent HTTP3 HEAD client',
  'Compile native profile',
  'Native regressions and pinned official compatibility sample',
  'Verify installed HTTPS upstream trust and hostname',
  'Verify managed frontend HTTPS and certificate lifecycle',
  'Verify native tenant cache contract experiment',
  'Verify private Unix control transport',
  'Build profile without control API',
  'Package local Linux alpha',
  'Checksum local Linux alpha',
  'Verify packed alpha before extraction',
  'Verify temporary user-service with authenticated private Node',
  'Preserve JSON evidence',
  'Preserve local Linux alpha',
  'Post Run actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
  'Post Run actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd',
  'Complete job',
]);
const failure = code => ({ valid: false, errors: [code] });

function plainJson(value, seen = new Set(), depth = 0, budget = { n: 0 }) {
  if (++budget.n > 8192 || depth > 24) return false;
  if (value === null || typeof value === 'boolean') return true;
  if (typeof value === 'string') return value.length <= 4096;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object' || seen.has(value)) return false;
  const array = Array.isArray(value), proto = Object.getPrototypeOf(value);
  if (proto !== (array ? Array.prototype : Object.prototype) && !(proto === null && !array)) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some(k => typeof k !== 'string')) return false;
  seen.add(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (array && key === 'length') continue;
    if (array && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length)) return false;
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable || key.length > 128
        || !plainJson(descriptor.value, seen, depth + 1, budget)) return false;
  }
  if (array && Object.keys(descriptors).length !== value.length + 1) return false;
  seen.delete(value);
  return true;
}

// Deliberately small evaluator for the keywords used by this checked-in schema.
// Cross-reference/identity rules below supplement JSON Schema's shape rules.
function matches(value, rule) {
  if (rule.$ref) return matches(value, schema.$defs[rule.$ref.slice('#/$defs/'.length)]);
  if (rule.const !== undefined && value !== rule.const) return false;
  if (rule.enum && !rule.enum.includes(value)) return false;
  if (rule.type) {
    const type = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    if (rule.type === 'integer' ? !Number.isSafeInteger(value) : type !== rule.type) return false;
  }
  if (typeof value === 'string') {
    if (rule.minLength !== undefined && value.length < rule.minLength) return false;
    if (rule.maxLength !== undefined && value.length > rule.maxLength) return false;
    if (rule.pattern && !new RegExp(rule.pattern).test(value)) return false;
  }
  if (typeof value === 'number' && (value < (rule.minimum ?? -Infinity) || value > (rule.maximum ?? Infinity))) return false;
  if (Array.isArray(value)) {
    if (value.length < (rule.minItems ?? 0) || value.length > (rule.maxItems ?? Infinity)) return false;
    if (rule.uniqueItems && new Set(value.map(x => JSON.stringify(x))).size !== value.length) return false;
    if (rule.items && !value.every(x => matches(x, rule.items))) return false;
  } else if (value && typeof value === 'object') {
    if (rule.required?.some(k => !Object.hasOwn(value, k))) return false;
    for (const key of Object.keys(value)) {
      if (rule.additionalProperties === false && !Object.hasOwn(rule.properties ?? {}, key)) return false;
      if (rule.properties?.[key] && !matches(value[key], rule.properties[key])) return false;
    }
  }
  if (rule.anyOf && !rule.anyOf.some(r => matches(value, r))) return false;
  if (rule.allOf && !rule.allOf.every(r => matches(value, r))) return false;
  if (rule.if && !matches(value, matches(value, rule.if) ? (rule.then ?? {}) : (rule.else ?? {}))) return false;
  return true;
}

export function validateReleaseRecord(value) {
  try {
    if (!plainJson(value)) return failure('record_input');
    if (!matches(value, schema)) return failure('record_schema');
    if (value.build.eventHead !== value.source.commit) return failure('record_identity');
    if (value.build.prMergeCommit === null ? value.build.checkoutCommit !== value.source.commit
        : value.build.checkoutCommit !== value.build.prMergeCommit || value.build.prMergeCommit === value.source.commit)
      return failure('record_identity');
    const ciIds = new Set();
    for (const ci of value.build.ci) {
      if (ci.eventHead !== value.source.commit || ci.checkoutCommit !== value.build.checkoutCommit)
        return failure('record_identity');
      const identity = `${ci.runId}:${ci.jobId}:${ci.attempt}`;
      if (ciIds.has(identity)) return failure('record_ci');
      ciIds.add(identity);
      const names = ci.executedSteps.map(step => step.name);
      if (ci.conclusion !== 'success' || ci.executedSteps.some(step => step.conclusion !== 'success')
          || names.length > MAX_EXECUTED_STEPS || new Set(names).size !== names.length
          || names[0] !== REQUIRED_NATIVE_CI_STEPS[0] || names.at(-1) !== REQUIRED_NATIVE_CI_STEPS.at(-1))
        return failure('record_ci');
      // Preserve receipt order; a sorted set of selected historical steps is
      // insufficient. Additional actual steps must remain unique, successful,
      // inside the setup/completion boundaries and within the schema cap.
      let previous = -1;
      for (const name of REQUIRED_NATIVE_CI_STEPS) {
        const index = names.indexOf(name);
        if (index <= previous) return failure('record_ci');
        previous = index;
      }
    }
    const canonicalURL = text => {
      const url = new URL(text);
      return url.href === text && !url.username && !url.password && !url.search && !url.hash
        && !text.split('/').some(part => part === '.' || part === '..');
    };
    if (!canonicalURL(value.artifact.url) || value.evidence.some(x => !canonicalURL(x.url))) return failure('record_url');
    const a = value.artifact;
    const release = a.url.match(/\/releases\/download\/([^/]+)\//);
    if (release && release[1] !== `v${value.version}`) return failure('record_version');
    const artifactBlob = a.url.match(/\/blob\/([0-9a-f]{40})\//);
    if (artifactBlob && ![value.source.commit, value.build.checkoutCommit].includes(artifactBlob[1])) return failure('record_identity');
    if (a.permanent ? a.expiresAtUTC !== null || !a.url.includes('/releases/download/')
        : a.expiresAtUTC === null || !Number.isFinite(Date.parse(a.expiresAtUTC))) return failure('record_artifact');
    if (a.expiresAtUTC !== null && new Date(a.expiresAtUTC).toISOString() !== a.expiresAtUTC.replace('Z', '.000Z'))
      return failure('record_artifact');
    const evidence = new Map();
    for (const item of value.evidence) {
      if (evidence.has(item.id)) return failure('record_evidence');
      if (![value.source.commit, value.build.checkoutCommit].includes(item.sourceCommit)) return failure('record_identity');
      const blob = item.url.match(/\/blob\/([0-9a-f]{40})\//);
      if (blob && blob[1] !== item.sourceCommit) return failure('record_identity');
      if (item.outcome === 'passed' && item.unexpectedFailures !== 0) return failure('record_evidence');
      evidence.set(item.id, item);
    }
    const kinds = ['authority', 'contract', 'alpha-install', 'service', 'rollback', 'security', 'soak', 'distribution', 'independent'];
    for (let i = 0; i < 9; i++) {
      const gate = value.gates[`G${i}`];
      if (gate.evidenceIds.some(id => !evidence.has(id))) return failure('record_evidence');
      if (gate.status !== 'accepted') continue;
      if (i > 0 && value.gates[`G${i - 1}`].status !== 'accepted') return failure('record_gate');
      const items = gate.evidenceIds.map(id => evidence.get(id));
      if (items.some(x => x.outcome !== 'passed' || x.unexpectedFailures !== 0)
          || !items.some(x => x.kind === kinds[i])) return failure('record_gate');
      if (i === 6 && !items.some(x => x.kind === 'soak' && x.durationSeconds >= 3600)) return failure('record_gate');
    }
    return { valid: true, errors: [] };
  } catch { return failure('record_input'); }
}

function main() {
  let fd;
  try {
    if (process.argv.length !== 3) return failure('record_usage');
    fd = openSync(process.argv[2], constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > MAX_RECORD_BYTES) return failure('record_input');
    const data = Buffer.alloc(MAX_RECORD_BYTES + 1);
    let used = 0, count;
    while ((count = readSync(fd, data, used, data.length - used, null)) > 0) {
      used += count;
      if (used > MAX_RECORD_BYTES) return failure('record_input');
    }
    return validateReleaseRecord(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(0, used))));
  } catch { return failure('record_input'); }
  finally { if (fd !== undefined) closeSync(fd); }
}
let invokedAsCLI = false;
try {
  invokedAsCLI = Boolean(process.argv[1])
    && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
} catch { /* An imported module does not acquire CLI authority. */ }
if (invokedAsCLI) {
  const result = main();
  process.stdout.write(JSON.stringify({ ...result, scope: 'declared-record-validation-only', evidenceAuthenticated: false, productionAccepted: false }) + '\n');
  process.exitCode = result.valid ? 0 : 1;
}
