// Pure source preservation controls. No fixture/helper import or execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const snapshot = {
  "helperPins": {
    "amendRecord": "40af3b13d448fbaa3c66cd0320b2e2de682755c695a61f24363c1efd1f394842",
    "assertInstalledPackageInfo": "2433b3ab61566fbe2ebc34e9416adb936b695d02f849b984f52895bf394ff434",
    "recipeTree": "c1f79083454513bf3ef893d4a1907fddf5adcb2a2b646039754bd7a4063902a7",
    "prepareRecipeNode": "a2c96ea8eebe80e05480770ec50cf629cd026b83683d1ced266f771f03ef4d53",
    "observeRecipeNode": "d30078f5f3ebc12e703324d766cc03e098fc3574ef5210a1ff548175eb23d5e6",
    "verifyRecipeNode": "347cf71925169f77f15fe64b1ce5018f4f4a245a8f94c907b8af75a01339420d",
    "rawRecipeNodeCommand": "14108324e4cdbcb4986d40516b88f2a54f2cee108aff229295cf83a02c090958",
    "recipeNodeCommand": "692259f07c5c0aaa11dd436287c73dac392249cc361371e9ffd242109797cd43",
    "installedRecipeFixture": "56ec5a03974e79116cad2e4f6e20f333d0c37f20317eef11fb5eceb0304bbbf7",
    "recipeCli": "8daad100b52dbdd6a72a7a4697d8066940b2b80cdca215ed6f727a71a838a07a",
    "assertRecipeResult": "ce2e4dcc071ce1e1f5a328e70f343b61ca404c966cf70ecaf1beff364b242a64"
  },
  "constantPins": {
    "recipeControlNames": "d42ef5af39aeab5d78b7bd9f1d4312152a73d94b37cacd7512c8ef8409e48732",
    "recipeAlphaNames": "d408d6307de1e9e497865b120c7f998264e5dbe0be69e053533bd0cc7a2b3b79",
    "recipeV2Names": "99a0504e2428eb177df6b47000fa73b3caa40dee27d455b989c7938f7f7529fa",
    "recipeV2Dirs": "8e0e540b603b8ce44b046ca2b23e702b18aead63ea74045d51f61d1aa448a4c2"
  },
  "recipeHash": "79e3b6cdfff6d0900a0562a251ade800c76199413b3aec9787cd5b4a795fb9c7",
  "remainingHash": "d8261f6251fcd65cbd8ce2d8e0df027dc0df48301fd98295868feb13add1e634",
  "workflowSteps": [
    "Check scope fail-closed controls",
    "Classify exact event delta",
    "Validate release-record contract and refusal controls",
    "Validate alpha archive refusal controls",
    "Validate guarded user-service recipe",
    "Validate fail-closed user-manager preflight",
    "Validate actual-service harness refusal controls",
    "Validate bounded owned-service journal observations",
    "Validate bounded downstream HTTPS fixture controls",
    "Validate bounded verified HTTPS origin fixture controls",
    "Validate bounded paused TLS client controls",
    "Validate owned operator interruption controls",
    "Validate failed interruption containment controls",
    "Validate authenticated Node dependency refusal controls",
    "Validate managed operator-package return refusal controls",
    "Validate managed unhealthy-package fallback refusal controls",
    "Build dependencies and optional test clients",
    "Install pinned HTTP3 interoperability client",
    "Install independent HTTP3 HEAD client",
    "Compile native profile",
    "Native regressions and pinned official compatibility sample",
    "Verify installed HTTPS upstream trust and hostname",
    "Verify managed frontend HTTPS and certificate lifecycle",
    "Verify native tenant cache contract experiment",
    "Verify private Unix control transport",
    "Build profile without control API",
    "Package local Linux alpha",
    "Checksum local Linux alpha",
    "Verify packed alpha before extraction",
    "Verify temporary user-service with authenticated private Node",
    "Preserve JSON evidence",
    "Preserve local Linux alpha"
  ],
  "workflowBudgets": [
    "5",
    "20"
  ]
};
const sha = s => createHash('sha256').update(s).digest('hex');
const alpha = await readFile(new URL('./alpha.test.mjs', import.meta.url), 'utf8');
const recipe = await readFile(new URL('./alpha-recipe.test.mjs', import.meta.url), 'utf8');
const helpers = await readFile(new URL('./alpha-recipe-helpers.mjs', import.meta.url), 'utf8');
const all = await readFile(new URL('./all.mjs', import.meta.url), 'utf8');
const workflow = await readFile(new URL('../../.github/workflows/x10-native.yml', import.meta.url), 'utf8');
function functionBody(source, name) {
  const pattern = new RegExp('^(?:export )?(?:async )?function ' + name + '\\(', 'm');
  const match = pattern.exec(source); assert(match, 'Required original helper ' + name);
  const lineEnd = source.indexOf('\n', match.index);
  const oneLine = source.slice(match.index, lineEnd).endsWith('}');
  const end = oneLine ? lineEnd : source.indexOf('\n}', match.index) + 2; assert(end > match.index);
  return source.slice(match.index, end).replace(/^export /, '');
}
for (const [name, expected] of Object.entries(snapshot.helperPins))
  test('original helper body preserved: ' + name, () => {
    assert.equal(sha(functionBody(helpers, name)), expected);
    assert.equal([...helpers.matchAll(new RegExp('^(?:export )?(?:async )?function ' + name + '\\(', 'gm'))].length, 1);
    assert.doesNotMatch(alpha, new RegExp('^(?:async )?function ' + name + '\\(', 'm'));
  });
for (const [name, expected] of Object.entries(snapshot.constantPins))
  test('original fixture inventory constant preserved: ' + name, () => {
    const match = new RegExp('^(?:export )?const ' + name + '=[\\s\\S]*?;', 'm').exec(helpers); assert(match);
    assert.equal(sha(match[0].replace(/^export /, '')), expected);
  });
test('complete recipe test bodies moved once with original assertions and budgets', () => {
  const start = recipe.indexOf("test('installed package-info identifies checked nonexecuted payload");
  assert(start > 0); assert.equal(sha(recipe.slice(start).trimEnd()), snapshot.recipeHash);
  assert.doesNotMatch(alpha, /test\('installed (?:recipe|package-info)/);
  assert.doesNotMatch(recipe, /test\.(?:skip|only)|--test-(?:name|skip)-pattern/);
});
test('all original physical alpha bodies retained byte-for-byte apart from explicit helper injection', () => {
  const start = alpha.indexOf("test('isolated Linux alpha");
  const retained = alpha.slice(start).replace('await assertInstalledPackageInfo(prefix, launcher, cli);', 'await assertInstalledPackageInfo(prefix, launcher);').trimEnd();
  assert.equal(sha(retained), snapshot.remainingHash);
});
test('all seventeen expanded recipe controls remain registered', () => {
  assert.equal([...recipe.matchAll(/^test\('/gm)].length, 8);
  assert.match(recipe, /for\(const key of \['version','executable','sha256'\]\)test\(/);
  assert.match(recipe, /for\(const mutation of \['missingHelper','unknownVersion','missingOtherFile','wrongHelperMode','wrongDirectoryMode','helperHardlink'\]\)test\(/);
  assert.equal(8 + 3 + 6, 17);
});
test('managed suite registers each controller/record/recipe file once and requires complete TAP', () => {
  const suite = all.split('\n').find(s => s.includes("name: 'managed-native-control'")); assert(suite);
  for (const name of ['x10/test/control.test.mjs', 'x10/control/record-input.test.mjs', 'x10/test/alpha-recipe.test.mjs', 'x10/test/alpha-decomposition.test.mjs'])
    assert.equal(suite.split("'" + name + "'").length - 1, 1);
  assert.match(suite, /requireCompleteTAP: true/);
  assert.match(suite, /'--test', '--test-reporter=tap'/);
  assert.doesNotMatch(suite, /timeoutMs|--test-(?:name|skip)-pattern/);
});
test('alpha stays separately registered with complete TAP and unchanged global budget', () => {
  const suite = all.split('\n').find(s => s.includes("name: 'local-alpha-lifecycle'")); assert(suite);
  assert.match(suite, /'x10\/test\/alpha\.test\.mjs'/); assert.match(suite, /requireCompleteTAP: true/);
  assert.doesNotMatch(suite, /timeoutMs|--test-(?:name|skip)-pattern/);
  assert.match(all, /timeoutMs: suite\.timeoutMs \|\| 120_000/);
});
test('shared helper module registers no test or main fixture', () => {
  assert.doesNotMatch(helpers, /import test from|(?:^|\n)test\(|(?:^|\n)await (?:installedRecipeFixture|prepareRecipeNode)\(/);
  for (const name of ['amendRecord', 'recipeControlNames', 'recipeAlphaNames', 'assertInstalledPackageInfo', 'recipeTree', 'prepareRecipeNode', 'verifyRecipeNode', 'recipeNodeCommand'])
    assert.match(alpha, new RegExp('\\b' + name + '\\b'));
  assert.match(recipe, /recipeNodeCommand[^;]*from '\.\/alpha-recipe-helpers\.mjs'/s);
});
test('workflow configured step names and job budgets are unchanged', () => {
  assert.deepEqual([...workflow.matchAll(/^\s+- name: (.+)$/gm)].map(m => m[1]), snapshot.workflowSteps);
  assert.deepEqual([...workflow.matchAll(/^\s+timeout-minutes: (.+)$/gm)].map(m => m[1]), snapshot.workflowBudgets);
});
