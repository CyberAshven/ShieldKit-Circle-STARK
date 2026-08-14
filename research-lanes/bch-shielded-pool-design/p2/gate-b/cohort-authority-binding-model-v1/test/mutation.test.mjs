import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, cpSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { rawFileDigest, validateStatic } from '../validate-static.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/';
const FILES = [
  'COMMAND.txt', 'README.md', 'authority-binding-root.v1.json', 'validate-static.mjs',
  'schemas/authority-dag.v1.schema.json', 'schemas/dependency-catalog.v1.schema.json', 'schemas/external-origin-catalog.v1.schema.json', 'schemas/fact-catalog.v1.schema.json', 'schemas/state-grammar.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/model-root.v1.schema.json', 'schemas/manifest.v1.schema.json',
  'src/canonical.mjs', 'src/sha256.mjs', 'src/model.mjs',
  'test/digest.kat.json', 'test/digest.test.mjs', 'test/model.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs'
];
const UPSTREAM = [
  '../cohort-runtime-binding-v1/runtime-binding-root.v1.json',
  '../cohort-runtime-binding-v1/MANIFEST.json',
  '../cohort-runtime-binding-v1/SHA256SUMS',
  '../cohort-runner-core-v1/runtime-core.v1.json',
  '../cohort-runner-core-v1/MANIFEST.json',
  '../cohort-runner-core-v1/SHA256SUMS',
  '../cohort-runner-core-v1/schemas/worker-row.v1.schema.json',
  '../cohort-runner-core-v1/schemas/dispatch-plan.v1.schema.json',
  '../cohort-frozen-inputs-v1/frozen-inputs-root.v1.json',
  '../cohort-frozen-inputs-v1/MANIFEST.json',
  '../cohort-frozen-inputs-v1/SHA256SUMS',
  '../cohort-policy-authority-v1/policy-authority-root.v1.json',
  '../cohort-policy-authority-v1/MANIFEST.json',
  '../cohort-policy-authority-v1/SHA256SUMS',
  '../cohort-live-executor-v2/model-root.v2.json',
  '../cohort-live-executor-v2/MANIFEST.json',
  '../cohort-live-executor-v2/SHA256SUMS',
  '../cohort-live-executor-v2/validate-static.mjs'
];

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function frame(domain, value) {
  return sha256(Buffer.from(`${domain}\u0000${canonical(value)}\n`, 'utf8'));
}

function readJson(root, locator) {
  return JSON.parse(readFileSync(resolve(root, locator), 'utf8'));
}

function writeJson(root, locator, value) {
  writeFileSync(resolve(root, locator), `${canonical(value)}\n`);
}

function refreshRootDigest(root) {
  const document = readJson(root, 'authority-binding-root.v1.json');
  const payload = { ...document };
  delete payload.contentDigest;
  document.contentDigest.value = frame(`${PREFIX}root`, payload);
  writeJson(root, 'authority-binding-root.v1.json', document);
}

function refreshEnvelope(root) {
  const entries = FILES.map((locator) => {
    const bytes = readFileSync(resolve(root, locator));
    return { locator, bytes: bytes.length, sha256: sha256(bytes), fileDigest: rawFileDigest(bytes) };
  });
  const manifest = {
    schema: `${PREFIX}manifest/v1`,
    format: `${PREFIX}manifest/1`,
    package: 'cohort-authority-binding-model-v1',
    entryCount: FILES.length,
    entries,
    rosterDigest: frame(`${PREFIX}manifest-roster`, { package: 'cohort-authority-binding-model-v1', entries })
  };
  writeJson(root, 'MANIFEST.json', manifest);
  const sums = [...entries, { locator: 'MANIFEST.json', sha256: sha256(readFileSync(resolve(root, 'MANIFEST.json'))) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  writeFileSync(resolve(root, 'SHA256SUMS'), `${sums}\n`);
}

function fixture() {
  const temporary = mkdtempSync(resolve(dirname(ROOT), '.cabm-v1-'));
  const gate = resolve(temporary, 'gate-b');
  const root = resolve(gate, 'cohort-authority-binding-model-v1');
  mkdirSync(gate, { recursive: true });
  cpSync(ROOT, root, { recursive: true });
  for (const locator of UPSTREAM) {
    const source = resolve(ROOT, locator);
    const target = resolve(root, locator);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
  }
  refreshEnvelope(root);
  return { root, temporary };
}

function withFixture(run) {
  const value = fixture();
  try {
    return run(value.root, value.temporary);
  } finally {
    rmSync(value.temporary, { recursive: true, force: true });
    assert.equal(existsSync(value.temporary), false, 'temporary mutation root cleaned');
  }
}

async function withFixtureAsync(run) {
  const value = fixture();
  try {
    return await run(value.root, value.temporary);
  } finally {
    rmSync(value.temporary, { recursive: true, force: true });
    assert.equal(existsSync(value.temporary), false, 'temporary mutation root cleaned');
  }
}

function mutateRoot(root, mutate) {
  const document = readJson(root, 'authority-binding-root.v1.json');
  mutate(document);
  writeJson(root, 'authority-binding-root.v1.json', document);
  refreshRootDigest(root);
  refreshEnvelope(root);
}

function expectRejected(label, mutate) {
  withFixture((root) => {
    mutate(root);
    assert.throws(() => validateStatic({ root }), label);
  });
}

function changeSourcePin(root, locator) {
  const validator = resolve(root, 'validate-static.mjs');
  const sourceHash = sha256(readFileSync(resolve(root, locator)));
  const source = readFileSync(validator, 'utf8');
  const matcher = new RegExp(`('${locator.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}': ')[0-9a-f]{64}(')`);
  const changed = source.replace(matcher, `$1${sourceHash}$2`);
  assert.notEqual(changed, source, `source pin for ${locator}`);
  writeFileSync(validator, changed);
}

async function importTemporaryValidator(root) {
  return import(`${pathToFileURL(resolve(root, 'validate-static.mjs')).href}?mutation=${Math.random()}`);
}

test('temporary complete envelope validates before every causal mutation', () => {
  withFixture((root) => assert.equal(validateStatic({ root }), true));
});

test('semantic catalog, guard, alias, and cardinality mutants are rejected', () => {
  const mutations = [
    ['origin roster', (root) => mutateRoot(root, (document) => document.externalOrigins.entries.pop())],
    ['fact moved into origin roster', (root) => mutateRoot(root, (document) => { document.externalOrigins.entries[0].id = 'A'; })],
    ['static template origin roster', (root) => mutateRoot(root, (document) => { document.externalOrigins.entries[1].id = 'LIVE_F_TEMPLATE'; })],
    ['authority grant', (root) => mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'C').grantsAuthority = true; })],
    ['J predecessor', (root) => mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'J').statePredecessors.initial = ['B']; })],
    ['retry edge in DAG', (root) => mutateRoot(root, (document) => document.pinnedAuthorityDag.edges.push('RETRY_PREDECESSOR→Q'))],
    ['retry predecessor removal', (root) => mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'Q').statePredecessors.retry = []; })],
    ['retry state admission', (root) => mutateRoot(root, (document) => { document.stateGrammar.retry.stateFacts = ['Q']; })],
    ['template as capture origin', (root) => mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'LIVE_F').originRequirements.initial = ['LIVE_F_TEMPLATE']; })],
    ['B capture cycle', (root) => mutateRoot(root, (document) => { document.stateGrammar.capture.bToOriginAuthorityEdge = true; })],
    ['D worker guard removal', (root) => mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'D').statePredecessors.initial = ['B', 'C', 'J']; })],
    ['D admission', (root) => mutateRoot(root, (document) => { document.stateGrammar.d.neverAdmitted = false; })],
    ['schema-shaped worker root substituted', (root) => mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'D').originRequirements.initial = ['0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef']; })],
    ['static dependency in state facts', (root) => mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'B').statePredecessors.initial.push('P'); })],
    ['worker-row maximum equated', (root) => mutateRoot(root, (document) => { document.cardinalitySeparation.workerRowSchema.maximum = 4608; })],
    ['projection derivation', (root) => mutateRoot(root, (document) => { document.cardinalitySeparation.projection.mayDerive = true; })],
    ['engine alias interchange', (root) => mutateRoot(root, (document) => { document.stateGrammar.aliasSeparation.workerRowEndpointIds[0] = 'engine:native'; })],
    ['invented worker root domain', (root) => mutateRoot(root, (document) => { document.stateGrammar.aliasSeparation.workerRowsRootDomain = 'worker-rows-root'; })],
    ['native alias map mismatch', (root) => mutateRoot(root, (document) => { document.staticDependencies.entries.find((entry) => entry.id === 'P').pins.find((pin) => pin.id === 'worker-alias-map').value = 'native=>engine:libauth,libauth=>engine:libauth,bchn=>engine:bchn,leanbch-primary=>engine:leanbch:primary,leanbch-secondary=>engine:leanbch:secondary'; })],
    ['crash retry synthesis', (root) => mutateRoot(root, (document) => { document.stateGrammar.crashPolicy.createsRetryPredecessor = true; })],
    ['abort retry synthesis', (root) => mutateRoot(root, (document) => { document.stateGrammar.abort.synthesizesRetryPredecessor = true; })],
  ];
  for (const [label, mutate] of mutations) expectRejected(label, mutate);
});

test('schema domain, raw-file frame, and schema loosening mutants are rejected', () => {
  expectRejected('wrong root digest domain', (root) => {
    const document = readJson(root, 'authority-binding-root.v1.json');
    document.contentDigest.domain = `${PREFIX}fact-catalog`;
    writeJson(root, 'authority-binding-root.v1.json', document);
    refreshEnvelope(root);
  });
  expectRejected('raw file digest metadata framing', (root) => {
    const manifest = readJson(root, 'MANIFEST.json');
    manifest.entries[0].fileDigest = frame(`${PREFIX}file`, { locator: manifest.entries[0].locator });
    writeJson(root, 'MANIFEST.json', manifest);
    const lines = manifest.entries.map((entry) => `${entry.sha256}  ${entry.locator}`);
    lines.push(`${sha256(readFileSync(resolve(root, 'MANIFEST.json')))}  MANIFEST.json`);
    writeFileSync(resolve(root, 'SHA256SUMS'), `${lines.join('\n')}\n`);
  });
  expectRejected('schema loosening', (root) => {
    const locator = 'schemas/digest.v1.schema.json';
    const path = resolve(root, locator);
    writeFileSync(path, readFileSync(path, 'utf8').replace('"additionalProperties":false', '"additionalProperties":true'));
    refreshEnvelope(root);
  });
});

test('source import, activation, and direct writer-export scanners remain causal after a coordinated source pin update', async () => {
  await withFixtureAsync(async (root) => {
    const model = resolve(root, 'src/model.mjs');
    writeFileSync(model, readFileSync(model, 'utf8').replace("import { canonicalJson, utf8Encode } from './canonical.mjs';", "import './unrelated.mjs';\nimport { canonicalJson, utf8Encode } from './canonical.mjs';"));
    changeSourcePin(root, 'src/model.mjs');
    refreshEnvelope(root);
    const temporary = await importTemporaryValidator(root);
    assert.throws(() => temporary.validateStatic({ root }), 'side-effect import');
  });
  await withFixtureAsync(async (root) => {
    const model = resolve(root, 'src/model.mjs');
    writeFileSync(model, readFileSync(model, 'utf8').replace('export {\n', 'const activationSurface = globalThis;\n\nexport {\n'));
    changeSourcePin(root, 'src/model.mjs');
    refreshEnvelope(root);
    const temporary = await importTemporaryValidator(root);
    assert.throws(() => temporary.validateStatic({ root }), 'activation surface');
  });
  await withFixtureAsync(async (root) => {
    const model = resolve(root, 'src/model.mjs');
    writeFileSync(model, readFileSync(model, 'utf8').replace('export {\n', 'export const writer = null;\n\nexport {\n'));
    changeSourcePin(root, 'src/model.mjs');
    refreshEnvelope(root);
    const temporary = await importTemporaryValidator(root);
    assert.throws(() => temporary.validateStatic({ root }), 'writer export');
  });
  await withFixtureAsync(async (root) => {
    const model = resolve(root, 'src/model.mjs');
    writeFileSync(model, readFileSync(model, 'utf8').replace('export {\n', 'const copiedStaticRuntime = admitDispatch;\n\nexport {\n'));
    changeSourcePin(root, 'src/model.mjs');
    refreshEnvelope(root);
    const temporary = await importTemporaryValidator(root);
    assert.throws(() => temporary.validateStatic({ root }), 'source copy locator');
  });
});

test('transitive raw leaves and gate-b component walk reject stale or linked upstream inputs', () => {
  expectRejected('transitive manifest raw pin', (root) => {
    writeFileSync(resolve(root, '../cohort-runtime-binding-v1/MANIFEST.json'), '{"changed":true}\n');
  });
  expectRejected('transitive sums raw pin', (root) => {
    writeFileSync(resolve(root, '../cohort-frozen-inputs-v1/SHA256SUMS'), '00  changed\n');
  });
  expectRejected('intermediate upstream package symlink', (root) => {
    const upstream = resolve(root, '../cohort-policy-authority-v1');
    const mirror = resolve(dirname(upstream), 'cohort-policy-authority-v1-copy');
    cpSync(upstream, mirror, { recursive: true });
    rmSync(upstream, { recursive: true, force: true });
    symlinkSync('cohort-policy-authority-v1-copy', upstream);
  });
  expectRejected('upstream pinned leaf hardlink', (root) => {
    const leaf = resolve(root, '../cohort-policy-authority-v1/policy-authority-root.v1.json');
    const mirror = `${leaf}.copy`;
    copyFileSync(leaf, mirror);
    rmSync(leaf);
    linkSync(mirror, leaf);
  });
});

test('filesystem and manifest closure mutants are rejected', () => {
  expectRejected('extra file', (root) => writeFileSync(resolve(root, 'extra.txt'), 'x\n'));
  expectRejected('extra directory', (root) => mkdirSync(resolve(root, 'empty-extra')));
  expectRejected('wrong file mode', (root) => chmodSync(resolve(root, 'README.md'), 0o600));
  expectRejected('symlink', (root) => {
    const source = resolve(root, 'src/sha256.mjs');
    const backup = resolve(root, 'src/sha256-real.mjs');
    copyFileSync(source, backup);
    rmSync(source);
    symlinkSync('sha256-real.mjs', source);
  });
  expectRejected('hardlink', (root) => {
    const source = resolve(root, 'COMMAND.txt');
    const target = resolve(root, 'README.md');
    rmSync(target);
    linkSync(source, target);
  });
  expectRejected('manifest locator order', (root) => {
    const manifest = readJson(root, 'MANIFEST.json');
    [manifest.entries[0], manifest.entries[1]] = [manifest.entries[1], manifest.entries[0]];
    writeJson(root, 'MANIFEST.json', manifest);
    const lines = manifest.entries.map((entry) => `${entry.sha256}  ${entry.locator}`);
    lines.push(`${sha256(readFileSync(resolve(root, 'MANIFEST.json')))}  MANIFEST.json`);
    writeFileSync(resolve(root, 'SHA256SUMS'), `${lines.join('\n')}\n`);
  });
});

test('coordinated replacement is locally accepted but detectable by an external raw anchor', async () => {
  await withFixtureAsync(async (root) => {
    const realPins = {
      validator: sha256(readFileSync(resolve(root, 'validate-static.mjs'))),
      root: sha256(readFileSync(resolve(root, 'authority-binding-root.v1.json'))),
      manifest: sha256(readFileSync(resolve(root, 'MANIFEST.json'))),
      sums: sha256(readFileSync(resolve(root, 'SHA256SUMS'))),
    };
    mutateRoot(root, (document) => { document.facts.entries.find((entry) => entry.id === 'D').grantsAuthority = true; });
    const schema = readJson(root, 'schemas/fact-catalog.v1.schema.json');
    schema.$defs.factEntry.properties.grantsAuthority.const = true;
    writeJson(root, 'schemas/fact-catalog.v1.schema.json', schema);
    writeFileSync(resolve(root, 'validate-static.mjs'), 'function validateStatic() { return true; }\nexport { validateStatic };\n');
    refreshEnvelope(root);
    const replacement = await importTemporaryValidator(root);
    assert.equal(replacement.validateStatic({ root }), true, 'replacement local validator accepts its own coordinated bytes');
    assert.notEqual(sha256(readFileSync(resolve(root, 'validate-static.mjs'))), realPins.validator, 'external validator raw pin');
    assert.notEqual(sha256(readFileSync(resolve(root, 'authority-binding-root.v1.json'))), realPins.root, 'external root raw pin');
    assert.notEqual(sha256(readFileSync(resolve(root, 'MANIFEST.json'))), realPins.manifest, 'external manifest raw pin');
    assert.notEqual(sha256(readFileSync(resolve(root, 'SHA256SUMS'))), realPins.sums, 'external sums raw pin');
  });
});
