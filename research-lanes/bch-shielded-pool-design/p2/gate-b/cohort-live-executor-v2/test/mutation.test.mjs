import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFile, chmod, cp, link, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonicalJson } from '../src/canonical.mjs';
import { AUTHORITY_DAG, TRANSITION_GRAMMAR, assertAuthorityDag, assertTransitionGrammar } from '../src/model.mjs';
import { assertState, emptyState, transition } from '../src/state-machine.mjs';
import { validateStatic } from '../validate-static.mjs';

const PACKAGE_ROOT = fileURLToPath(new URL('../', import.meta.url));
const P_ROOT = fileURLToPath(new URL('../cohort-policy-authority-v1/policy-authority-root.v1.json', new URL('../', import.meta.url)));
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/';
const FILES = [
  'COMMAND.txt', 'README.md', 'model-root.v2.json', 'validate-static.mjs',
  'schemas/authority-dag.v2.schema.json', 'schemas/digest.v2.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/model-root.v2.schema.json', 'schemas/state.v2.schema.json', 'schemas/transition-grammar.v2.schema.json',
  'src/canonical.mjs', 'src/model.mjs', 'src/sha256.mjs', 'src/state-machine.mjs',
  'test/digest.kat.json', 'test/digest.test.mjs', 'test/model.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/state-machine.test.mjs',
];
const P_BINDING = {
  schema: 'shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/root',
  artifactId: 'artifact:gate-b:cohort-policy-authority-v1',
  path: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-policy-authority-v1/policy-authority-root.v1.json',
  rawSha256: 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e',
  contentDigest: '9f040a5bbafc56a71dcd19081262c5411eea91e1fc35707ae4a0c2aa784c3f50',
  bindingDigest: '36ab3e7ca0594ef20c9ac1ec9f4f2ec21a3ed415815bde51d1e0c63163e4a654',
  policyDigest: '179009bd062d3207a995ee68da150e5c1622d4ad1576a68474d1d8331594e0bf',
  authorityDagDigest: '98a4ba8298744602e9979ce0e4fc28883953fecac467993d2196bcf279bbfd4d',
  liveFDigest: '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be',
};

function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function framed(domain, value) { return sha256(Buffer.from(`${domain}\u0000${canonicalJson(value)}\n`, 'utf8')); }
function rawFileDigest(bytes) { return sha256(Buffer.concat([Buffer.from(`${PREFIX}file\u0000`, 'utf8'), bytes])); }
function jsonText(value) { return `${canonicalJson(value)}\n`; }
async function readJson(root, locator) { return JSON.parse(await readFile(join(root, locator), 'utf8')); }
async function writeJson(root, locator, value) { await writeFile(join(root, locator), jsonText(value), { mode: 0o644 }); }
async function rebuildEnvelope(root) {
  const modelRoot = await readJson(root, 'model-root.v2.json');
  const payload = { authority: modelRoot.authority, authorityDag: modelRoot.authorityDag, identifier: modelRoot.identifier, schema: modelRoot.schema, transitionGrammar: modelRoot.transitionGrammar };
  modelRoot.contentDigest = { algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: `${PREFIX}root`, frame: 'utf8(domain)||0x00||canonical-json-utf8-lf-v1', value: framed(`${PREFIX}root`, payload) };
  await writeJson(root, 'model-root.v2.json', modelRoot);
  await rebuildManifestAndSums(root);
}
async function rebuildManifestAndSums(root) {
  const entries = [];
  for (const locator of FILES) {
    const bytes = await readFile(join(root, locator));
    const sha = sha256(bytes);
    entries.push({ locator, bytes: bytes.length, sha256: sha, fileDigest: rawFileDigest(bytes) });
  }
  const manifest = { schema: `${PREFIX}manifest/v1`, format: `${PREFIX}manifest/1`, package: 'cohort-live-executor-v2', entryCount: FILES.length, entries, rosterDigest: framed(`${PREFIX}manifest-roster`, { package: 'cohort-live-executor-v2', entries }) };
  await writeJson(root, 'MANIFEST.json', manifest);
  const sums = [...entries, { locator: 'MANIFEST.json', sha256: sha256(await readFile(join(root, 'MANIFEST.json'))) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  await writeFile(join(root, 'SHA256SUMS'), `${sums}\n`, { mode: 0o644 });
}
async function draftEnvelope(root) {
  const authority = { pRoot: P_BINDING, semanticBindingDigest: framed(`${PREFIX}policy-authority-binding`, P_BINDING) };
  await writeJson(root, 'model-root.v2.json', {
    schema: `${PREFIX}model-root/v2`, identifier: 'cohort-live-executor-v2', authority,
    authorityDag: AUTHORITY_DAG, transitionGrammar: TRANSITION_GRAMMAR,
    contentDigest: { algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: `${PREFIX}root`, frame: 'utf8(domain)||0x00||canonical-json-utf8-lf-v1', value: '0'.repeat(64) },
  });
  await rebuildEnvelope(root);
}
async function withCopy(action) {
  const temporary = await mkdtemp(join(tmpdir(), 'cohort-live-executor-v2-'));
  try {
    await cp(PACKAGE_ROOT, temporary, { recursive: true, dereference: false });
    await chmod(temporary, 0o755);
    await draftEnvelope(temporary);
    await action(temporary);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
async function mustReject(temporary) {
  assert.throws(() => validateStatic({ root: temporary, pRootPath: P_ROOT }), /static validation failed/);
}

test('semantic mutations are rejected without an external satisfier', () => {
  const state = emptyState('initial');
  const malformed = [
    { ...state, facts: ['D'] },
    { ...state, facts: ['Q', 'A', 'LIVE_F', 'B', 'J'] },
    { ...state, facts: ['Q', 'LIVE_F', 'A', 'B', 'C', 'J', 'J'] },
    { ...state, variant: 'retry', facts: ['Q'] },
  ];
  for (const candidate of malformed) assert.throws(() => assertState(candidate));
  assert.notStrictEqual(transition(state, 'MATCH_D').state, state);
});

test('canonicalization mutations are rejected or visibly distinct', () => {
  assert.throws(() => canonicalJson(new Date(0)), /nonplain/);
  assert.throws(() => canonicalJson(Object.create({ inherited: true })), /nonplain/);
  assert.throws(() => canonicalJson({ value: Infinity }), /non-canonical/);
  assert.notEqual(canonicalJson({ a: ['B', 'C'] }), canonicalJson({ a: ['C', 'B'] }));
});

test('pure source graph excludes imports, activation, and execution surfaces', async () => {
  const root = new URL('../src/', import.meta.url);
  const sources = await Promise.all(['canonical.mjs', 'sha256.mjs', 'model.mjs', 'state-machine.mjs'].map((name) => readFile(new URL(name, root), 'utf8')));
  const all = sources.join('\n');
  assert.doesNotMatch(all, /node:|from\s+['"][^./]/);
  assert.doesNotMatch(all, /import\s*\(|child_process|Worker|process\.|fetch\(|net\.|http\.|https\.|fs\./);
  assert.match(sources[2], /from '\.\/canonical\.mjs'/);
  assert.match(sources[2], /from '\.\/sha256\.mjs'/);
  assert.match(sources[3], /from '\.\/model\.mjs'/);
});

test('DAG and grammar mutators cannot substitute a different authority model', () => {
  const dag = { nodes: [...AUTHORITY_DAG.nodes], edges: [...AUTHORITY_DAG.edges] };
  dag.edges[17] = 'P→J';
  assert.throws(() => assertAuthorityDag(dag));
  const grammar = JSON.parse(JSON.stringify(TRANSITION_GRAMMAR));
  grammar.predecessors.J = ['P'];
  assert.throws(() => assertTransitionGrammar(grammar));
});

test('sealed static validation causally rejects P pins, source surfaces, and filesystem envelope mutations', async () => {
  for (const pin of ['schema', 'artifactId', 'path', 'rawSha256', 'contentDigest', 'bindingDigest', 'policyDigest', 'authorityDagDigest', 'liveFDigest']) {
    await withCopy(async (temporary) => {
      assert.equal(validateStatic({ root: temporary, pRootPath: P_ROOT }), true);
      const root = await readJson(temporary, 'model-root.v2.json');
      root.authority.pRoot[pin] = '0'.repeat(64);
      await writeJson(temporary, 'model-root.v2.json', root);
      await rebuildEnvelope(temporary);
      await mustReject(temporary);
    });
  }
  await withCopy(async (temporary) => {
    const root = await readJson(temporary, 'model-root.v2.json');
    root.authorityDag.edges.pop();
    await writeJson(temporary, 'model-root.v2.json', root);
    await rebuildEnvelope(temporary);
    await mustReject(temporary);
  });
  for (const mutate of [
    (root) => { root.transitionGrammar.externalGuards.retryQ = 'SATISFIED'; },
    (root) => { delete root.transitionGrammar.externalGuards.retryQ; },
    (root) => { root.transitionGrammar.predecessors.C = []; },
    (root) => { root.executionAllowed = true; },
  ]) {
    await withCopy(async (temporary) => {
      const root = await readJson(temporary, 'model-root.v2.json');
      mutate(root);
      await writeJson(temporary, 'model-root.v2.json', root);
      await rebuildEnvelope(temporary);
      await mustReject(temporary);
    });
  }
  for (const mutate of [
    (root) => { root.contentDigest.frame = 'wrong'; },
    (root) => { root.contentDigest.domain = `${PREFIX}state`; },
    (root) => { delete root.contentDigest; },
  ]) {
    await withCopy(async (temporary) => {
      const root = await readJson(temporary, 'model-root.v2.json');
      mutate(root);
      await writeJson(temporary, 'model-root.v2.json', root);
      await rebuildManifestAndSums(temporary);
      await mustReject(temporary);
    });
  }
  await withCopy(async (temporary) => {
    await appendFile(join(temporary, 'src/canonical.mjs'), "\nimport './forbidden.mjs';\n");
    await rebuildEnvelope(temporary);
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await appendFile(join(temporary, 'src/sha256.mjs'), '\nglobalThis.sideEffect = true;\n');
    await rebuildEnvelope(temporary);
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    const locator = join(temporary, 'src/sha256.mjs');
    const source = await readFile(locator, 'utf8');
    await writeFile(locator, source.replace('export { sha256Hex };', 'export const writer = true;\n\nexport { sha256Hex };'), { mode: 0o644 });
    await rebuildEnvelope(temporary);
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    const schema = await readJson(temporary, 'schemas/state.v2.schema.json');
    schema.properties.facts.items.enum.push('D');
    await writeJson(temporary, 'schemas/state.v2.schema.json', schema);
    await rebuildEnvelope(temporary);
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await writeFile(join(temporary, 'extra.txt'), 'x\n', { mode: 0o644 });
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await unlink(join(temporary, 'README.md'));
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await mkdir(join(temporary, 'extra'));
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await chmod(join(temporary, 'README.md'), 0o600);
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await symlink('README.md', join(temporary, 'link.md'));
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await unlink(join(temporary, 'README.md'));
    await link(join(temporary, 'COMMAND.txt'), join(temporary, 'README.md'));
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    const manifest = await readJson(temporary, 'MANIFEST.json');
    manifest.entries[0].fileDigest = '0'.repeat(64);
    await writeJson(temporary, 'MANIFEST.json', manifest);
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    await writeFile(join(temporary, 'SHA256SUMS'), '0'.repeat(64) + '  README.md\n', { mode: 0o644 });
    await mustReject(temporary);
  });
  await withCopy(async (temporary) => {
    const pDirectory = await mkdtemp(join(tmpdir(), 'cohort-live-executor-v2-p-'));
    const pCopy = join(pDirectory, 'p-root.json');
    try {
      await cp(P_ROOT, pCopy);
      await appendFile(pCopy, ' ');
      assert.throws(() => validateStatic({ root: temporary, pRootPath: pCopy }), /P raw SHA-256 pin changed/);
    } finally {
      await rm(pDirectory, { recursive: true, force: true });
    }
  });
});
