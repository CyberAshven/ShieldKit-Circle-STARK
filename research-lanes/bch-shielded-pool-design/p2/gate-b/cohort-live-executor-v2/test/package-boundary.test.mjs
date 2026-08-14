import assert from 'node:assert/strict';
import { lstat, readdir, readFile } from 'node:fs/promises';
import test from 'node:test';
import * as model from '../src/model.mjs';
import * as stateMachine from '../src/state-machine.mjs';
import { canonicalJson } from '../src/canonical.mjs';

const root = new URL('../', import.meta.url);
const entries = [
  'COMMAND.txt', 'README.md', 'model-root.v2.json', 'validate-static.mjs',
  'schemas/authority-dag.v2.schema.json', 'schemas/digest.v2.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/model-root.v2.schema.json', 'schemas/state.v2.schema.json', 'schemas/transition-grammar.v2.schema.json',
  'src/canonical.mjs', 'src/model.mjs', 'src/sha256.mjs', 'src/state-machine.mjs',
  'test/digest.kat.json', 'test/digest.test.mjs', 'test/model.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/state-machine.test.mjs',
];

test('the package closure is exact, regular, single-link, and mode-sealed', async () => {
  const actual = [];
  for (const directory of ['', 'schemas', 'src', 'test']) {
    const directoryUrl = new URL(`${directory ? `${directory}/` : ''}`, root);
    const stat = await lstat(directoryUrl);
    assert.ok(stat.isDirectory());
    assert.equal(stat.mode & 0o7777, 0o755);
    if (directory) for (const entry of await readdir(directoryUrl)) actual.push(`${directory}/${entry}`);
  }
  for (const name of await readdir(root)) if (!['schemas', 'src', 'test'].includes(name)) actual.push(name);
  assert.deepEqual(actual.sort(), [...entries, 'MANIFEST.json', 'SHA256SUMS'].sort());
  for (const locator of [...entries, 'MANIFEST.json', 'SHA256SUMS']) {
    const stat = await lstat(new URL(locator, root));
    assert.ok(stat.isFile());
    assert.equal(stat.nlink, 1);
    assert.equal(stat.mode & 0o7777, 0o644);
  }
});

test('pure API and import closure are exact', async () => {
  assert.deepEqual(Object.keys(model).sort(), ['AUTHORITY_DAG', 'EVENTS', 'FACTS', 'TRANSITION_GRAMMAR', 'VARIANTS', 'VERDICTS', 'assertAuthorityDag', 'assertTransitionGrammar', 'authorityDagDigest', 'modelRootDigest', 'requiredPredecessors', 'stateDigest', 'transitionGrammarDigest']);
  assert.deepEqual(Object.keys(stateMachine).sort(), ['assertState', 'emptyState', 'guardTransition', 'replay', 'transition']);
  const sources = await Promise.all(['canonical.mjs', 'sha256.mjs', 'model.mjs', 'state-machine.mjs'].map((name) => readFile(new URL(`src/${name}`, root), 'utf8')));
  for (const source of sources) assert.doesNotMatch(source, /node:|from\s+['"][^./]|import\s*\(|require\s*\(|child_process|Worker|process\.|fetch\(/);
  assert.deepEqual([...sources[2].matchAll(/from '([^']+)'/g)].map((match) => match[1]), ['./canonical.mjs', './sha256.mjs']);
  assert.deepEqual([...sources[3].matchAll(/from '([^']+)'/g)].map((match) => match[1]), ['./model.mjs']);
});

test('checked JSON is canonical and the root binds each P pin', async () => {
  for (const locator of entries.filter((name) => name.endsWith('.json')).concat('MANIFEST.json')) {
    const text = await readFile(new URL(locator, root), 'utf8');
    assert.equal(text, `${canonicalJson(JSON.parse(text))}\n`, locator);
  }
  const rootDocument = JSON.parse(await readFile(new URL('model-root.v2.json', root), 'utf8'));
  assert.equal(rootDocument.authority.pRoot.rawSha256, 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e');
  assert.equal(rootDocument.authority.pRoot.contentDigest, '9f040a5bbafc56a71dcd19081262c5411eea91e1fc35707ae4a0c2aa784c3f50');
  assert.equal(rootDocument.authority.pRoot.bindingDigest, '36ab3e7ca0594ef20c9ac1ec9f4f2ec21a3ed415815bde51d1e0c63163e4a654');
  assert.equal(rootDocument.authority.pRoot.policyDigest, '179009bd062d3207a995ee68da150e5c1622d4ad1576a68474d1d8331594e0bf');
  assert.equal(rootDocument.authority.pRoot.authorityDagDigest, '98a4ba8298744602e9979ce0e4fc28883953fecac467993d2196bcf279bbfd4d');
  assert.equal(rootDocument.authority.pRoot.liveFDigest, '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be');
});
