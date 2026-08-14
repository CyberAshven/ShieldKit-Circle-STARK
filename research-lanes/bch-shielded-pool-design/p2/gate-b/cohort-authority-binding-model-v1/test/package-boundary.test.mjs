import assert from 'node:assert/strict';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const directories = ['.', 'schemas', 'src', 'test'];
const files = [
  'COMMAND.txt', 'README.md', 'authority-binding-root.v1.json', 'validate-static.mjs',
  'schemas/authority-dag.v1.schema.json', 'schemas/dependency-catalog.v1.schema.json', 'schemas/external-origin-catalog.v1.schema.json', 'schemas/fact-catalog.v1.schema.json', 'schemas/state-grammar.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/model-root.v1.schema.json', 'schemas/manifest.v1.schema.json',
  'src/canonical.mjs', 'src/sha256.mjs', 'src/model.mjs',
  'test/digest.kat.json', 'test/digest.test.mjs', 'test/model.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs',
  'MANIFEST.json', 'SHA256SUMS'
];

function collect(directory = ROOT, prefix = '') {
  const foundFiles = [];
  const foundDirectories = [prefix || '.'];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const locator = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = resolve(directory, entry.name);
    const stat = lstatSync(absolute);
    assert.equal(stat.isSymbolicLink(), false, `${locator} link`);
    if (stat.isDirectory()) {
      const nested = collect(absolute, locator);
      foundFiles.push(...nested.files);
      foundDirectories.push(...nested.directories);
    } else {
      assert.equal(stat.isFile(), true, `${locator} regular file`);
      foundFiles.push(locator);
    }
  }
  return { files: foundFiles, directories: foundDirectories };
}

function imports(source) {
  return [
    ...source.matchAll(/\bimport\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/g),
    ...source.matchAll(/\bexport\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g),
  ].map((match) => match[1]);
}

test('sealed closure has exactly the approved files and directories', () => {
  const found = collect();
  assert.deepEqual(found.directories.sort(), [...directories].sort());
  assert.deepEqual(found.files.sort(), [...files].sort());
  for (const locator of directories) {
    const stat = lstatSync(resolve(ROOT, locator));
    assert.equal(stat.nlink, 1, `${locator} nlink`);
    assert.equal(stat.mode & 0o7777, 0o755, `${locator} mode`);
  }
  for (const locator of files) {
    const stat = lstatSync(resolve(ROOT, locator));
    assert.equal(stat.nlink, 1, `${locator} nlink`);
    assert.equal(stat.mode & 0o7777, 0o644, `${locator} mode`);
  }
});

test('pure source import graph is exactly local and closed', () => {
  const expected = {
    'canonical.mjs': [],
    'sha256.mjs': [],
    'model.mjs': ['./canonical.mjs', './sha256.mjs'],
  };
  for (const [name, expectedImports] of Object.entries(expected)) {
    const source = readFileSync(resolve(ROOT, 'src', name), 'utf8');
    assert.deepEqual(imports(source), expectedImports, name);
    assert.equal(/node:|\bimport\.meta\b|\bimport\s*\(|\brequire\s*\(/.test(source), false, name);
    assert.equal(/\b(?:eval|Function|globalThis|WebAssembly|Deno|Bun|Worker|SharedWorker|process|setTimeout|setInterval|queueMicrotask|fetch|WebSocket|XMLHttpRequest|child_process|vm|net|http|https)\b/.test(source), false, name);
  }
});

test('pure sources expose only terminal exact export lists', () => {
  const expected = {
    'canonical.mjs': ['canonicalJson', 'utf8Encode'],
    'sha256.mjs': ['sha256Hex'],
    'model.mjs': ['AUTHORITY_DAG', 'DEPENDENCY_CATALOG', 'EXTERNAL_ORIGINS', 'FACT_CATALOG', 'STATE_GRAMMAR', 'DISPOSITIONS', 'assertAuthorityDag', 'assertDependencyCatalog', 'assertExternalOrigins', 'assertFactCatalog', 'assertStateGrammar', 'requiredPredecessors', 'ownerOf', 'availabilityOf', 'authorityDisposition', 'authorityDagDigest', 'dependencyCatalogDigest', 'externalOriginsDigest', 'factCatalogDigest', 'stateGrammarDigest', 'modelRootDigest'],
  };
  for (const [name, expectedExports] of Object.entries(expected)) {
    const source = readFileSync(resolve(ROOT, 'src', name), 'utf8');
    const terminal = source.match(/export\s*\{([\s\S]*?)\};\s*$/);
    assert.ok(terminal, name);
    assert.equal(/\bexport\b/.test(source.slice(0, terminal.index)), false, name);
    assert.deepEqual(terminal[1].split(',').map((value) => value.trim()).filter(Boolean), expectedExports, name);
  }
});

test('root and schemas are canonical JSON with exactly one final LF', () => {
  const jsonFiles = [
    'authority-binding-root.v1.json',
    'schemas/authority-dag.v1.schema.json', 'schemas/dependency-catalog.v1.schema.json', 'schemas/external-origin-catalog.v1.schema.json', 'schemas/fact-catalog.v1.schema.json', 'schemas/state-grammar.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/model-root.v1.schema.json', 'schemas/manifest.v1.schema.json',
    'test/digest.kat.json', 'MANIFEST.json'
  ];
  for (const locator of jsonFiles) {
    const text = readFileSync(resolve(ROOT, locator), 'utf8');
    assert.equal(text.includes('\r'), false, locator);
    assert.equal(text.endsWith('\n'), true, locator);
    assert.equal(text.endsWith('\n\n'), false, locator);
    assert.doesNotThrow(() => JSON.parse(text), locator);
  }
});

test('documentation states the external closure boundary', () => {
  const readme = readFileSync(resolve(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /cannot establish integrity if it and the sealed package bytes are changed together/);
  assert.match(readme, /validator raw SHA-256 together with the root, manifest, and checksum bytes/);
});
