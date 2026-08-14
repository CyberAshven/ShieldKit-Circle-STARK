import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import * as core from '../src/contracts.mjs';

const CLOSURE = JSON.parse(await readFile(new URL('../runtime-core.v1.json', import.meta.url), 'utf8'));

function staticImports(source) {
  if (/\bimport\s*\(/.test(source)) throw new Error('dynamic import is outside K runtime closure');
  return [...source.matchAll(/^\s*import(?:[\s\S]*?\s+from)?\s*['"]([^'"]+)['"]\s*;?\s*$/gm)]
    .map((match) => match[1])
    .sort();
}

function assertRuntimeClosure(closure, sources) {
  assert.deepEqual(Object.keys(closure).sort(), ['buildTimeOnlyLocators', 'format', 'runtimeEntrypoint', 'runtimeExports', 'runtimeModules', 'typeModules']);
  assert.equal(closure.format, 'K/runtime-core/1');
  assert.equal(closure.runtimeEntrypoint, 'src/contracts.mjs');
  assert.deepEqual(closure.typeModules, ['src/interfaces.d.ts']);
  assert.deepEqual(closure.buildTimeOnlyLocators, ['generate.mjs', 'src/integrity.mjs', 'validate.mjs']);
  const declared = new Set(closure.runtimeModules.map((module) => module.locator));
  assert.deepEqual([...declared].sort(), ['src/contracts.mjs', 'src/file-contracts.mjs', 'src/strict.mjs']);
  for (const module of closure.runtimeModules) {
    assert.deepEqual(Object.keys(module).sort(), ['imports', 'locator']);
    const imports = staticImports(sources.get(module.locator));
    assert.deepEqual(imports, [...module.imports].sort(), `import graph differs at ${module.locator}`);
    for (const specifier of imports) {
      if (specifier.startsWith('node:')) {
        assert.equal(specifier, 'node:crypto');
      } else {
        assert.equal(specifier.startsWith('./'), true, `runtime import must remain local: ${specifier}`);
        const target = `src/${specifier.slice(2)}`;
        assert.equal(declared.has(target), true, `runtime import escapes closure: ${specifier}`);
      }
    }
  }
}

test('sealed runtime import closure excludes build tooling', async () => {
  const sources = new Map();
  for (const module of CLOSURE.runtimeModules) {
    sources.set(module.locator, await readFile(new URL(`../${module.locator}`, import.meta.url), 'utf8'));
  }
  assertRuntimeClosure(CLOSURE, sources);
  assert.equal(CLOSURE.runtimeModules.some((module) => CLOSURE.buildTimeOnlyLocators.includes(module.locator)), false);
  assert.deepEqual(Object.keys(core).sort(), [...CLOSURE.runtimeExports].sort());
});

test('causal import encoding and template mutants fail the runtime closure', async () => {
  const sources = new Map();
  for (const module of CLOSURE.runtimeModules) {
    sources.set(module.locator, await readFile(new URL(`../${module.locator}`, import.meta.url), 'utf8'));
  }
  const alteredStatic = new Map(sources);
  alteredStatic.set('src/contracts.mjs', `${sources.get('src/contracts.mjs')}\nimport './integrity.mjs';\n`);
  assert.throws(() => assertRuntimeClosure(CLOSURE, alteredStatic), /import graph differs/);
  const alteredTemplate = new Map(sources);
  alteredTemplate.set('src/contracts.mjs', `${sources.get('src/contracts.mjs')}\nawait import(\`./integrity.mjs\`);\n`);
  assert.throws(() => assertRuntimeClosure(CLOSURE, alteredTemplate), /dynamic import/);
});
