import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  packageDirectory,
  validateExternalRuntimeClosure,
  validateLibauthBundleReceipt,
  validateLibauthInputGraph,
  validateManifestPackage,
  validateNativeDescriptor,
} from './semantic-validators.mjs';

const here = new URL('.', import.meta.url);
const read = name => fs.readFileSync(new URL(name, here), 'utf8');
const parse = name => JSON.parse(read(name));
const clone = value => structuredClone(value);
const validateSchema = (schemaName, value) => {
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(parse(schemaName));
  assert.equal(validate(value), true, `${schemaName} rejected canonical KAT: ${JSON.stringify(validate.errors)}`);
};
const rejectSchema = (schemaName, value) => {
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(parse(schemaName));
  assert.equal(validate(value), false, `${schemaName} accepted a mutation`);
};

test('positive KATs validate every canonical descriptor and closure', () => {
  const runtime = parse('external-runtime-closure.v1.json');
  const native = parse('native-descriptor.v1.json');
  const graph = parse('libauth-input-graph.v1.json');
  const receipt = parse('libauth-bundle-receipt.v1.json');
  const manifest = parse('MANIFEST.json');
  validateSchema('runtime-closure.v1.schema.json', runtime);
  validateSchema('native-descriptor.v1.schema.json', native);
  validateSchema('libauth-input-graph.v1.schema.json', graph);
  validateSchema('libauth-bundle-receipt.v1.schema.json', receipt);
  validateSchema('manifest.v1.schema.json', manifest);
  assert.deepEqual(validateExternalRuntimeClosure(runtime).ok, true);
  assert.deepEqual(validateNativeDescriptor(native).ok, true);
  assert.deepEqual(validateLibauthInputGraph(graph).ok, true);
  assert.deepEqual(validateLibauthBundleReceipt(receipt).ok, true);
  assert.deepEqual(validateManifestPackage(manifest, packageDirectory).ok, true);
});

test('Native source remains closed and expected/corpus-independent', () => {
  const source = read('native-evaluator.mjs');
  assert.doesNotMatch(source, /^\s*import\s/m);
  assert.doesNotMatch(source, /\bimport\s*\(/u);
  assert.doesNotMatch(source, /\brequire\s*\(/u);
  assert.doesNotMatch(source, /node:(?:fs|net|http|https|child_process|dgram|tls)/u);
  assert.doesNotMatch(source, /\b(?:fetch|WebAssembly)\s*\(/u);
  assert.doesNotMatch(source, /\.node\b/u);
  assert.doesNotMatch(source, /\b(?:expected|corpus)\b/iu);
  assert.doesNotMatch(source, /\b(?:oracle|transaction|manifest)\s*[:=]/u);
});

test('accepted-mutant KATs are rejected by schemas and semantic relations', () => {
  const runtime = parse('external-runtime-closure.v1.json');
  const runtimeFdMutant = clone(runtime);
  runtimeFdMutant.launch.stdio['3'] = 'captured-extra';
  rejectSchema('runtime-closure.v1.schema.json', runtimeFdMutant);
  assert.throws(() => validateExternalRuntimeClosure(runtimeFdMutant), /launch\.stdio|runtime closure/iu);

  const runtimeArgvMutant = clone(runtime);
  runtimeArgvMutant.executables[0].argv0 = '/tmp/not-bchn';
  rejectSchema('runtime-closure.v1.schema.json', runtimeArgvMutant);
  assert.throws(() => validateExternalRuntimeClosure(runtimeArgvMutant), /pinned descriptor|argv0 relation/iu);

  const runtimeDsoMutant = clone(runtime);
  runtimeDsoMutant.dsos[0].realpath = '/usr/lib/libcrypto-mutant.so.3';
  rejectSchema('runtime-closure.v1.schema.json', runtimeDsoMutant);
  assert.throws(() => validateExternalRuntimeClosure(runtimeDsoMutant), /pinned descriptor|realpath/iu);

  const native = parse('native-descriptor.v1.json');
  const nativeMutant = clone(native);
  nativeMutant.relations['relation:e-mac'] = ['A', 'B', 'C', 'D'];
  rejectSchema('native-descriptor.v1.schema.json', nativeMutant);
  assert.throws(() => validateNativeDescriptor(nativeMutant), /pinned values|relation/iu);

  const graph = parse('libauth-input-graph.v1.json');
  const graphMutant = clone(graph);
  graphMutant.files[0].sha256 = '0'.repeat(64);
  const graphSchema = new Ajv2020({ strict: true, allErrors: true }).compile(parse('libauth-input-graph.v1.schema.json'));
  assert.equal(graphSchema(graphMutant), true, 'graph schema should admit a syntactically valid but wrong digest');
  assert.throws(() => validateLibauthInputGraph(graphMutant), /hash mismatch|pinned|digest/iu);

  const receipt = parse('libauth-bundle-receipt.v1.json');
  const receiptMutant = clone(receipt);
  receiptMutant.output = { bundle: 'unexpected' };
  rejectSchema('libauth-bundle-receipt.v1.schema.json', receiptMutant);
  assert.throws(() => validateLibauthBundleReceipt(receiptMutant), /pinned|output/iu);

  const manifest = parse('MANIFEST.json');
  const manifestMutant = clone(manifest);
  manifestMutant.files[0].path = `${manifest.packageRoot}/extra.txt`;
  rejectSchema('manifest.v1.schema.json', manifestMutant);
  assert.throws(() => validateManifestPackage(manifestMutant, packageDirectory), /coverage|path/iu);
});
