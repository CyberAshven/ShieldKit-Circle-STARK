import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import Ajv from 'ajv/dist/2020.js';
import { DIRECTORY, REPO, SCHEMA_PATH, canonicalJson, contentDigestFor, generateLoweringFreeze, validateLoweringFreezeSemantics } from './lowering-freeze.mjs';

const schema = JSON.parse(readFileSync(resolve(REPO, SCHEMA_PATH), 'utf8'));
const artifactPath = resolve(DIRECTORY, 'lowering-freeze.v1.json');
const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
const validateSchema = new Ajv({ strict: true, allErrors: true }).compile(schema);
const expectValid = (value) => { assert.equal(validateSchema(value), true, JSON.stringify(validateSchema.errors)); assert.deepEqual(validateLoweringFreezeSemantics(value), []); };

test('frozen artifact is strict-schema and semantic valid', () => expectValid(artifact));
test('regeneration is byte-identical and canonical LF JSON', () => {
  const generated = generateLoweringFreeze();
  const bytes = Buffer.from(canonicalJson(generated));
  assert.deepEqual(bytes, readFileSync(artifactPath));
  assert.equal(bytes[bytes.length - 1], 0x0a);
  assert.equal(bytes.includes(0x0d), false);
  assert.equal(JSON.stringify(JSON.parse(bytes), null, 2) + '\n', bytes.toString());
});
test('exact roster, order, 42 relation targets, and all pending/null slots', () => {
  assert.deepEqual(artifact.constructionOrder.map((x) => x.constructionId), [
    'algebra-construction:m89-d2-x2-plus-1-v1', 'algebra-construction:m61-d3-x3-minus-5-v1',
    'algebra-construction:m31-d5-x5-plus-2x-minus-1-v1', 'algebra-construction:m31-d6-x6-minus-5-v1'
  ]);
  assert.equal(artifact.arms.length, 14); assert.equal(artifact.relationTargets.length, 42);
  assert.deepEqual(artifact.relationTargets.slice(0, 3).map((x) => x.relationId), ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check']);
  for (const row of [...artifact.arms, ...artifact.relationTargets]) {
    assert.equal(row.sourceLowering.status, 'pending');
    assert.ok(Object.values(row.metrics).every((v) => v === null));
  }
});
test('contract invariants are explicit', () => {
  assert.equal(artifact.codecParserContract.parserSteps[3], 'construct-one-byte-00-by-OP_1-OP_1-OP_XOR-then-raw-cat-and-bin2num-per-limb');
  assert.equal(artifact.scalarLowering.division, 'OP_DIV-forbidden');
  assert.equal(artifact.dagPolicy.commonSubexpressionElimination, 'forbidden');
  assert.deepEqual(artifact.stackAbi.relationOperandOrder, { eMac: ['D', 'C', 'B', 'A'], eSquareMac: ['D', 'C', 'A'], eInverseCheck: ['H', 'A'] });
  assert.equal(artifact.executionBoundary.executionAllowed, false); assert.equal(artifact.executionBoundary.sourceImplementationAllowed, true);
  assert.deepEqual(artifact.executionBoundary.requiredBeforeExecution, [
    'source-set-v1-content-binding', 'campaign-v2-content-binding',
    'canonical-corpus-v2-content-binding', 'execution-epoch-v2-content-binding'
  ]);
  assert.deepEqual(artifact.downstreamBindings, {
    sourceSetV1: null, campaignV2: null, canonicalCorpusV2: null, executionEpochV2: null
  });
  assert.equal(artifact.selection, 'none'); assert.equal(artifact.tupleRef, null); assert.equal(artifact.evidenceClassification, 'not-evidence');
});
test('mutation negatives reject stale digest and semantic drift', () => {
  const stale = structuredClone(artifact); stale.selection = 'arm'; assert.throws(() => expectValid(stale));
  const semantic = structuredClone(artifact); semantic.stackAbi.relationOperandOrder.eMac = ['A', 'B', 'C', 'D']; semantic.contentDigest.value = contentDigestFor(semantic); assert.throws(() => expectValid(semantic));
  const source = structuredClone(artifact); source.arms[0].sourceLowering.sourceListing = 'PENDING'; source.contentDigest.value = contentDigestFor(source); assert.throws(() => expectValid(source));
  const unknown = structuredClone(artifact); unknown.unexpected = true; assert.throws(() => expectValid(unknown));
  const staleDigest = structuredClone(artifact); staleDigest.codecParserContract.parserSteps[3] = 'wrong'; assert.throws(() => expectValid(staleDigest));
  const reorder = structuredClone(artifact); [reorder.arms[0], reorder.arms[1]] = [reorder.arms[1], reorder.arms[0]]; reorder.contentDigest.value = contentDigestFor(reorder); assert.throws(() => expectValid(reorder));
  const opened = structuredClone(artifact); opened.downstreamBindings.executionEpochV2 = { fake: true }; opened.contentDigest.value = contentDigestFor(opened); assert.throws(() => expectValid(opened));
});
