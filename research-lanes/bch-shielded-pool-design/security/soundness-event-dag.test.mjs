import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import Ajv2020 from 'ajv/dist/2020.js';

import { exactFloorSecurityBits, validateSoundnessEventDagV2 } from './soundness-event-dag.mjs';

const schema = JSON.parse(readFileSync(new URL('./soundness-worksheet.v2.schema.json', import.meta.url), 'utf8'));
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const digest = (byte) => byte.repeat(64);
const twoTo130 = 1n << 130n;
const twoTo131 = 1n << 131n;

const event = ({ id, kind, role, key, opportunity, sampler }) => ({
  eventId: id,
  kind,
  accounting: {
    mode: 'systemic-summand',
    eventKey: key,
    opportunitySetId: opportunity,
    samplerRefs: [sampler]
  },
  roleRefs: [role],
  dependsOn: [],
  bound: {
    status: 'derived',
    form: 'exact-rational',
    exactUpperBound: { numerator: '1', denominator: twoTo131.toString() },
    expression: 'one bad event bounded by 2^-131',
    multiplicity: 1,
    multiplicityIncludedInBound: true,
    assumptionRefs: ['assumption:random-oracle'],
    evidenceRefs: ['evidence:derivation']
  }
});

const validWorksheet = () => ({
  schema: 'shieldkit-labs/security/soundness-worksheet/v2',
  qualificationBoundary: 'prequalification-only',
  worksheetId: 'worksheet:conformance-control',
  status: 'partial',
  candidateTupleRef: 'tuple:conformance-control',
  candidateTupleDigest: digest('2'),
  relationRef: 'relation:pool-action-fv1',
  profileRef: 'profile:fixed-ticket-serial-pool',
  sourceCommits: [{
    repository: 'conformance fixture',
    commit: digest('a'),
    dirty: false,
    paths: ['security/soundness-event-dag.test.mjs']
  }],
  toolchain: {
    runtime: 'node test',
    checker: 'soundness-event-dag.mjs',
    lockfileDigest: digest('1')
  },
  artifactDigests: {
    relation: digest('3'),
    candidateTuple: digest('2'),
    derivation: digest('4')
  },
  assumptions: [{
    assumptionId: 'assumption:random-oracle',
    statement: 'Conformance-only random-oracle assumption.',
    status: 'supported',
    evidenceRefs: ['evidence:derivation']
  }],
  eventDag: {
    nodes: [
      event({
        id: 'event:air-batch',
        kind: 'air',
        role: 'F_batch',
        key: 'bad-event:air-batch',
        opportunity: 'opportunities:air-batch',
        sampler: 'sampler:air-batch'
      }),
      event({
        id: 'event:fri-query',
        kind: 'fri',
        role: 'F_fri',
        key: 'bad-event:fri-query',
        opportunity: 'opportunities:fri-query',
        sampler: 'sampler:fri-query'
      })
    ],
    systemicUnion: {
      status: 'derived',
      summandRefs: ['event:air-batch', 'event:fri-query'],
      method: 'union-bound',
      boundExpression: 'min(1,sum(unique systemic summands))',
      exactUpperBound: { numerator: '1', denominator: twoTo130.toString() },
      floorSecurityBits: 130,
      evidenceRefs: ['evidence:derivation']
    }
  },
  completeTransactions: { deposit: null, withdrawal: null },
  conclusion: {
    qualification: 'not-qualified',
    targetBits: 128,
    minimumBits: 100,
    selectionAllowed: false,
    fallbackAuthorized: false,
    reason: 'Conformance fixture only; no complete transaction evidence.'
  }
});

const expectSemanticError = (mutate, pattern) => {
  const worksheet = validWorksheet();
  mutate(worksheet);
  assert.equal(validateSchema(worksheet), true, JSON.stringify(validateSchema.errors));
  assert.match(validateSoundnessEventDagV2(worksheet).join('\n'), pattern);
};

test('v2 schema and event-DAG semantics accept the exact conformance control', () => {
  const worksheet = validWorksheet();
  assert.equal(validateSchema(worksheet), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(validateSoundnessEventDagV2(worksheet), []);
  assert.equal(exactFloorSecurityBits({ numerator: 1n, denominator: twoTo130 }), 130);
});

test('event accounting rejects duplicate event identity, opportunity, and sampler ownership', () => {
  expectSemanticError(
    (worksheet) => { worksheet.eventDag.nodes[1].accounting.eventKey = 'bad-event:air-batch'; },
    /duplicate systemic event key/u
  );
  expectSemanticError(
    (worksheet) => { worksheet.eventDag.nodes[1].accounting.opportunitySetId = 'opportunities:air-batch'; },
    /duplicate systemic opportunity set/u
  );
  expectSemanticError(
    (worksheet) => { worksheet.eventDag.nodes[1].accounting.samplerRefs = ['sampler:air-batch']; },
    /is owned by both/u
  );
});

test('event DAG rejects dangling references, cycles, and ancestor plus descendant summands', () => {
  expectSemanticError(
    (worksheet) => { worksheet.eventDag.nodes[0].dependsOn = ['event:missing']; },
    /dangling dependency/u
  );
  expectSemanticError(
    (worksheet) => {
      worksheet.eventDag.nodes[0].dependsOn = ['event:fri-query'];
      worksheet.eventDag.nodes[1].dependsOn = ['event:air-batch'];
    },
    /contains a cycle/u
  );
  expectSemanticError(
    (worksheet) => { worksheet.eventDag.nodes[1].dependsOn = ['event:air-batch']; },
    /counts an ancestor and descendant/u
  );
});

test('exact union recomputation rejects rational, bit, and tuple-digest mismatches', () => {
  expectSemanticError(
    (worksheet) => { worksheet.eventDag.systemicUnion.exactUpperBound = { numerator: '1', denominator: twoTo131.toString() }; },
    /systemic union mismatch/u
  );
  expectSemanticError(
    (worksheet) => { worksheet.eventDag.systemicUnion.floorSecurityBits = 131; },
    /security-bit mismatch/u
  );
  expectSemanticError(
    (worksheet) => { worksheet.artifactDigests.candidateTuple = digest('9'); },
    /candidate tuple digest disagrees/u
  );
});

test('schema forbids raw-field events and multiplicity outside the bound', () => {
  const rawField = validWorksheet();
  rawField.eventDag.nodes[0].kind = 'field-cardinality';
  assert.equal(validateSchema(rawField), false);

  const duplicateMultiplicity = validWorksheet();
  duplicateMultiplicity.eventDag.nodes[0].bound.multiplicityIncludedInBound = false;
  assert.equal(validateSchema(duplicateMultiplicity), false);

  const unexpandedMultiplicity = validWorksheet();
  unexpandedMultiplicity.eventDag.nodes[0].bound.multiplicity = 999_999;
  assert.equal(validateSchema(unexpandedMultiplicity), false);
});

test('prequalification v2 cannot encode a 128-bit qualification pass', () => {
  const worksheet = validWorksheet();
  worksheet.status = 'complete';
  worksheet.conclusion.qualification = '128-bit-pass';
  assert.equal(validateSchema(worksheet), false);
  assert.match(validateSoundnessEventDagV2(worksheet).join('\n'), /cannot express a qualification pass/u);
});

test('sampler ownership is unique across systemic and derivation-only nodes', () => {
  const worksheet = validWorksheet();
  worksheet.eventDag.nodes.push({
    ...event({
      id: 'event:derived-sampler-use',
      kind: 'challenge-sampler',
      role: 'F_batch',
      key: 'bad-event:unused',
      opportunity: 'opportunities:unused',
      sampler: 'sampler:air-batch'
    }),
    accounting: {
      mode: 'derivation-only',
      eventKey: null,
      opportunitySetId: null,
      samplerRefs: ['sampler:air-batch']
    }
  });
  assert.equal(validateSchema(worksheet), true, JSON.stringify(validateSchema.errors));
  assert.match(validateSoundnessEventDagV2(worksheet).join('\n'), /is owned by both/u);
});
