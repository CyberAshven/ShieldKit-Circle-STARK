import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import Ajv2020 from 'ajv/dist/2020.js';

import { validateCandidateCompositionV2 } from './candidate-composition.mjs';

const loadBytes = (path) => readFileSync(new URL(path, import.meta.url));
const load = (path) => JSON.parse(loadBytes(path).toString('utf8'));
const schema = load('./circle-fri-candidate-matrix.v2.schema.json');
const current = load('./circle-fri-candidate-matrix.v2.json');
const legacy = load('./circle-fri-candidate-matrix.v1.json');
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

const fieldById = (matrix, fieldSpecId) => matrix.fieldSpecs.find((item) => item.fieldSpecId === fieldSpecId);

const expectSemanticError = (mutate, pattern) => {
  const matrix = structuredClone(current);
  mutate(matrix);
  assert.equal(validateSchema(matrix), true, JSON.stringify(validateSchema.errors));
  assert.match(validateCandidateCompositionV2(matrix, legacy).join('\n'), pattern);
};

const expectSchemaReject = (mutate) => {
  const matrix = structuredClone(current);
  mutate(matrix);
  assert.equal(validateSchema(matrix), false);
};

test('current v2 is a valid tuple-incapable prequalification component registry', () => {
  assert.equal(validateSchema(current), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(validateCandidateCompositionV2(current, legacy), []);
  assert.equal(current.registryKind, 'prequalification-component-registry');
  assert.equal(current.tupleRepresentation, 'unsupported-requires-additive-future-schema');
  assert.equal(current.fieldSpecs.length, 14);
  assert.equal(current.tuples.length, 0);
  assert.equal(schema.$defs.candidateTuple, undefined);
});

test('all composition axes are schema-locked empty pending an additive future schema', () => {
  for (const axis of [
    'circleDomains',
    'deepQuotients',
    'algebraicHashes',
    'outerHashChannels',
    'embeddings',
    'tuples'
  ]) {
    expectSchemaReject((matrix) => { matrix[axis].push({}); });
  }
});

test('semantic validation independently rejects every attempted tuple', () => {
  const matrix = structuredClone(current);
  matrix.tuples.push({
    tupleId: 'tuple:cannot-exist',
    status: 'draft-unfrozen',
    selectionAllowed: false
  });
  assert.match(
    validateCandidateCompositionV2(matrix, legacy).join('\n'),
    /tuples is unsupported in the v2 prequalification registry and must be empty/u
  );
});

test('M17 degree-8 is an explicit unmeasured control with a generic prime check only', () => {
  const m17 = fieldById(current, 'field-spec:m17-d8');
  assert.deepEqual(
    {
      q: m17.mersenneExponent,
      degree: m17.extensionDegree,
      baseBytes: m17.baseLimbBytes,
      rawBytes: m17.rawElementBytes,
      legacyRow: m17.legacyComponentRowRef,
      certificates: m17.certificateRefs
    },
    {
      q: 17,
      degree: 8,
      baseBytes: 3,
      rawBytes: 24,
      legacyRow: null,
      certificates: ['certificate-fixture:frontier-mersenne-prime-checks-v1']
    }
  );
  assert.match(m17.description, /generic prime-check fixture replays q=17/u);
});

test('fixed q, degree, limb width, raw width, and legacy mappings fail closed', () => {
  expectSemanticError(
    (matrix) => { fieldById(matrix, 'field-spec:m31-d5').mersenneExponent = 32; },
    /field field-spec:m31-d5 mersenneExponent does not match/u
  );
  expectSemanticError(
    (matrix) => { fieldById(matrix, 'field-spec:m31-d5').extensionDegree = 6; },
    /field field-spec:m31-d5 extensionDegree does not match/u
  );
  expectSemanticError(
    (matrix) => { fieldById(matrix, 'field-spec:m31-d5').baseLimbBytes = 5; },
    /field field-spec:m31-d5 baseLimbBytes does not match/u
  );
  expectSemanticError(
    (matrix) => { fieldById(matrix, 'field-spec:m31-d5').rawElementBytes = 24; },
    /field field-spec:m31-d5 rawElementBytes does not match/u
  );
  expectSemanticError(
    (matrix) => { fieldById(matrix, 'field-spec:m31-d5').legacyComponentRowRef = 'field:m31-degree6'; },
    /field field-spec:m31-d5 legacyComponentRowRef does not match/u
  );
});

test('the exact field frontier rejects missing, extra, and duplicate identities', () => {
  const missing = structuredClone(current);
  missing.fieldSpecs.pop();
  assert.equal(validateSchema(missing), false);
  assert.match(validateCandidateCompositionV2(missing, legacy).join('\n'), /field frontier IDs does not match/u);

  const extra = structuredClone(current);
  extra.fieldSpecs.push({ ...structuredClone(extra.fieldSpecs[0]), fieldSpecId: 'field-spec:m13-d11' });
  assert.equal(validateSchema(extra), false);
  assert.match(validateCandidateCompositionV2(extra, legacy).join('\n'), /field frontier IDs does not match/u);

  expectSemanticError(
    (matrix) => { matrix.fieldSpecs[1].fieldSpecId = matrix.fieldSpecs[0].fieldSpecId; },
    /duplicate field spec/u
  );
});

test('source path, digest, kind, role, and nonqualification labels are exact', () => {
  expectSemanticError(
    (matrix) => { matrix.sourcePins[1].path = 'p2/field-cert/fixtures/not-the-fixture.json'; },
    /source certificate-fixture:frontier-mersenne-prime-checks-v1 path does not match/u
  );
  expectSemanticError(
    (matrix) => { matrix.sourcePins[1].sha256 = '0'.repeat(64); },
    /source certificate-fixture:frontier-mersenne-prime-checks-v1 sha256 does not match/u
  );
  expectSemanticError(
    (matrix) => { matrix.sourcePins[1].role = 'm89-d2-rabin-irreducibility-check-no-selection'; },
    /source certificate-fixture:frontier-mersenne-prime-checks-v1 role does not match/u
  );
  expectSemanticError(
    (matrix) => {
      matrix.sourcePins[1].kind = 'research-contract';
      matrix.sourcePins[1].role = 'prequalification-registry-boundary-no-selection';
      delete matrix.sourcePins[1].qualification;
    },
    /source certificate-fixture:frontier-mersenne-prime-checks-v1 kind does not match/u
  );
  expectSchemaReject((matrix) => { matrix.sourcePins[1].qualification.selection = 'winner'; });
});

test('certificate coverage is exact and certificates cannot become evidence', () => {
  expectSemanticError(
    (matrix) => { fieldById(matrix, 'field-spec:m31-d5').certificateRefs = []; },
    /field field-spec:m31-d5 certificateRefs does not match/u
  );
  expectSemanticError(
    (matrix) => { fieldById(matrix, 'field-spec:m17-d8').certificateRefs = []; },
    /field field-spec:m17-d8 certificateRefs does not match/u
  );
  expectSemanticError(
    (matrix) => {
      fieldById(matrix, 'field-spec:m89-d2').evidenceRefs.push(
        'certificate-fixture:m89-x2-plus-1-rabin-v1'
      );
    },
    /incorrectly classifies certificate .* as evidence/u
  );
});

test('M89 references both generic prime and Rabin fixtures without selection', () => {
  const m89 = fieldById(current, 'field-spec:m89-d2');
  assert.deepEqual(m89.certificateRefs, [
    'certificate-fixture:frontier-mersenne-prime-checks-v1',
    'certificate-fixture:m89-x2-plus-1-rabin-v1'
  ]);
  for (const ref of m89.certificateRefs) {
    const source = current.sourcePins.find((item) => item.sourceId === ref);
    assert.deepEqual(source.qualification, {
      status: 'generic-math-unqualified',
      casReview: 'not-cas-reviewed',
      evidenceClassification: 'not-evidence',
      selection: 'none'
    });
  }
  assert.equal(current.decisionPolicy.selectionStatus, 'closed');
});

test('legacy evidence remains component-only and tuple-null by construction', () => {
  expectSchemaReject((matrix) => { matrix.legacyEvidenceBindings[0].claimedRoles = ['B']; });
  expectSchemaReject((matrix) => { matrix.legacyEvidenceBindings[0].tupleRef = 'tuple:forbidden'; });
  expectSchemaReject((matrix) => { matrix.legacyEvidenceBindings[0].classification = 'tuple-scoped'; });
});

test('the immutable v1 component matrix bytes remain unchanged', () => {
  assert.equal(
    createHash('sha256').update(loadBytes('./circle-fri-candidate-matrix.v1.json')).digest('hex'),
    '44f1239ef942852e2cc111e7cbe105b2e4a20be2958f980e94082d309e10d02d'
  );
});
