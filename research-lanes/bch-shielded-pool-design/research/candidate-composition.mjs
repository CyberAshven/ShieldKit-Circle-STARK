const exactSet = (values) => [...new Set(values ?? [])].sort().join('\u0000');

const PRIME_FIXTURE = 'certificate-fixture:frontier-mersenne-prime-checks-v1';
const M89_RABIN_FIXTURE = 'certificate-fixture:m89-x2-plus-1-rabin-v1';
const FRONTIER_CONTRACT = 'research:field-frontier-contract';

const EXPECTED_SOURCES = new Map([
  [FRONTIER_CONTRACT, {
    path: 'research/field-frontier-contract.md',
    sha256: '40f004a36caa519be3c70266209612d8629e2a5416f18d3703bd05b2d3a7c55e',
    kind: 'research-contract',
    role: 'prequalification-registry-boundary-no-selection',
    qualification: null
  }],
  [PRIME_FIXTURE, {
    path: 'p2/field-cert/fixtures/frontier-prime-checks.v1.json',
    sha256: '04e713d637296e11547add2d8d8dddde15c7d398cb04aed39f35864fe28a135d',
    kind: 'generic-math-certificate-fixture',
    role: 'mersenne-primality-and-rejection-checks-no-selection',
    qualification: {
      status: 'generic-math-unqualified',
      casReview: 'not-cas-reviewed',
      evidenceClassification: 'not-evidence',
      selection: 'none'
    }
  }],
  [M89_RABIN_FIXTURE, {
    path: 'p2/field-cert/fixtures/m89-x2-plus-1-rabin.v1.json',
    sha256: 'f7d802d5f763cc4afc301ed0d35f141fd80ffa4a64ad7e6151588ad8c370ea7a',
    kind: 'generic-math-certificate-fixture',
    role: 'm89-d2-rabin-irreducibility-check-no-selection',
    qualification: {
      status: 'generic-math-unqualified',
      casReview: 'not-cas-reviewed',
      evidenceClassification: 'not-evidence',
      selection: 'none'
    }
  }]
]);

const field = (
  q,
  degree,
  baseBytes,
  rawBytes,
  legacyRow,
  disposition,
  certificateRefs,
  overrides = {}
) => ({
  kind: 'mersenne-family',
  freezingStatus: 'family-unfrozen',
  evidenceState: 'unmeasured',
  disposition,
  mersenneExponent: q,
  extensionDegree: degree,
  baseLimbBytes: baseBytes,
  rawElementBytes: rawBytes,
  legacyComponentRowRef: legacyRow,
  exactAlgebraStatus: 'unfrozen',
  encodingStatus: 'unfrozen',
  sourceRefs: [FRONTIER_CONTRACT],
  certificateRefs,
  evidenceRefs: [],
  ...overrides
});

const EXPECTED_FIELDS = new Map([
  ['field-spec:m13-d10', field(13, 10, 2, 20, null, 'analytical-domain-control', [PRIME_FIXTURE])],
  ['field-spec:m17-d8', field(17, 8, 3, 24, null, 'analytical-domain-control', [PRIME_FIXTURE])],
  ['field-spec:m19-d7', field(19, 7, 3, 21, null, 'analytical-domain-control', [PRIME_FIXTURE])],
  ['field-spec:m31-d1', field(31, 1, 4, 4, 'field:m31-base-control', 'measured-base-control', [PRIME_FIXTURE], {
    evidenceState: 'measured-neutral-control',
    exactAlgebraStatus: 'base-arithmetic-measured-neutral',
    encodingStatus: 'implemented-neutral-control',
    evidenceRefs: ['source:m31-base-suite-evidence']
  })],
  ['field-spec:m31-d4', field(31, 4, 4, 16, 'field:m31-degree4-control', 'raw-capacity-control', [PRIME_FIXTURE])],
  ['field-spec:m31-d5', field(31, 5, 4, 20, 'field:m31-degree5', 'first-arithmetic-shortlist', [PRIME_FIXTURE])],
  ['field-spec:m31-d6', field(31, 6, 4, 24, 'field:m31-degree6', 'first-arithmetic-shortlist', [PRIME_FIXTURE])],
  ['field-spec:m61-d2', field(61, 2, 8, 16, 'field:m61-degree2-control', 'raw-capacity-control', [PRIME_FIXTURE])],
  ['field-spec:m61-d3', field(61, 3, 8, 24, 'field:m61-degree3', 'first-arithmetic-shortlist', [PRIME_FIXTURE])],
  ['field-spec:m89-d2', field(89, 2, 12, 24, null, 'first-arithmetic-shortlist', [PRIME_FIXTURE, M89_RABIN_FIXTURE])],
  ['field-spec:m107-d2', field(107, 2, 14, 28, null, 'dormant-escalator', [PRIME_FIXTURE])],
  ['field-spec:m127-d1', field(127, 1, 16, 16, null, 'raw-capacity-control', [PRIME_FIXTURE])],
  ['field-spec:m127-d2', field(127, 2, 16, 32, 'field:m127-degree2-control', 'dormant-escalator', [PRIME_FIXTURE])],
  ['field-spec:m29-d5-invalid', field(29, 5, 4, 20, 'field:m29-degree5-control', 'killed', [PRIME_FIXTURE], {
    kind: 'rejected-composite-control',
    freezingStatus: 'killed',
    evidenceState: 'eliminated',
    exactAlgebraStatus: 'not-applicable',
    encodingStatus: 'not-applicable',
    sourceRefs: [FRONTIER_CONTRACT, 'source:m29-compositeness-check'],
    evidenceRefs: ['source:m29-compositeness-check']
  })]
]);

const UNSUPPORTED_COMPOSITION_AXES = [
  'circleDomains',
  'deepQuotients',
  'algebraicHashes',
  'outerHashChannels',
  'embeddings',
  'tuples'
];

const uniqueMap = (items, key, label, errors) => {
  const result = new Map();
  for (const item of items ?? []) {
    const id = item?.[key];
    if (typeof id !== 'string') {
      errors.push(`${label} is missing ${key}`);
      continue;
    }
    if (result.has(id)) errors.push(`duplicate ${label} ${id}`);
    result.set(id, item);
  }
  return result;
};

const compareExactSet = (actual, expected, label, errors) => {
  if (exactSet(actual) !== exactSet(expected)) errors.push(`${label} does not match the frozen set`);
};

const compareQualification = (actual, expected, sourceId, errors) => {
  if (expected === null) {
    if (actual !== undefined) errors.push(`source ${sourceId} must not carry certificate qualification labels`);
    return;
  }
  for (const [key, value] of Object.entries(expected)) {
    if (actual?.[key] !== value) errors.push(`source ${sourceId} qualification ${key} is not ${value}`);
  }
  if (actual && exactSet(Object.keys(actual)) !== exactSet(Object.keys(expected))) {
    errors.push(`source ${sourceId} has unexpected qualification labels`);
  }
};

export const validateCandidateCompositionV2 = (matrix, legacyMatrix) => {
  const errors = [];
  const legacyRows = uniqueMap(legacyMatrix?.rows, 'id', 'legacy component row', errors);
  const legacySources = uniqueMap(legacyMatrix?.sourcePins, 'id', 'legacy source', errors);
  const sources = uniqueMap(matrix?.sourcePins, 'sourceId', 'composition source', errors);
  const fields = uniqueMap(matrix?.fieldSpecs, 'fieldSpecId', 'field spec', errors);
  const bindings = uniqueMap(matrix?.legacyEvidenceBindings, 'bindingId', 'legacy evidence binding', errors);
  const sourceIds = new Set([...legacySources.keys(), ...sources.keys()]);

  if (matrix?.registryKind !== 'prequalification-component-registry') {
    errors.push('v2 is not labeled as a prequalification component registry');
  }
  if (matrix?.tupleRepresentation !== 'unsupported-requires-additive-future-schema') {
    errors.push('v2 does not require an additive future schema for tuple representation');
  }
  if (matrix?.legacyComponentMatrix?.matrixId !== legacyMatrix?.matrixId) errors.push('legacy matrix identity mismatch');
  if (matrix?.legacyComponentMatrix?.schema !== legacyMatrix?.schema) errors.push('legacy matrix schema mismatch');
  if (matrix?.legacyComponentMatrix?.rowCount !== legacyMatrix?.rows?.length) errors.push('legacy matrix row-count mismatch');
  if (matrix?.decisionPolicy?.selectionStatus !== 'closed') errors.push('candidate selection is not closed');

  for (const axis of UNSUPPORTED_COMPOSITION_AXES) {
    if (!Array.isArray(matrix?.[axis]) || matrix[axis].length !== 0) {
      errors.push(`${axis} is unsupported in the v2 prequalification registry and must be empty`);
    }
  }

  compareExactSet(sources.keys(), EXPECTED_SOURCES.keys(), 'composition source IDs', errors);
  for (const [sourceId, expected] of EXPECTED_SOURCES) {
    const actual = sources.get(sourceId);
    if (!actual) continue;
    for (const key of ['path', 'sha256', 'kind', 'role']) {
      if (actual[key] !== expected[key]) errors.push(`source ${sourceId} ${key} does not match the frozen pin`);
    }
    compareQualification(actual.qualification, expected.qualification, sourceId, errors);
  }

  compareExactSet(fields.keys(), EXPECTED_FIELDS.keys(), 'field frontier IDs', errors);
  for (const [fieldId, expected] of EXPECTED_FIELDS) {
    const actual = fields.get(fieldId);
    if (!actual) continue;
    for (const key of [
      'kind',
      'freezingStatus',
      'evidenceState',
      'disposition',
      'mersenneExponent',
      'extensionDegree',
      'baseLimbBytes',
      'rawElementBytes',
      'legacyComponentRowRef',
      'exactAlgebraStatus',
      'encodingStatus'
    ]) {
      if (actual[key] !== expected[key]) errors.push(`field ${fieldId} ${key} does not match the frozen prequalification record`);
    }
    for (const key of ['sourceRefs', 'certificateRefs', 'evidenceRefs']) {
      compareExactSet(actual[key], expected[key], `field ${fieldId} ${key}`, errors);
    }

    const expectedBaseBytes = Math.ceil(actual.mersenneExponent / 8);
    if (actual.baseLimbBytes !== expectedBaseBytes) {
      errors.push(`field ${fieldId} base width is ${actual.baseLimbBytes}, expected ${expectedBaseBytes}`);
    }
    if (actual.rawElementBytes !== actual.baseLimbBytes * actual.extensionDegree) {
      errors.push(`field ${fieldId} raw element width is inconsistent`);
    }
    if (actual.legacyComponentRowRef !== null) {
      const row = legacyRows.get(actual.legacyComponentRowRef);
      if (!row) errors.push(`field ${fieldId} has dangling legacy row ${actual.legacyComponentRowRef}`);
      else if (row.axis !== 'field-extension') errors.push(`field ${fieldId} legacy row is not a field component`);
    }
    for (const ref of [...(actual.sourceRefs ?? []), ...(actual.evidenceRefs ?? [])]) {
      if (!sourceIds.has(ref)) errors.push(`field ${fieldId} has unresolved source or evidence ${ref}`);
    }
    for (const ref of actual.certificateRefs ?? []) {
      const certificateSource = sources.get(ref);
      if (!certificateSource) errors.push(`field ${fieldId} has unresolved certificate ${ref}`);
      else if (certificateSource.kind !== 'generic-math-certificate-fixture') {
        errors.push(`field ${fieldId} certificate ${ref} is not a generic-math certificate fixture`);
      }
      if ((actual.evidenceRefs ?? []).includes(ref)) {
        errors.push(`field ${fieldId} incorrectly classifies certificate ${ref} as evidence`);
      }
    }
  }

  if (bindings.size !== 1 || !bindings.has('evidence-binding:m31-base-suite-v1')) {
    errors.push('v2 must retain exactly the neutral M31 component evidence binding');
  }
  for (const binding of bindings.values()) {
    if (!legacyRows.has(binding.candidateRowRef)) errors.push(`legacy evidence ${binding.bindingId} has unknown candidate row`);
    if (binding.classification !== 'component-only-neutral-control') {
      errors.push(`legacy evidence ${binding.bindingId} is not component-only`);
    }
    if ((binding.claimedRoles ?? []).length !== 0) errors.push(`legacy evidence ${binding.bindingId} claims tuple roles`);
    if (binding.tupleRef !== null) errors.push(`legacy evidence ${binding.bindingId} claims a tuple`);
  }

  return errors;
};

export const assertCandidateCompositionV2 = (matrix, legacyMatrix) => {
  const errors = validateCandidateCompositionV2(matrix, legacyMatrix);
  if (errors.length > 0) throw new Error(errors.join('\n'));
};
