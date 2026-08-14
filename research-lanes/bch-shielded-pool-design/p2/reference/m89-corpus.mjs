import { createHash } from 'node:crypto';

import { M89_MODULUS, add, bytesToHex, decodeM89Hex, encodeM89Hex, equal, inverse, mul, neg, square, verifyInverseHint } from './m89.mjs';

export const SEED_HEX = '0123456789abcdef';
export const DOMAIN_TAG = 'shieldkit-gate-b-corpus-v2';
export const RELATIONS = ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check'];
export const CATEGORIES = ['category:valid', 'category:boundary', 'category:random', 'category:metamorphic', 'category:malformed'];
export const MUTATIONS = ['wrong-length', 'truncation', 'trailing-bytes', 'out-of-range', 'sign-alias', 'swapped-limb', 'wrong-relation-output', 'zero-inverse-hint'];
export const DESCRIPTOR_DIGEST = 'be55d7b3d73c08745aa0aaea1028c7c691318b0e1c1f698127dbf56f5e5d97b6';
export const CAMPAIGN_DIGEST = '137ed80c61a3c40258f71b2796e0585d8d05fab3836d10a42a60e9ee9bd2e862';
export const CAMPAIGN_FILE_DIGEST = 'f90f634268a2a91c857248bf70343d91af4142c5b52b6117da4fe6b49229f9c1';

const encoder = new TextEncoder();
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const scalar = (value) => [value, 0n];
const zero = () => [0n, 0n];
const one = () => [1n, 0n];
const clone = (value) => structuredClone(value);
const canonicalize = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
};
const rawLimb = (value) => {
  let current = value;
  const bytes = new Uint8Array(12);
  for (let index = 0; index < 12; index += 1) { bytes[index] = Number(current & 0xffn); current >>= 8n; }
  if (current !== 0n) throw new RangeError('raw fixed-width limb overflow');
  return bytesToHex(bytes);
};
const setLimb = (hex, index, limbHex) => `${hex.slice(0, index * 24)}${limbHex}${hex.slice((index + 1) * 24)}`;
const replaceByte = (hex, index, byteHex) => `${hex.slice(0, index * 2)}${byteHex}${hex.slice(index * 2 + 2)}`;
const insertByte = (hex, index, byteHex) => `${hex.slice(0, index * 2)}${byteHex}${hex.slice(index * 2)}`;
const removeByte = (hex, index) => `${hex.slice(0, index * 2)}${hex.slice(index * 2 + 2)}`;
const swapLimbs = (hex) => `${hex.slice(24, 48)}${hex.slice(0, 24)}`;
const names = (relation) => relation === RELATIONS[0] ? ['A', 'B', 'C', 'D'] : relation === RELATIONS[1] ? ['A', 'C', 'D'] : ['A', 'H'];

/** SHA-256 counter/rejection sampler, including both v2 retry coordinates. */
export function sampleFp({ relationIndex, categoryIndex, operandIndex, limbIndex, caseIndex, vectorAttempt = 0, sampleRetry = 0 }) {
  for (const value of [relationIndex, categoryIndex, operandIndex]) if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new RangeError('u8 sampler coordinate out of range');
  if (!Number.isInteger(limbIndex) || limbIndex < 0 || limbIndex > 0xffff) throw new RangeError('u16 sampler coordinate out of range');
  for (const value of [caseIndex, vectorAttempt, sampleRetry]) if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('u32 sampler coordinate out of range');
  const tag = encoder.encode(DOMAIN_TAG);
  const frame = new Uint8Array(tag.length + 1 + 8 + 1 + 1 + 1 + 2 + 4 + 4 + 4);
  frame.set(tag);
  let offset = tag.length + 1;
  frame.set(Uint8Array.from(Buffer.from(SEED_HEX, 'hex')), offset); offset += 8;
  frame[offset++] = relationIndex; frame[offset++] = categoryIndex; frame[offset++] = operandIndex;
  frame[offset++] = limbIndex & 0xff; frame[offset++] = limbIndex >>> 8;
  const writeU32 = (value) => { for (let index = 0; index < 4; index += 1) frame[offset++] = (value >>> (index * 8)) & 0xff; };
  writeU32(caseIndex); writeU32(vectorAttempt); writeU32(sampleRetry);
  let retry = sampleRetry;
  const retryOffset = frame.length - 4;
  const threshold = ((1n << 256n) / M89_MODULUS) * M89_MODULUS;
  while (true) {
    for (let index = 0; index < 4; index += 1) frame[retryOffset + index] = (retry >>> (index * 8)) & 0xff;
    const digest = sha256(frame);
    let x = 0n;
    for (let index = 31; index >= 0; index -= 1) x = (x << 8n) | BigInt(digest[index]);
    if (x < threshold) return { value: x % M89_MODULUS, sampleRetry: retry, frameHex: bytesToHex(frame) };
    if (retry === 0xffffffff) throw new Error('sampleRetry overflow');
    retry += 1;
  }
}

const randomElement = (coordinates) => [
  sampleFp({ ...coordinates, limbIndex: 0 }).value,
  sampleFp({ ...coordinates, limbIndex: 1 }).value,
];
const derive = (relation, a, b = one(), c = zero()) => relation === RELATIONS[0]
  ? { A: a, B: b, C: c, D: add(mul(a, b), c) }
  : relation === RELATIONS[1] ? { A: a, C: c, D: add(square(a), c) }
    : { A: a, H: inverse(a) };
const raw = (operands) => Object.fromEntries(Object.entries(operands).map(([key, value]) => [key, encodeM89Hex(value)]));

export function evaluateCase(candidate) {
  try {
    const required = names(candidate.relationId);
    if (Object.keys(candidate.raw).length !== required.length || !required.every((name) => typeof candidate.raw[name] === 'string')) return { verdict: 'reject', stage: 'operand-set-check' };
    for (const name of required) if (candidate.raw[name].length !== 48) return { verdict: 'reject', stage: 'exact-extension-element-length-check-before-limb-decode' };
    const values = {};
    for (const name of required) {
      try { values[name] = decodeM89Hex(candidate.raw[name]); }
      catch (error) {
        if (/unused high bit/u.test(error.message)) return { verdict: 'reject', stage: 'unused-high-bit-check-before-numeric-decode' };
        if (/>= p/u.test(error.message)) return { verdict: 'reject', stage: 'coefficient-range-check-before-arithmetic' };
        return { verdict: 'reject', stage: 'canonical-parser-reject' };
      }
    }
    if (candidate.relationId === RELATIONS[0]) return equal(values.D, add(mul(values.A, values.B), values.C)) ? { verdict: 'accept', stage: 'accept' } : { verdict: 'reject', stage: 'relation-check' };
    if (candidate.relationId === RELATIONS[1]) return equal(values.D, add(square(values.A), values.C)) ? { verdict: 'accept', stage: 'accept' } : { verdict: 'reject', stage: 'relation-check' };
    return verifyInverseHint(values.A, values.H) ? { verdict: 'accept', stage: 'accept' } : { verdict: 'reject', stage: 'inverse-relation-check' };
  } catch {
    return { verdict: 'reject', stage: 'canonical-parser-reject' };
  }
}
const makeCase = (relationId, categoryId, caseIndex, vectorAttempt, operands, extra = {}) => {
  const candidate = { relationId, categoryId, caseIndex, vectorAttempt, raw: operands, ...extra };
  return { ...candidate, expected: evaluateCase(candidate) };
};

const validCases = (relation) => Array.from({ length: 16 }, (_, caseIndex) => {
  const a = scalar(BigInt(caseIndex + 1));
  const operands = relation === RELATIONS[0] ? derive(relation, a, scalar(BigInt(caseIndex + 2)), scalar(BigInt(caseIndex + 3)))
    : relation === RELATIONS[1] ? derive(relation, a, undefined, scalar(BigInt(caseIndex + 2))) : derive(relation, a);
  return makeCase(relation, CATEGORIES[0], caseIndex, 0, raw(operands));
});
const boundaryTemplates = () => [
  { id: 'zero', semantic: zero() }, { id: 'one', semantic: one() },
  { id: 'all-p-minus-1', semantic: [M89_MODULUS - 1n, M89_MODULUS - 1n] },
  { id: 'p', semantic: zero(), patch: (hex) => setLimb(hex, 0, rawLimb(M89_MODULUS)) },
  { id: 'p-plus-1', semantic: scalar(1n), patch: (hex) => setLimb(hex, 0, rawLimb(M89_MODULUS + 1n)) },
  { id: 'sign-alias', semantic: zero(), patch: (hex) => replaceByte(hex, 11, '80') },
  { id: 'unit-0-p-minus-1', semantic: [M89_MODULUS - 1n, 0n] },
  { id: 'unit-0-p', semantic: zero(), patch: (hex) => setLimb(hex, 0, rawLimb(M89_MODULUS)) },
  { id: 'unit-1-p-minus-1', semantic: [0n, M89_MODULUS - 1n] },
  { id: 'unit-1-p', semantic: zero(), patch: (hex) => setLimb(hex, 1, rawLimb(M89_MODULUS)) },
];
const boundaryCases = (relation) => boundaryTemplates().map((template, caseIndex) => {
  const values = relation === RELATIONS[2] && template.semantic[0] === 0n && template.semantic[1] === 0n ? { A: zero(), H: zero() } : derive(relation, template.semantic, one(), zero());
  const operands = raw(values);
  operands.A = template.patch ? template.patch(operands.A) : operands.A;
  return makeCase(relation, CATEGORIES[1], caseIndex, 0, operands, { template: template.id });
});

const independentBase = (relation, relationIndex, categoryIndex, caseIndex, vectorAttempt) => {
  const a = randomElement({ relationIndex, categoryIndex, operandIndex: 0, caseIndex, vectorAttempt });
  if (relation === RELATIONS[2] && a[0] === 0n && a[1] === 0n) return null;
  if (relation === RELATIONS[0]) return derive(relation, a, randomElement({ relationIndex, categoryIndex, operandIndex: 1, caseIndex, vectorAttempt }), randomElement({ relationIndex, categoryIndex, operandIndex: 2, caseIndex, vectorAttempt }));
  if (relation === RELATIONS[1]) return derive(relation, a, undefined, randomElement({ relationIndex, categoryIndex, operandIndex: 1, caseIndex, vectorAttempt }));
  return derive(relation, a);
};
const retryVector = (builder) => {
  for (let vectorAttempt = 0; vectorAttempt <= 0xffffffff; vectorAttempt += 1) {
    const output = builder(vectorAttempt);
    if (output) return output;
  }
  throw new Error('vectorAttempt overflow');
};
const randomCases = (relation, relationIndex) => Array.from({ length: 32 }, (_, caseIndex) => retryVector((vectorAttempt) => {
  const operands = independentBase(relation, relationIndex, 2, caseIndex, vectorAttempt);
  return operands ? makeCase(relation, CATEGORIES[2], caseIndex, vectorAttempt, raw(operands)) : null;
}));
const metamorphicCases = (relation, relationIndex) => Array.from({ length: 16 }, (_, caseIndex) => retryVector((vectorAttempt) => {
  const operands = independentBase(relation, relationIndex, 3, caseIndex, vectorAttempt);
  if (!operands) return null;
  const encoded = raw(operands);
  let transform;
  if (relation === RELATIONS[0]) { if (equal(operands.A, operands.B)) return null; [encoded.A, encoded.B] = [encoded.B, encoded.A]; transform = 'swap-A-B'; }
  else if (relation === RELATIONS[1]) { if (operands.A[0] === 0n && operands.A[1] === 0n) return null; encoded.A = encodeM89Hex(neg(operands.A)); transform = 'negate-A'; }
  else { if (equal(operands.A, operands.H)) return null; [encoded.A, encoded.H] = [encoded.H, encoded.A]; transform = 'swap-A-H'; }
  const candidate = makeCase(relation, CATEGORIES[3], caseIndex, vectorAttempt, encoded, { transform });
  return candidate.expected.verdict === 'accept' ? candidate : null;
}));

const mutationFamiliesFor = (relation) => relation === RELATIONS[2] ? MUTATIONS : MUTATIONS.slice(0, 7);
const mutate = (relation, family, limbIndex, encoded) => {
  const output = clone(encoded);
  const target = relation === RELATIONS[2] ? 'H' : 'D';
  if (family === 'wrong-length') output.A = output.A.slice(0, limbIndex * 24);
  else if (family === 'truncation') output.A = removeByte(output.A, (limbIndex + 1) * 12 - 1);
  else if (family === 'trailing-bytes') output.A = insertByte(output.A, (limbIndex + 1) * 12, '00');
  else if (family === 'out-of-range') output.A = setLimb(output.A, limbIndex, rawLimb(M89_MODULUS));
  else if (family === 'sign-alias') output.A = setLimb(output.A, limbIndex, `${'00'.repeat(11)}80`);
  else if (family === 'swapped-limb') output.A = swapLimbs(output.A);
  else if (family === 'wrong-relation-output') {
    const value = decodeM89Hex(output[target]);
    value[limbIndex] = (value[limbIndex] + 1n) % M89_MODULUS;
    output[target] = encodeM89Hex(value);
  } else {
    const value = decodeM89Hex(output.H);
    value[limbIndex] = 0n;
    output.H = encodeM89Hex(value);
  }
  return output;
};
const expectedStage = (family, relation) => family === 'wrong-length' || family === 'truncation' || family === 'trailing-bytes'
  ? 'exact-extension-element-length-check-before-limb-decode'
  : family === 'out-of-range' ? 'coefficient-range-check-before-arithmetic'
    : family === 'sign-alias' ? 'unused-high-bit-check-before-numeric-decode'
      : relation === RELATIONS[2] ? 'inverse-relation-check' : 'relation-check';
const malformedCases = (relation, relationIndex) => mutationFamiliesFor(relation).flatMap((family, mutationIndex) => [0, 1].map((limbIndex) => {
  const caseIndex = mutationIndex * 2 + limbIndex;
  return retryVector((vectorAttempt) => {
    const base = independentBase(relation, relationIndex, 4, caseIndex, vectorAttempt);
    if (!base) return null;
    if (family === 'swapped-limb' && equal(base.A, [base.A[1], base.A[0]])) return null;
    if (family === 'zero-inverse-hint' && base.H[limbIndex] === 0n) return null;
    const candidate = makeCase(relation, CATEGORIES[4], caseIndex, vectorAttempt, mutate(relation, family, limbIndex, raw(base)), { mutation: family, limbIndex });
    return candidate.expected.verdict === 'reject' && candidate.expected.stage === expectedStage(family, relation) ? candidate : null;
  });
}));

export function generateCases() {
  const cases = [];
  for (const [relationIndex, relation] of RELATIONS.entries()) {
    cases.push(...validCases(relation));
    cases.push(...boundaryCases(relation));
    cases.push(...randomCases(relation, relationIndex));
    cases.push(...metamorphicCases(relation, relationIndex));
    cases.push(...malformedCases(relation, relationIndex));
  }
  return cases;
}
export const caseCounts = (cases = generateCases()) => Object.fromEntries(RELATIONS.map((relation) => [relation, cases.filter((item) => item.relationId === relation).length]));
export function buildArtifact() {
  const cases = generateCases();
  return {
    schema: 'shieldkit-labs/m89-gate-b0-shakedown-corpus/v2', status: 'deterministic-host-reference-corpus-component-only', selection: 'none', tupleRef: null,
    descriptor: { id: 'algebra-component:m89-d2-x2-plus-1-v1', contentDigest: DESCRIPTOR_DIGEST },
    campaign: { id: 'campaign:gate-b-arithmetic-v1', contentDigest: CAMPAIGN_DIGEST, fileDigest: CAMPAIGN_FILE_DIGEST },
    generator: { algorithm: 'sha256-counter-rejection-v2', protocolUse: 'host-test-only-not-protocol-hash-or-sampler', seedHex: SEED_HEX, domainTagAscii: DOMAIN_TAG, frame: 'ascii(domainTag)||00||seed[8]||relationIndex:u8||categoryIndex:u8||operandIndex:u8||limbIndex:u16le||caseIndex:u32le||vectorAttempt:u32le||sampleRetry:u32le', digestInterpretation: 'sha256(frame)-as-unsigned-little-endian-256-bit-integer' },
    counts: { total: cases.length, byRelation: caseCounts(cases), accepted: cases.filter((item) => item.expected.verdict === 'accept').length, rejected: cases.filter((item) => item.expected.verdict === 'reject').length },
    cases,
  };
}
export const artifactBytes = (artifact = buildArtifact()) => encoder.encode(`${canonicalize(artifact)}\n`);
export const artifactSha256 = (artifact = buildArtifact()) => createHash('sha256').update(artifactBytes(artifact)).digest('hex');
