/**
 * Deterministic, generated neutral-M31 corpus for cross-engine qualification.
 *
 * This composes the already-pinned native corpus with the isolated BCH Script
 * relations. It selects no extension field, Circle domain, hash, AIR, proof,
 * or deployment topology.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { inverse } from '../reference/m31.mjs';
import {
  M31_BASE_OP_CASES,
  encodeBaseOpTransactionFixture,
  evaluateBaseOpCase,
  materializeBaseOpCase,
} from './base-ops.mjs';
import {
  M31_KERNEL_CASES,
  M31_PRIME,
  bytesToHex,
  encodeM31,
  encodeM31MulTransactionFixture,
  evaluateM31Mul,
  materializeM31Case,
} from './m31-kernel.mjs';

const corpusUrl = new URL('../reference/m31-corpus.json', import.meta.url);
const corpusBytes = readFileSync(corpusUrl);
const corpus = JSON.parse(corpusBytes.toString('utf8'));
const n = (value) => BigInt(value);
const mod = (value) => ((value % M31_PRIME) + M31_PRIME) % M31_PRIME;

export const M31_FULL_BASE_CORPUS_SHA256 = createHash('sha256').update(corpusBytes).digest('hex');

const operationCase = ({ id, operation, a, b, result, accepted = true }) => {
  if (operation === 'add') return { id, operation, left: a, right: b, sum: result, accepted };
  if (operation === 'sub') return { id, operation, left: a, right: b, difference: result, accepted };
  if (operation === 'neg') return { id, operation, value: a, negation: result, accepted };
  if (operation === 'mul') return { id, operation, a, b, product: result, accepted };
  if (operation === 'square') return { id, operation, value: a, square: result, accepted };
  if (operation === 'inverseHint') return { id, operation, value: a, inverseHint: result, accepted };
  throw new TypeError(`unknown generated operation ${operation}`);
};

const requiredKatCases = corpus.requiredKats.map((kat) => {
  const a = n(kat.a);
  if (kat.op === 'inverse') {
    return operationCase({ id: `corpus-kat-${kat.id}`, operation: 'inverseHint', a, result: n(kat.expected) });
  }
  if (kat.op === 'inverse-hint') {
    return operationCase({
      id: `corpus-kat-${kat.id}`,
      operation: 'inverseHint',
      a,
      result: n(kat.hint),
      accepted: kat.valid,
    });
  }
  return operationCase({
    id: `corpus-kat-${kat.id}`,
    operation: kat.op,
    a,
    b: kat.b === undefined ? undefined : n(kat.b),
    result: n(kat.expected),
  });
});

const randomCases = corpus.randomVectors.flatMap((row) => {
  const a = n(row.a);
  const b = n(row.b);
  return [
    operationCase({ id: `${row.id}-add`, operation: 'add', a, b, result: n(row.add) }),
    operationCase({ id: `${row.id}-sub`, operation: 'sub', a, b, result: n(row.sub) }),
    operationCase({ id: `${row.id}-neg`, operation: 'neg', a, result: n(row.negA) }),
    operationCase({ id: `${row.id}-mul`, operation: 'mul', a, b, result: n(row.mul) }),
    operationCase({ id: `${row.id}-square`, operation: 'square', a, result: n(row.squareA) }),
    operationCase({ id: `${row.id}-inverse`, operation: 'inverseHint', a, result: n(row.inverseHintA) }),
    operationCase({ id: `${row.id}-inverse-wrong`, operation: 'inverseHint', a, result: n(row.wrongInverseHintA), accepted: false }),
  ];
});

const lowRangeCases = [];
for (let a = n(corpus.exhaustiveLowRange.start); a < n(corpus.exhaustiveLowRange.endExclusive); a += 1n) {
  lowRangeCases.push(operationCase({ id: `low-${a}-neg`, operation: 'neg', a, result: mod(-a) }));
  lowRangeCases.push(operationCase({ id: `low-${a}-square`, operation: 'square', a, result: mod(a * a) }));
  if (a !== 0n) lowRangeCases.push(operationCase({ id: `low-${a}-inverse`, operation: 'inverseHint', a, result: inverse(a) }));
  for (let b = n(corpus.exhaustiveLowRange.start); b < n(corpus.exhaustiveLowRange.endExclusive); b += 1n) {
    lowRangeCases.push(operationCase({ id: `low-${a}-${b}-add`, operation: 'add', a, b, result: mod(a + b) }));
    lowRangeCases.push(operationCase({ id: `low-${a}-${b}-sub`, operation: 'sub', a, b, result: mod(a - b) }));
    lowRangeCases.push(operationCase({ id: `low-${a}-${b}-mul`, operation: 'mul', a, b, result: mod(a * b) }));
  }
}

const boundaryCases = [];
const boundaries = corpus.boundaryValues.map(n);
for (const [aIndex, a] of boundaries.entries()) {
  boundaryCases.push(operationCase({ id: `boundary-${aIndex}-neg`, operation: 'neg', a, result: mod(-a) }));
  boundaryCases.push(operationCase({ id: `boundary-${aIndex}-square`, operation: 'square', a, result: mod(a * a) }));
  if (a !== 0n) boundaryCases.push(operationCase({ id: `boundary-${aIndex}-inverse`, operation: 'inverseHint', a, result: inverse(a) }));
  for (const [bIndex, b] of boundaries.entries()) {
    boundaryCases.push(operationCase({ id: `boundary-${aIndex}-${bIndex}-add`, operation: 'add', a, b, result: mod(a + b) }));
    boundaryCases.push(operationCase({ id: `boundary-${aIndex}-${bIndex}-sub`, operation: 'sub', a, b, result: mod(a - b) }));
    boundaryCases.push(operationCase({ id: `boundary-${aIndex}-${bIndex}-mul`, operation: 'mul', a, b, result: mod(a * b) }));
  }
}

const malformedWords = Object.freeze({
  short3: Uint8Array.of(0x01, 0x00, 0x00),
  modulus: Uint8Array.of(0xff, 0xff, 0xff, 0x7f),
  highBitAlias: Uint8Array.of(0x00, 0x00, 0x00, 0x80),
  overlong5: Uint8Array.of(0x01, 0x00, 0x00, 0x00, 0x00),
});

const malformedTemplates = Object.freeze([
  {
    operation: 'add',
    canonical: { left: 3n, right: 5n, sum: 8n },
    positions: ['rawLeft', 'rawRight', 'rawSum'],
  },
  {
    operation: 'sub',
    canonical: { left: 3n, right: 5n, difference: M31_PRIME - 2n },
    positions: ['rawLeft', 'rawRight', 'rawDifference'],
  },
  {
    operation: 'neg',
    canonical: { value: 3n, negation: M31_PRIME - 3n },
    positions: ['rawValue', 'rawNegation'],
  },
  {
    operation: 'square',
    canonical: { value: 3n, square: 9n },
    positions: ['rawValue', 'rawSquare'],
  },
  {
    operation: 'inverseHint',
    canonical: { value: 2n, inverseHint: (M31_PRIME + 1n) / 2n },
    positions: ['rawValue', 'rawInverseHint'],
  },
  {
    operation: 'mul',
    canonical: { a: 3n, b: 5n, product: 15n },
    positions: ['rawA', 'rawB', 'rawProduct'],
  },
]);

const malformedPositionCases = malformedTemplates.flatMap((template) => template.positions.flatMap((position) => (
  Object.entries(malformedWords).map(([variant, bytes]) => ({
    id: `malformed-${template.operation}-${position}-${variant}`,
    operation: template.operation,
    ...template.canonical,
    [position]: bytes,
    accepted: false,
  }))
)));

const signByteMutationCases = [0, 1, 2].map((decoderOrdinal) => ({
  id: `decoder-sign-byte-mutation-${decoderOrdinal}`,
  operation: 'mul',
  a: 3n,
  b: 5n,
  product: 15n,
  decoderSignByteMutationOrdinal: decoderOrdinal,
  accepted: false,
}));

export const M31_FULL_BASE_CASES = Object.freeze([
  ...M31_KERNEL_CASES.map((entry) => ({ ...entry, operation: 'mul' })),
  ...M31_BASE_OP_CASES,
  ...requiredKatCases,
  ...randomCases,
  ...lowRangeCases,
  ...boundaryCases,
  ...malformedPositionCases,
  ...signByteMutationCases,
]);

const mutateDecoderSignByte = (fixture, ordinal) => {
  const mutated = fixture.lockingBytecode.slice();
  const pattern = [0x76, 0x00, 0x51, 0x80, 0x7e];
  const offsets = [];
  for (let index = 0; index <= mutated.length - pattern.length; index += 1) {
    if (pattern.every((byte, inner) => mutated[index + inner] === byte)) offsets.push(index);
  }
  if (offsets.length !== 3 || offsets[ordinal] === undefined) throw new Error('M31 decoder mutation pattern changed');
  mutated[offsets[ordinal] + 1] = 0x51;
  return Object.freeze({ ...fixture, lockingBytecode: mutated });
};

export const materializeFullBaseCase = (entry) => {
  if (entry.operation !== 'mul') return materializeBaseOpCase(entry);
  const fixture = materializeM31Case(entry);
  return entry.decoderSignByteMutationOrdinal === undefined
    ? fixture
    : mutateDecoderSignByte(fixture, entry.decoderSignByteMutationOrdinal);
};

export const evaluateFullBaseCase = (entry) => {
  const fixture = materializeFullBaseCase(entry);
  if (entry.operation === 'mul' && entry.decoderSignByteMutationOrdinal === undefined) return evaluateM31Mul(fixture);
  if (entry.operation !== 'mul') return evaluateBaseOpCase(entry);
  return evaluateM31Mul(fixture);
};

export const encodeFullBaseTransactionFixture = (entry) => {
  const fixture = materializeFullBaseCase(entry);
  return entry.operation === 'mul'
    ? encodeM31MulTransactionFixture(fixture)
    : encodeBaseOpTransactionFixture(entry);
};

const rawOrCanonical = (entry, rawKey, valueKey) => entry[rawKey] ?? encodeM31(entry[valueKey]);

export const rawInputHexForFullBaseCase = (entry) => {
  if (entry.operation === 'mul') return {
    a: bytesToHex(rawOrCanonical(entry, 'rawA', 'a')),
    b: bytesToHex(rawOrCanonical(entry, 'rawB', 'b')),
    product: bytesToHex(rawOrCanonical(entry, 'rawProduct', 'product')),
  };
  if (entry.operation === 'add') return {
    left: bytesToHex(rawOrCanonical(entry, 'rawLeft', 'left')),
    right: bytesToHex(rawOrCanonical(entry, 'rawRight', 'right')),
    sum: bytesToHex(rawOrCanonical(entry, 'rawSum', 'sum')),
  };
  if (entry.operation === 'sub') return {
    left: bytesToHex(rawOrCanonical(entry, 'rawLeft', 'left')),
    right: bytesToHex(rawOrCanonical(entry, 'rawRight', 'right')),
    difference: bytesToHex(rawOrCanonical(entry, 'rawDifference', 'difference')),
  };
  if (entry.operation === 'neg') return {
    value: bytesToHex(rawOrCanonical(entry, 'rawValue', 'value')),
    negation: bytesToHex(rawOrCanonical(entry, 'rawNegation', 'negation')),
  };
  if (entry.operation === 'square') return {
    value: bytesToHex(rawOrCanonical(entry, 'rawValue', 'value')),
    square: bytesToHex(rawOrCanonical(entry, 'rawSquare', 'square')),
  };
  return {
    value: bytesToHex(rawOrCanonical(entry, 'rawValue', 'value')),
    inverseHint: bytesToHex(rawOrCanonical(entry, 'rawInverseHint', 'inverseHint')),
  };
};

const ids = new Set(M31_FULL_BASE_CASES.map(({ id }) => id));
if (ids.size !== M31_FULL_BASE_CASES.length) throw new Error('generated M31 full-base case IDs are not unique');
