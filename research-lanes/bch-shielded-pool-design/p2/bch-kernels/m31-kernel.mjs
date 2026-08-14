/**
 * Thin, deterministic M31 BCH Script kernel adapter.
 *
 * This is a Tranche-1 control kernel for candidate rows field:m31-*. It selects
 * no extension tower, Circle domain, hash, AIR, proof format, or deployment
 * covenant. The only relation is c = a*b mod (2^31-1), after each public input
 * has passed the fixed-width canonical decoder below.
 */

import { createHash } from 'node:crypto';

import {
  binToHex,
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  encodeTransaction,
  encodeTransactionOutputs,
} from '@bitauth/libauth';

export const M31_PRIME = 2_147_483_647n;
export const M31_ELEMENT_BYTES = 4;

const OP = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_4: 0x54,
  OP_VERIFY: 0x69,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_DUP: 0x76,
  OP_NIP: 0x77,
  OP_ROT: 0x7b,
  OP_SWAP: 0x7c,
  OP_CAT: 0x7e,
  OP_NUM2BIN: 0x80,
  OP_BIN2NUM: 0x81,
  OP_SIZE: 0x82,
  OP_EQUALVERIFY: 0x88,
  OP_MUL: 0x95,
  OP_MOD: 0x97,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHANOREQUAL: 0xa2,
});
export const M31_SCRIPT_OPCODES = OP;

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

const push = (bytes) => {
  require(bytes instanceof Uint8Array && bytes.length <= 75, 'only direct-push fixtures are supported');
  return [bytes.length, ...bytes];
};
export const encodeDirectPush = push;

export const bytesToHex = (bytes) => binToHex(bytes);
export const sha256Artifact = (bytes) => sha256Hex(bytes);

/** Encode one M31 element as exactly four unsigned little-endian bytes. */
export const encodeM31 = (value) => {
  require(typeof value === 'bigint' && value >= 0n && value < M31_PRIME, 'M31 value must satisfy 0 <= x < p');
  return Uint8Array.from([
    Number(value & 0xffn),
    Number((value >> 8n) & 0xffn),
    Number((value >> 16n) & 0xffn),
    Number((value >> 24n) & 0xffn),
  ]);
};

/**
 * Native reference decoder. It interprets all four bytes as unsigned LE then
 * applies the field bound; therefore values with bit 31 set cannot alias a
 * signed ScriptNum value before they are rejected.
 */
export const decodeM31 = (bytes) => {
  require(bytes instanceof Uint8Array && bytes.length === M31_ELEMENT_BYTES, 'M31 element must be exactly four bytes');
  const value = BigInt(bytes[0])
    | (BigInt(bytes[1]) << 8n)
    | (BigInt(bytes[2]) << 16n)
    | (BigInt(bytes[3]) << 24n);
  require(value < M31_PRIME, 'M31 fixed LE encoding is out of range');
  return value;
};

// p itself is intentionally not a canonical field element, but it is a valid
// positive ScriptNum constant used only as the strict upper bound.
export const M31_PRIME_SCRIPT_PUSH = Object.freeze(push(Uint8Array.of(0xff, 0xff, 0xff, 0x7f)));

/**
 * Decode the top raw field element to a Script number and preserve exactly one
 * numeric copy. A fixed-width raw value is first duplicated and given a fifth,
 * literal zero byte. This `raw || 00` word is an unambiguously non-negative
 * ScriptNum representation of the entire unsigned u32 input: it cannot turn a
 * high-bit value (including negative zero) into a smaller signed value. The
 * `raw || 00` is injective for a fixed four-byte raw word, so the explicit
 * width and `< p` checks completely define the accepted representation.
 */
export const decodeFixedM31Top = () => [
  OP.OP_SIZE,
  OP.OP_4,
  OP.OP_NUMEQUALVERIFY,
  // Synthesize exactly one raw 00 byte as NUM2BIN(0, 1), then decode raw || 00.
  // (A numeric `0x80 & 0x80 == 0` check would itself admit negative zero.)
  OP.OP_DUP,
  OP.OP_0,
  OP.OP_1,
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_BIN2NUM,
  // Delete the original raw word; raw||00 uniquely represented its u32 value.
  OP.OP_NIP,
  OP.OP_DUP,
  OP.OP_0,
  OP.OP_GREATERTHANOREQUAL,
  OP.OP_VERIFY,
  OP.OP_DUP,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_LESSTHAN,
  OP.OP_VERIFY,
];

/**
 * Locking program. Unlocking stack order is bottom-to-top cRaw, bRaw, aRaw.
 * The decoder transforms it to a, b, c, then checks a*b mod p == c.
 */
export const buildM31MulLockingBytecode = () => Uint8Array.from([
  ...decodeFixedM31Top(),
  OP.OP_SWAP,
  ...decodeFixedM31Top(),
  OP.OP_ROT,
  ...decodeFixedM31Top(),
  OP.OP_TOALTSTACK,
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_FROMALTSTACK,
  OP.OP_NUMEQUAL,
]);

export const buildM31MulUnlockingBytecode = ({
  a,
  b,
  product,
  rawA = a === undefined ? undefined : encodeM31(a),
  rawB = b === undefined ? undefined : encodeM31(b),
  rawProduct = product === undefined ? undefined : encodeM31(product),
} = {}) => {
  require(rawA instanceof Uint8Array && rawB instanceof Uint8Array && rawProduct instanceof Uint8Array, 'each M31 kernel input needs raw bytes');
  return Uint8Array.from([
    ...push(rawProduct),
    ...push(rawB),
    ...push(rawA),
  ]);
};

const isStrictSuccess = (state) => state.error === undefined
  && state.stack.length === 1
  && state.stack[0].length === 1
  && state.stack[0][0] === 1
  && state.alternateStack.length === 0
  && state.controlStack.length === 0;

export const rawMetricProjection = (metrics) => ({
  evaluatedInstructionCount: metrics.evaluatedInstructionCount,
  signatureCheckCount: metrics.signatureCheckCount,
  hashDigestIterations: metrics.hashDigestIterations,
  arithmeticCost: metrics.arithmeticCost,
  stackPushedBytes: metrics.stackPushedBytes,
  operationCost: metrics.operationCost,
});

const maximum = (values) => values.reduce((current, value) => Math.max(current, value), 0);
const isFunctionFrame = (value) => value !== null
  && typeof value === 'object'
  && Array.isArray(value.instructions)
  && Number.isInteger(value.ip);

const stackMaximums = (trace) => {
  const elementLengths = trace.flatMap((state) => [
    ...(state.stack ?? []),
    ...(state.alternateStack ?? []),
    ...Object.values(state.functionTable ?? {}),
  ]).map((item) => item.length);
  return Object.freeze({
    primaryItems: maximum(trace.map((state) => state.stack?.length ?? 0)),
    alternateItems: maximum(trace.map((state) => state.alternateStack?.length ?? 0)),
    definedFunctions: maximum(trace.map((state) => state.functionCount ?? 0)),
    controlDepth: maximum(trace.map((state) => state.controlStack?.length ?? 0)),
    functionCallDepth: maximum(trace.map((state) => (
      state.controlStack ?? []
    ).filter(isFunctionFrame).length)),
    cumulativeMemoryItems: maximum(trace.map((state) => (
      (state.stack?.length ?? 0) + (state.alternateStack?.length ?? 0) + (state.functionCount ?? 0)
    ))),
    elementBytes: maximum(elementLengths),
  });
};

const resourceLimits = ({ metrics, maxima, lockingBytecode, unlockingBytecode }) => Object.freeze({
  maximumOperationCost: metrics.maximumOperationCost,
  operationCostHeadroom: metrics.maximumOperationCost - metrics.operationCost,
  maximumHashDigestIterations: metrics.maximumHashDigestIterations,
  hashDigestIterationsHeadroom: metrics.maximumHashDigestIterations - metrics.hashDigestIterations,
  maximumSignatureCheckCount: metrics.maximumSignatureCheckCount,
  signatureCheckCountHeadroom: metrics.maximumSignatureCheckCount - metrics.signatureCheckCount,
  maximumStackItems: 1_000,
  stackItemsHeadroom: 1_000 - maxima.cumulativeMemoryItems,
  maximumElementBytes: 10_000,
  elementBytesHeadroom: 10_000 - maxima.elementBytes,
  maximumLockingBytes: 10_000,
  lockingBytesHeadroom: 10_000 - lockingBytecode.length,
  maximumUnlockingBytes: 10_000,
  unlockingBytesHeadroom: 10_000 - unlockingBytecode.length,
});

/** Evaluate a deterministic synthetic BCH spend using standard/relay BCH-2026 VM limits. */
export const evaluateScriptFixture = ({ lockingBytecode, unlockingBytecode }) => {
  const standard = true;
  const vm = createVirtualMachineBch2026(standard);
  const program = createTestAuthenticationProgramBch({
    lockingBytecode,
    unlockingBytecode,
    valueSatoshis: 1000n,
  });
  const trace = vm.debug(program, { maskProgramState: true });
  const state = trace.at(-1);
  require(state !== undefined, 'Libauth BCH-2026 debug trace is empty');
  const maxima = stackMaximums(trace);
  return Object.freeze({
    accepted: isStrictSuccess(state),
    error: state.error ?? null,
    standard,
    metrics: Object.freeze({
      ...rawMetricProjection(state.metrics),
      stackMaximums: maxima,
      limits: resourceLimits({ metrics: state.metrics, maxima, lockingBytecode, unlockingBytecode }),
    }),
    lockingHex: binToHex(lockingBytecode),
    unlockingHex: binToHex(unlockingBytecode),
    lockingDigestSha256: sha256Hex(lockingBytecode),
    unlockingDigestSha256: sha256Hex(unlockingBytecode),
  });
};
export const evaluateM31Mul = evaluateScriptFixture;

/** Create the exact single-input fixture wires consumed by LeanBCH costprobe. */
export const encodeScriptTransactionFixture = ({ lockingBytecode, unlockingBytecode }) => {
  const sourceOutputs = [{ lockingBytecode, valueSatoshis: 1000n }];
  const transaction = {
    version: 2,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(0x11),
      outpointIndex: 0,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode,
    }],
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n }],
    locktime: 0,
  };
  const transactionWire = encodeTransaction(transaction);
  const sourceOutputsWire = encodeTransactionOutputs(sourceOutputs);
  return Object.freeze({
    transactionHex: binToHex(transactionWire),
    sourceOutputsHex: binToHex(sourceOutputsWire),
    transactionDigestSha256: sha256Hex(transactionWire),
    sourceOutputsDigestSha256: sha256Hex(sourceOutputsWire),
  });
};
export const encodeM31MulTransactionFixture = encodeScriptTransactionFixture;

const M31_CODEC_BOUNDARIES = Object.freeze([
  ['m31-codec-zero', 0n],
  ['m31-codec-one', 1n],
  ['m31-codec-width-7f', 0x7fn],
  ['m31-codec-width-80', 0x80n],
  ['m31-codec-width-ff', 0xffn],
  ['m31-codec-width-0100', 0x100n],
  ['m31-codec-width-7fff', 0x7fffn],
  ['m31-codec-width-8000', 0x8000n],
  ['m31-codec-width-7fffff', 0x7f_ffffn],
  ['m31-codec-width-800000', 0x80_0000n],
  ['m31-codec-width-ffffff', 0xff_ffffn],
  ['m31-codec-width-01000000', 0x100_0000n],
  ['m31-codec-two-to-30', 1n << 30n],
  ['m31-codec-p-minus-two', M31_PRIME - 2n],
  ['m31-codec-p-minus-one', M31_PRIME - 1n],
]);

export const M31_KERNEL_CASES = Object.freeze([
  ...M31_CODEC_BOUNDARIES.map(([id, value]) => ({ id, a: value, b: 1n, product: value, accepted: true })),
  { id: 'm31-small-product', a: 3n, b: 5n, product: 15n, accepted: true },
  { id: 'm31-zero-product', a: 0n, b: 123n, product: 0n, accepted: true },
  { id: 'm31-product-boundary', a: M31_PRIME - 1n, b: M31_PRIME - 1n, product: 1n, accepted: true },
  { id: 'm31-p-minus-two-square', a: M31_PRIME - 2n, b: M31_PRIME - 2n, product: 4n, accepted: true },
  { id: 'm31-out-of-range-p', a: M31_PRIME, b: 1n, product: 0n, rawA: Uint8Array.of(0xff, 0xff, 0xff, 0x7f), accepted: false },
  { id: 'm31-p-plus-one-sign-alias', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0x00, 0x00, 0x00, 0x80), accepted: false },
  { id: 'm31-p-plus-two-sign-alias', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0x01, 0x00, 0x00, 0x80), accepted: false },
  { id: 'm31-max-u32', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0xff, 0xff, 0xff, 0xff), accepted: false },
  { id: 'm31-zero-byte-alias', a: 0n, b: 1n, product: 0n, rawA: new Uint8Array(), accepted: false },
  { id: 'm31-one-byte-alias', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0x42), accepted: false },
  { id: 'm31-two-byte-alias', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0x01, 0x00), accepted: false },
  { id: 'm31-three-byte-alias', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0x01, 0x00, 0x00), accepted: false },
  { id: 'm31-five-byte-alias', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0x01, 0x00, 0x00, 0x00, 0x00), accepted: false },
  { id: 'm31-six-byte-alias', a: 0n, b: 1n, product: 0n, rawA: Uint8Array.of(0x01, 0x00, 0x00, 0x00, 0x00, 0x00), accepted: false },
  { id: 'm31-wrong-product', a: 3n, b: 5n, product: 14n, accepted: false },
]);

export const materializeM31Case = (entry) => {
  const lockingBytecode = buildM31MulLockingBytecode();
  const unlockingBytecode = buildM31MulUnlockingBytecode(entry);
  return Object.freeze({ ...entry, lockingBytecode, unlockingBytecode });
};
