/**
 * Bounded Gate-B0 M89 fixture adapter.
 *
 * This is a component-only Libauth replay. It deliberately uses a 35-byte
 * P2SH32 source lock because the bare M89 redeem scripts exceed the current
 * standard bare-script size boundary. No corpus bytes are decoded or
 * normalized before they enter the relation kernel.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  binToHex,
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  encodeTransaction,
  encodeTransactionOutputs,
  hash256,
} from '@bitauth/libauth';

import {
  buildM89EMacLockingBytecode,
  buildM89EMacUnlockingBytecode,
  buildM89ESquareMacLockingBytecode,
  buildM89ESquareMacUnlockingBytecode,
  buildM89EInverseCheckLockingBytecode,
  buildM89EInverseCheckUnlockingBytecode,
} from '../bch-kernels/m89-kernel.mjs';

export const M89_CORPUS = JSON.parse(readFileSync(
  new URL('../reference/m89-corpus.json', import.meta.url), 'utf8',
));

export const M89_RELATION_OPERANDS = Object.freeze({
  'relation:e-mac': ['A', 'B', 'C', 'D'],
  'relation:e-square-mac': ['A', 'C', 'D'],
  'relation:e-inverse-check': ['A', 'H'],
});

export const M89_P2SH32_SOURCE_VALUE_SATOSHIS = 1_000n;
export const M89_P2SH32_OUTPUT_VALUE_SATOSHIS = 1_000n;
export const M89_P2SH32_OUTPUT_LOCKING_BYTECODE = Uint8Array.of(0x51);

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const relationSuffix = (relationId) => relationId.replace('relation:e-', '');
const categorySuffix = (categoryId) => categoryId.replace('category:', '');

const hexToBytes = (hex, label) => {
  require(typeof hex === 'string' && hex.length % 2 === 0 && /^[0-9a-f]*$/iu.test(hex), `${label} must be even hexadecimal`);
  return Uint8Array.from(Buffer.from(hex, 'hex'));
};

/** Minimal push opcode for arbitrary redeem-script bytes. */
export const encodeMinimalPush = (bytes) => {
  require(bytes instanceof Uint8Array, 'minimal push requires Uint8Array');
  if (bytes.length <= 75) return Uint8Array.from([bytes.length, ...bytes]);
  if (bytes.length <= 0xff) return Uint8Array.from([0x4c, bytes.length, ...bytes]);
  require(bytes.length <= 0xffff, 'minimal push only supports PUSHDATA2');
  return Uint8Array.from([0x4d, bytes.length & 0xff, bytes.length >>> 8, ...bytes]);
};

const p2sh32Lock = (redeemBytecode) => Uint8Array.from([
  0xaa, // OP_HASH256
  0x20, // push exactly 32-byte hash256 commitment
  ...hash256(redeemBytecode),
  0x87, // OP_EQUAL
]);

const operandNames = (relationId) => {
  const names = M89_RELATION_OPERANDS[relationId];
  require(names !== undefined, `unsupported M89 relation ${relationId}`);
  return names;
};

const rawOperands = (entry) => Object.fromEntries(operandNames(entry.relationId).map((name) => [
  name,
  hexToBytes(entry.raw?.[name], `${entry.relationId}.${name}`),
]));

const relationBytecodes = (entry, raw) => {
  if (entry.relationId === 'relation:e-mac') return {
    redeemBytecode: buildM89EMacLockingBytecode(),
    operandUnlockingBytecode: buildM89EMacUnlockingBytecode({
      rawFirst: raw.A, rawSecond: raw.B, rawAddend: raw.C, rawResult: raw.D,
    }),
  };
  if (entry.relationId === 'relation:e-square-mac') return {
    redeemBytecode: buildM89ESquareMacLockingBytecode(),
    operandUnlockingBytecode: buildM89ESquareMacUnlockingBytecode({
      rawFirst: raw.A, rawAddend: raw.C, rawResult: raw.D,
    }),
  };
  return {
    redeemBytecode: buildM89EInverseCheckLockingBytecode(),
    operandUnlockingBytecode: buildM89EInverseCheckUnlockingBytecode({
      rawValue: raw.A, rawInverseHint: raw.H,
    }),
  };
};

const fixtureId = (entry) => [
  'm89-gate-b0', relationSuffix(entry.relationId), categorySuffix(entry.categoryId),
  entry.caseIndex, `v${entry.vectorAttempt}`,
].join(':');

const buildTransactionWires = ({ sourceLockingBytecode, unlockingBytecode }) => {
  const sourceOutputs = [{
    lockingBytecode: sourceLockingBytecode,
    valueSatoshis: M89_P2SH32_SOURCE_VALUE_SATOSHIS,
  }];
  const transaction = {
    version: 2,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(0x11),
      outpointIndex: 0,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode,
    }],
    outputs: [{
      lockingBytecode: M89_P2SH32_OUTPUT_LOCKING_BYTECODE,
      valueSatoshis: M89_P2SH32_OUTPUT_VALUE_SATOSHIS,
    }],
    locktime: 0,
  };
  const transactionWire = encodeTransaction(transaction);
  const sourceOutputsWire = encodeTransactionOutputs(sourceOutputs);
  return Object.freeze({
    transactionWire,
    sourceOutputsWire,
    transactionHex: binToHex(transactionWire),
    sourceOutputsHex: binToHex(sourceOutputsWire),
    transactionDigestSha256: sha256Hex(transactionWire),
    sourceOutputsDigestSha256: sha256Hex(sourceOutputsWire),
  });
};

export const buildM89ShakedownFixture = (entry) => {
  require(entry !== null && typeof entry === 'object', 'M89 corpus case must be an object');
  const raw = rawOperands(entry);
  const { redeemBytecode, operandUnlockingBytecode } = relationBytecodes(entry, raw);
  const redeemPush = encodeMinimalPush(redeemBytecode);
  const unlockingBytecode = Uint8Array.from([...operandUnlockingBytecode, ...redeemPush]);
  const sourceLockingBytecode = p2sh32Lock(redeemBytecode);
  const wires = buildTransactionWires({ sourceLockingBytecode, unlockingBytecode });
  return Object.freeze({
    fixtureId: fixtureId(entry),
    relationId: entry.relationId,
    categoryId: entry.categoryId,
    caseIndex: entry.caseIndex,
    vectorAttempt: entry.vectorAttempt,
    expected: entry.expected,
    raw,
    redeemBytecode,
    redeemHex: binToHex(redeemBytecode),
    redeemBytes: redeemBytecode.length,
    redeemHash256Hex: binToHex(hash256(redeemBytecode)),
    redeemDigestSha256: sha256Hex(redeemBytecode),
    sourceLockingBytecode,
    sourceLockingHex: binToHex(sourceLockingBytecode),
    sourceLockingBytes: sourceLockingBytecode.length,
    unlockingBytecode,
    unlockingHex: binToHex(unlockingBytecode),
    unlockingBytes: unlockingBytecode.length,
    operandUnlockingBytecode,
    operandUnlockingBytes: operandUnlockingBytecode.length,
    redeemPush,
    redeemPushBytes: redeemPush.length,
    wrapperDigestSha256: sha256Hex(unlockingBytecode),
    sourceValueSatoshis: M89_P2SH32_SOURCE_VALUE_SATOSHIS,
    outputValueSatoshis: M89_P2SH32_OUTPUT_VALUE_SATOSHIS,
    outputLockingHex: binToHex(M89_P2SH32_OUTPUT_LOCKING_BYTECODE),
    dustSafe: M89_P2SH32_SOURCE_VALUE_SATOSHIS >= 546n
      && M89_P2SH32_OUTPUT_VALUE_SATOSHIS >= 546n,
    ...wires,
  });
};

const isStrictSuccess = (state) => state.error === undefined
  && state.stack.length === 1
  && state.stack[0].length === 1
  && state.stack[0][0] === 1
  && state.alternateStack.length === 0
  && state.controlStack.length === 0;

const maximum = (values) => values.reduce((current, value) => Math.max(current, value), 0);
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
    ).filter((value) => value !== null && typeof value === 'object' && Array.isArray(value.instructions)).length)),
    cumulativeMemoryItems: maximum(trace.map((state) => (
      (state.stack?.length ?? 0) + (state.alternateStack?.length ?? 0) + (state.functionCount ?? 0)
    ))),
    elementBytes: maximum(elementLengths),
  });
};

const opcodeKey = (opcode) => `0x${opcode.toString(16).padStart(2, '0')}`;
const traceMetrics = (trace) => {
  const histogram = new Map();
  let mulByteProduct = 0;
  let divByteProduct = 0;
  let modByteProduct = 0;
  let resultPushBytes = 0;
  const arithmeticCounts = { mul: 0, div: 0, mod: 0 };
  for (const [index, state] of trace.entries()) {
    const opcode = state.instruction?.opcode;
    if (!Number.isInteger(opcode)) continue;
    const key = opcodeKey(opcode);
    histogram.set(key, (histogram.get(key) ?? 0) + 1);
    if (opcode !== 0x95 && opcode !== 0x96 && opcode !== 0x97) continue;
    const operands = state.stack ?? [];
    const left = operands.at(-2);
    const right = operands.at(-1);
    const byteProduct = left === undefined || right === undefined ? 0 : left.length * right.length;
    const nextStack = trace[index + 1]?.stack ?? [];
    const result = nextStack.at(-1);
    resultPushBytes += result?.length ?? 0;
    if (opcode === 0x95) { mulByteProduct += byteProduct; arithmeticCounts.mul += 1; }
    if (opcode === 0x96) { divByteProduct += byteProduct; arithmeticCounts.div += 1; }
    if (opcode === 0x97) { modByteProduct += byteProduct; arithmeticCounts.mod += 1; }
  }
  return Object.freeze({
    opcodeHistogram: Object.fromEntries([...histogram.entries()].sort(([left], [right]) => left.localeCompare(right))),
    mulByteProduct,
    divByteProduct,
    modByteProduct,
    resultPushBytes,
    arithmeticCounts: Object.freeze(arithmeticCounts),
  });
};

export const evaluateM89ShakedownFixture = (fixture) => {
  const vm = createVirtualMachineBch2026(true);
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: fixture.sourceLockingBytecode,
    unlockingBytecode: fixture.unlockingBytecode,
    valueSatoshis: M89_P2SH32_SOURCE_VALUE_SATOSHIS,
  });
  const trace = vm.debug(program, { maskProgramState: true });
  const state = trace.at(-1);
  require(state !== undefined, 'Libauth debug trace is empty');
  const maxima = stackMaximums(trace);
  const arithmetic = traceMetrics(trace);
  // Preserve every Libauth metric field, including density-control and
  // defined-function accounting; consumers may project their metric vector.
  const rawMetrics = Object.freeze({ ...state.metrics });
  const standardnessByteSizes = Object.freeze({
    sourceLockingBytes: fixture.sourceLockingBytes,
    unlockingBytes: fixture.unlockingBytes,
    sourceOutputsBytes: fixture.sourceOutputsWire.length,
    redeemBytes: fixture.redeemBytes,
    redeemPushBytes: fixture.redeemPushBytes,
    outputLockingBytes: M89_P2SH32_OUTPUT_LOCKING_BYTECODE.length,
  });
  return Object.freeze({
    ...fixture,
    accepted: isStrictSuccess(state),
    error: state.error ?? null,
    // Libauth standard VM rules/flags; this is not a complete policy verdict
    // for a mined transaction or node mempool.
    standardVmRules: true,
    traceLength: trace.length,
    rawMetrics,
    metrics: rawMetrics,
    stackMaximums: maxima,
    elementMax: maxima.elementBytes,
    standardnessByteSizes,
    ...arithmetic,
  });
};

export const evaluateM89ShakedownCase = (entry) => evaluateM89ShakedownFixture(buildM89ShakedownFixture(entry));

export const evaluateM89ShakedownCorpus = (corpus = M89_CORPUS) => {
  require(Array.isArray(corpus.cases), 'M89 corpus must contain cases');
  return Object.freeze(corpus.cases.map(evaluateM89ShakedownCase));
};
