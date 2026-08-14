/**
 * M89 degree-2 canonical-schoolbook BCH-2026 Libauth kernels.
 *
 * Gate-B0 component-only scope.  Inputs are exactly two contiguous 12-byte
 * unsigned little-endian coefficients over p = 2^89 - 1.  The Script parser
 * checks the fixed width, clears the seven unused high bits (mask fe), appends
 * one literal 00 sign guard before BIN2NUM, and enforces n < p.  No host-side
 * normalization is performed for supplied raw bytes.
 */

import {
  binToHex,
  encodeTransaction,
  encodeTransactionOutputs,
} from '@bitauth/libauth';

import {
  encodeDirectPush,
  evaluateScriptFixture,
  sha256Artifact,
} from './m31-kernel.mjs';

export const M89_PRIME = 618970019642690137449562111n;
export const M89_EXPONENT = 89;
export const M89_LIMB_BYTES = 12;
export const M89_ELEMENT_BYTES = 24;
export const M89_UNUSED_HIGH_BITS_MASK = 0xfe;

const OP = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_5: 0x55,
  OP_6: 0x56,
  OP_7: 0x57,
  OP_11: 0x5b,
  OP_12: 0x5c,
  OP_DUP: 0x76,
  OP_NIP: 0x77,
  OP_2DROP: 0x6d,
  OP_DROP: 0x75,
  OP_SWAP: 0x7c,
  OP_CAT: 0x7e,
  OP_SPLIT: 0x7f,
  OP_NUM2BIN: 0x80,
  OP_BIN2NUM: 0x81,
  OP_SIZE: 0x82,
  OP_AND: 0x84,
  OP_EQUALVERIFY: 0x88,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_VERIFY: 0x69,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_MOD: 0x97,
  OP_PICK: 0x79,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
});

export const M89_SCRIPT_OPCODES = OP;

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const directPush = (bytes) => {
  require(bytes instanceof Uint8Array && bytes.length <= 75, 'M89 direct push must be a short byte vector');
  return [...encodeDirectPush(bytes)];
};

const numericPush = (value) => {
  require(Number.isSafeInteger(value) && value >= 0 && value <= 16, 'small numeric opcode required');
  return value === 0 ? [OP.OP_0] : [OP.OP_1 + value - 1];
};

const numericPushBytes = (value) => directPush(Uint8Array.of(value));

const m89PrimePush = Object.freeze(directPush(Uint8Array.from([
  ...new Array(11).fill(0xff),
  0x01,
])));

export const M89_PRIME_SCRIPT_PUSH = m89PrimePush;

const highMaskPush = Object.freeze(directPush(Uint8Array.of(M89_UNUSED_HIGH_BITS_MASK)));

const assertRawLimb = (bytes) => {
  require(bytes instanceof Uint8Array, 'M89 raw limb must be Uint8Array');
  require(bytes.length === M89_LIMB_BYTES, 'M89 raw limb must be exactly 12 bytes');
  require((bytes.at(-1) & M89_UNUSED_HIGH_BITS_MASK) === 0, 'M89 raw limb sets unused high bits');
  return bytes;
};

const assertRawElement = (bytes) => {
  require(bytes instanceof Uint8Array, 'M89 raw element must be Uint8Array');
  require(bytes.length === M89_ELEMENT_BYTES, 'M89 raw element must be exactly 24 bytes');
  assertRawLimb(bytes.slice(0, M89_LIMB_BYTES));
  assertRawLimb(bytes.slice(M89_LIMB_BYTES));
  return bytes;
};

// Preserve protocol-supplied bytes verbatim. Script, rather than host
// normalization, is the rejection boundary for high bits and n >= p.
const assertRawElementShape = (bytes) => {
  require(bytes instanceof Uint8Array, 'M89 raw element must be Uint8Array');
  require(bytes.length <= 75, 'M89 raw element must fit one direct push');
  return bytes;
};

export const encodeM89 = (value) => {
  require(typeof value === 'bigint' && value >= 0n && value < M89_PRIME, 'M89 value must satisfy 0 <= x < p');
  const bytes = new Uint8Array(M89_LIMB_BYTES);
  let remaining = value;
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  require(remaining === 0n, 'M89 value did not fit the fixed 12-byte encoding');
  return bytes;
};

export const decodeM89 = (bytes) => {
  assertRawLimb(bytes);
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]);
  require(value < M89_PRIME, 'M89 fixed LE encoding is out of range');
  return value;
};

export const encodeM89Element = ({ c0, c1 }) => Uint8Array.from([
  ...encodeM89(c0),
  ...encodeM89(c1),
]);

export const decodeM89Element = (bytes) => {
  assertRawElement(bytes);
  return Object.freeze({
    c0: decodeM89(bytes.slice(0, M89_LIMB_BYTES)),
    c1: decodeM89(bytes.slice(M89_LIMB_BYTES)),
  });
};

/** Decode the top 12-byte raw limb and leave one Script number. */
export const decodeFixedM89Top = () => [
  OP.OP_SIZE,
  OP.OP_12,
  OP.OP_NUMEQUALVERIFY,
  // raw -> prefix suffix; preserve suffix for reconstruction after checking.
  OP.OP_DUP,
  OP.OP_11,
  OP.OP_SPLIT,
  OP.OP_DUP,
  ...highMaskPush,
  OP.OP_AND,
  // Synthesize one raw zero byte without a non-minimal direct 00 push.
  OP.OP_0,
  OP.OP_1,
  OP.OP_NUM2BIN,
  OP.OP_EQUALVERIFY,
  OP.OP_CAT,
  OP.OP_NIP,
  // raw || 00 is an injective non-negative ScriptNum representation.
  OP.OP_DUP,
  OP.OP_0,
  OP.OP_1,
  OP.OP_NUM2BIN,
  OP.OP_CAT,
  OP.OP_BIN2NUM,
  OP.OP_NIP,
  OP.OP_DUP,
  OP.OP_0,
  OP.OP_GREATERTHANOREQUAL,
  OP.OP_VERIFY,
  OP.OP_DUP,
  ...m89PrimePush,
  OP.OP_LESSTHAN,
  OP.OP_VERIFY,
];

/** Decode the top 24-byte element into c0,c1 (c0 below c1). */
export const decodeFixedM89ElementTop = () => [
  OP.OP_SIZE,
  ...numericPushBytes(M89_ELEMENT_BYTES),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_12,
  OP.OP_SPLIT,
  ...decodeFixedM89Top(),
  OP.OP_SWAP,
  ...decodeFixedM89Top(),
  OP.OP_SWAP,
];

const decodeThreeElements = () => [
  // Unlocking order is resultRaw, secondRaw, firstRaw; decode first first.
  ...decodeFixedM89ElementTop(),
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...decodeFixedM89ElementTop(),
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...decodeFixedM89ElementTop(),
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
];

const decodeFourElements = () => [
  // Unlocking order is resultRaw, addendRaw, secondRaw, firstRaw.
  ...decodeFixedM89ElementTop(), OP.OP_TOALTSTACK, OP.OP_TOALTSTACK,
  ...decodeFixedM89ElementTop(), OP.OP_TOALTSTACK, OP.OP_TOALTSTACK,
  ...decodeFixedM89ElementTop(), OP.OP_TOALTSTACK, OP.OP_TOALTSTACK,
  ...decodeFixedM89ElementTop(),
  OP.OP_FROMALTSTACK, OP.OP_FROMALTSTACK, OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK, OP.OP_FROMALTSTACK, OP.OP_FROMALTSTACK,
];

const pick = (index) => [
  ...(index <= 16 ? numericPush(index) : numericPushBytes(index)),
  OP.OP_PICK,
];

// Original three-element relation stack is [result0,result1,second0,second1,
// first0,first1], first1 on top. E-MAC adds [addend0,addend1] below second.
const productToAlt = (leftIndex, rightIndex) => [
  ...pick(leftIndex),
  ...pick(rightIndex + 1),
  OP.OP_MUL,
  // Reduce each product before subtraction; a raw difference can be below -p.
  ...m89PrimePush,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
];

// Keep the second product on the main stack. combineAltProduct pulls the
// first product from altstack and swaps it beneath this one.
const productOnStack = (leftIndex, rightIndex) => [
  ...pick(leftIndex),
  ...pick(rightIndex + 1),
  OP.OP_MUL,
  ...m89PrimePush,
  OP.OP_MOD,
];

const combineAltProduct = (operation) => [
  OP.OP_FROMALTSTACK,
  OP.OP_SWAP,
  operation,
];

const finishBinaryResultChecks = (result0Index, result1Index, dropCount) => [
  // r0 is compared with result0 after both results are restored.
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...pick(result0Index),
  OP.OP_NUMEQUALVERIFY,
  ...pick(result1Index),
  OP.OP_NUMEQUAL,
  OP.OP_TOALTSTACK,
  ...new Array(dropCount).fill(OP.OP_DROP),
  OP.OP_FROMALTSTACK,
];

/** E-MAC: D = A*B + C over Fp[u]/(u^2+1), canonical schoolbook. */
export const buildM89EMacLockingBytecode = () => Uint8Array.from([
  ...decodeFourElements(),
  // r0 = a0*b0 - a1*b1 mod p.
  ...productToAlt(1, 3),
  ...productOnStack(0, 2),
  ...combineAltProduct(OP.OP_SUB),
  ...m89PrimePush,
  OP.OP_ADD,
  ...m89PrimePush,
  OP.OP_MOD,
  ...pick(6),
  OP.OP_ADD,
  ...m89PrimePush,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  // r1 = a0*b1 + a1*b0 mod p.
  ...productToAlt(1, 2),
  ...productOnStack(0, 3),
  ...combineAltProduct(OP.OP_ADD),
  ...m89PrimePush,
  OP.OP_MOD,
  ...pick(5),
  OP.OP_ADD,
  ...m89PrimePush,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  ...finishBinaryResultChecks(9, 7, 8),
]);

const rawElement = (value, supplied, label) => {
  const bytes = supplied ?? (value === undefined ? undefined : encodeM89Element(value));
  require(bytes instanceof Uint8Array, `${label} requires raw bytes or a coefficient object`);
  return assertRawElementShape(bytes);
};

export const buildM89EMacUnlockingBytecode = ({ first, second, addend, result, rawFirst, rawSecond, rawAddend, rawResult } = {}) => Uint8Array.from([
  ...directPush(rawElement(result, rawResult, 'result')),
  ...directPush(rawElement(addend, rawAddend, 'addend')),
  ...directPush(rawElement(second, rawSecond, 'second')),
  ...directPush(rawElement(first, rawFirst, 'first')),
]);

/** E-SQUARE-MAC: D = A^2 + C over the same direct polynomial. */
export const buildM89ESquareMacLockingBytecode = () => Uint8Array.from([
  ...decodeThreeElements(),
  // r0 = a0^2 - a1^2 + c0 mod p.
  ...productToAlt(1, 1),
  ...productOnStack(0, 0),
  ...combineAltProduct(OP.OP_SUB),
  ...m89PrimePush,
  OP.OP_ADD,
  ...pick(4),
  OP.OP_ADD,
  ...m89PrimePush,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  // r1 = 2*a0*a1 + c1 mod p.
  ...productOnStack(1, 0),
  OP.OP_2,
  OP.OP_MUL,
  ...pick(3),
  OP.OP_ADD,
  ...m89PrimePush,
  OP.OP_MOD,
  OP.OP_TOALTSTACK,
  ...finishBinaryResultChecks(7, 5, 6),
]);

export const buildM89ESquareMacUnlockingBytecode = ({ first, addend, result, rawFirst, rawAddend, rawResult } = {}) => Uint8Array.from([
  ...directPush(rawElement(result, rawResult, 'result')),
  ...directPush(rawElement(addend, rawAddend, 'addend')),
  ...directPush(rawElement(first, rawFirst, 'first')),
]);

/** E-INVERSE-CHECK: A != 0 and A*H = 1. */
export const buildM89EInverseCheckLockingBytecode = () => Uint8Array.from([
  // Decode A (top) then H, leaving [h0,h1,a0,a1].
  ...decodeFixedM89ElementTop(),
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...decodeFixedM89ElementTop(),
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  // A != 0: a0+a1 == 0 iff both canonical coefficients are zero.
  ...pick(0),
  ...pick(2),
  OP.OP_ADD,
  OP.OP_0,
  OP.OP_NUMEQUAL,
  OP.OP_0,
  OP.OP_NUMEQUAL,
  OP.OP_VERIFY,
  // r0 = a0*h0 - a1*h1 mod p; compare with 1.
  ...productToAlt(1, 3),
  ...productOnStack(0, 2),
  ...combineAltProduct(OP.OP_SUB),
  ...m89PrimePush,
  OP.OP_ADD,
  ...m89PrimePush,
  OP.OP_MOD,
  OP.OP_1,
  OP.OP_NUMEQUALVERIFY,
  // r1 = a0*h1 + a1*h0 mod p; compare with 0.
  ...productToAlt(1, 2),
  ...productOnStack(0, 3),
  ...combineAltProduct(OP.OP_ADD),
  ...m89PrimePush,
  OP.OP_MOD,
  OP.OP_0,
  OP.OP_NUMEQUAL,
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
]);

export const buildM89EInverseCheckUnlockingBytecode = ({ value, inverseHint, rawValue, rawInverseHint } = {}) => Uint8Array.from([
  ...directPush(rawElement(inverseHint, rawInverseHint, 'inverse hint')),
  ...directPush(rawElement(value, rawValue, 'value')),
]);

export const evaluateM89ScriptFixture = evaluateScriptFixture;

export const encodeM89ScriptTransactionFixture = ({ lockingBytecode, unlockingBytecode }) => {
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
    transactionDigestSha256: sha256Artifact(transactionWire),
    sourceOutputsDigestSha256: sha256Artifact(sourceOutputsWire),
  });
};

export const materializeM89EMacCase = (entry) => Object.freeze({
  ...entry,
  lockingBytecode: buildM89EMacLockingBytecode(),
  unlockingBytecode: buildM89EMacUnlockingBytecode(entry),
});

export const materializeM89ESquareMacCase = (entry) => Object.freeze({
  ...entry,
  lockingBytecode: buildM89ESquareMacLockingBytecode(),
  unlockingBytecode: buildM89ESquareMacUnlockingBytecode(entry),
});

export const materializeM89EInverseCheckCase = (entry) => Object.freeze({
  ...entry,
  lockingBytecode: buildM89EInverseCheckLockingBytecode(),
  unlockingBytecode: buildM89EInverseCheckUnlockingBytecode(entry),
});
