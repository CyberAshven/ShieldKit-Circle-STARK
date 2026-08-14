/**
 * Bounded M31 base-operation relation kernels.
 *
 * These compose the canonical raw fixed4 decoder from m31-kernel.mjs. They do
 * not normalize raw inputs, choose a proof-system component, or form a full
 * base-field gate set.
 */

import {
  M31_PRIME,
  M31_PRIME_SCRIPT_PUSH,
  M31_SCRIPT_OPCODES,
  decodeFixedM31Top,
  encodeDirectPush,
  encodeM31,
  encodeScriptTransactionFixture,
  evaluateScriptFixture,
} from './m31-kernel.mjs';

const OP = Object.freeze({
  ...M31_SCRIPT_OPCODES,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
});

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const raw = (value, supplied) => {
  const bytes = supplied ?? encodeM31(value);
  require(bytes instanceof Uint8Array, 'base-op raw input must be Uint8Array');
  return bytes;
};

const unlocking = (...rawValuesBottomToTop) => Uint8Array.from(
  rawValuesBottomToTop.flatMap((value) => encodeDirectPush(value)),
);

// Starting unlocking order: resultRaw, rightRaw, leftRaw. Decoding yields
// left, right, result, after which the result is held on altstack.
const binaryRelationPrefix = () => [
  ...decodeFixedM31Top(),
  OP.OP_SWAP,
  ...decodeFixedM31Top(),
  OP.OP_ROT,
  ...decodeFixedM31Top(),
  OP.OP_TOALTSTACK,
];

const binaryRelationSuffix = (operation) => [
  operation,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_FROMALTSTACK,
  OP.OP_NUMEQUAL,
];

/** Relation: sum = left + right mod p. */
export const buildM31AddLockingBytecode = () => Uint8Array.from([
  ...binaryRelationPrefix(),
  ...binaryRelationSuffix(OP.OP_ADD),
]);

export const buildM31AddUnlockingBytecode = ({ left, right, sum, rawLeft, rawRight, rawSum } = {}) => unlocking(
  raw(sum, rawSum), raw(right, rawRight), raw(left, rawLeft),
);

/**
 * Relation: difference = left - right mod p. Adding p first prevents OP_MOD
 * from receiving a negative numerator for all canonical M31 operands.
 */
export const buildM31SubLockingBytecode = () => Uint8Array.from([
  ...binaryRelationPrefix(),
  OP.OP_SUB,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_ADD,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_FROMALTSTACK,
  OP.OP_NUMEQUAL,
]);

export const buildM31SubUnlockingBytecode = ({ left, right, difference, rawLeft, rawRight, rawDifference } = {}) => unlocking(
  raw(difference, rawDifference), raw(right, rawRight), raw(left, rawLeft),
);

// Starting unlocking order: resultRaw, valueRaw. Decoding yields value, result.
const unaryRelationPrefix = () => [
  ...decodeFixedM31Top(),
  OP.OP_SWAP,
  ...decodeFixedM31Top(),
  OP.OP_TOALTSTACK,
];

/** Relation: negation = -value mod p, computed as (p - value) mod p. */
export const buildM31NegLockingBytecode = () => Uint8Array.from([
  ...unaryRelationPrefix(),
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_SWAP,
  OP.OP_SUB,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_FROMALTSTACK,
  OP.OP_NUMEQUAL,
]);

export const buildM31NegUnlockingBytecode = ({ value, negation, rawValue, rawNegation } = {}) => unlocking(
  raw(negation, rawNegation), raw(value, rawValue),
);

/** Relation: square = value^2 mod p. */
export const buildM31SquareLockingBytecode = () => Uint8Array.from([
  ...unaryRelationPrefix(),
  OP.OP_DUP,
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_FROMALTSTACK,
  OP.OP_NUMEQUAL,
]);

export const buildM31SquareUnlockingBytecode = ({ value, square, rawValue, rawSquare } = {}) => unlocking(
  raw(square, rawSquare), raw(value, rawValue),
);

/**
 * Relation: value * inverseHint mod p = 1. The hint is supplied by the prover;
 * this checks it rather than attempting division/inversion in Script.
 */
export const buildM31InverseHintLockingBytecode = () => Uint8Array.from([
  ...decodeFixedM31Top(),
  OP.OP_SWAP,
  ...decodeFixedM31Top(),
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_1,
  OP.OP_NUMEQUAL,
]);

export const buildM31InverseHintUnlockingBytecode = ({ value, inverseHint, rawValue, rawInverseHint } = {}) => unlocking(
  raw(inverseHint, rawInverseHint), raw(value, rawValue),
);

export const BASE_OP_BUILDERS = Object.freeze({
  add: {
    locking: buildM31AddLockingBytecode,
    unlocking: buildM31AddUnlockingBytecode,
  },
  sub: {
    locking: buildM31SubLockingBytecode,
    unlocking: buildM31SubUnlockingBytecode,
  },
  neg: {
    locking: buildM31NegLockingBytecode,
    unlocking: buildM31NegUnlockingBytecode,
  },
  square: {
    locking: buildM31SquareLockingBytecode,
    unlocking: buildM31SquareUnlockingBytecode,
  },
  inverseHint: {
    locking: buildM31InverseHintLockingBytecode,
    unlocking: buildM31InverseHintUnlockingBytecode,
  },
});

export const materializeBaseOpCase = (entry) => {
  const builder = BASE_OP_BUILDERS[entry.operation];
  require(builder !== undefined, `unknown base operation: ${entry.operation}`);
  const lockingBytecode = builder.locking();
  const unlockingBytecode = builder.unlocking(entry);
  return Object.freeze({ ...entry, lockingBytecode, unlockingBytecode });
};

export const evaluateBaseOpCase = (entry) => evaluateScriptFixture(materializeBaseOpCase(entry));
export const encodeBaseOpTransactionFixture = (entry) => encodeScriptTransactionFixture(materializeBaseOpCase(entry));

const P_MINUS_ONE = M31_PRIME - 1n;
const P_MINUS_TWO = M31_PRIME - 2n;
const INV_TWO = (M31_PRIME + 1n) / 2n;

export const M31_BASE_OP_CASES = Object.freeze([
  { id: 'add-zero', operation: 'add', left: 0n, right: 0n, sum: 0n, accepted: true },
  { id: 'add-overflow-boundary', operation: 'add', left: P_MINUS_ONE, right: 1n, sum: 0n, accepted: true },
  { id: 'sub-zero-minus-one', operation: 'sub', left: 0n, right: 1n, difference: P_MINUS_ONE, accepted: true },
  { id: 'sub-one-minus-p-minus-one', operation: 'sub', left: 1n, right: P_MINUS_ONE, difference: 2n, accepted: true },
  { id: 'sub-self', operation: 'sub', left: 123_456n, right: 123_456n, difference: 0n, accepted: true },
  { id: 'neg-zero', operation: 'neg', value: 0n, negation: 0n, accepted: true },
  { id: 'neg-p-minus-one', operation: 'neg', value: P_MINUS_ONE, negation: 1n, accepted: true },
  { id: 'square-p-minus-one', operation: 'square', value: P_MINUS_ONE, square: 1n, accepted: true },
  { id: 'square-p-minus-two', operation: 'square', value: P_MINUS_TWO, square: 4n, accepted: true },
  { id: 'inverse-one', operation: 'inverseHint', value: 1n, inverseHint: 1n, accepted: true },
  { id: 'inverse-p-minus-one', operation: 'inverseHint', value: P_MINUS_ONE, inverseHint: P_MINUS_ONE, accepted: true },
  { id: 'inverse-two', operation: 'inverseHint', value: 2n, inverseHint: INV_TWO, accepted: true },
  { id: 'inverse-x-zero', operation: 'inverseHint', value: 0n, inverseHint: 1n, accepted: false },
  { id: 'inverse-hint-zero', operation: 'inverseHint', value: 2n, inverseHint: 0n, accepted: false },
  // ±1 are valid only for the matching values 1 and p-1 above, not for x = 2.
  { id: 'inverse-hint-plus-one-wrong', operation: 'inverseHint', value: 2n, inverseHint: 1n, accepted: false },
  { id: 'inverse-hint-minus-one-wrong', operation: 'inverseHint', value: 2n, inverseHint: P_MINUS_ONE, accepted: false },
  { id: 'inverse-hint-wrong', operation: 'inverseHint', value: 2n, inverseHint: 3n, accepted: false },
  { id: 'inverse-malformed-value-p-plus-one', operation: 'inverseHint', value: 1n, inverseHint: 1n, rawValue: Uint8Array.of(0x00, 0x00, 0x00, 0x80), accepted: false },
  { id: 'inverse-malformed-hint-short', operation: 'inverseHint', value: 1n, inverseHint: 1n, rawInverseHint: Uint8Array.of(0x01, 0x00, 0x00), accepted: false },
]);
