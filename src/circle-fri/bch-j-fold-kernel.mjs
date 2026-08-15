import {
  M31_PRIME_SCRIPT_PUSH,
  decodeFixedM31Top,
  encodeDirectPush,
  encodeM31,
  encodeScriptTransactionFixture,
  evaluateScriptFixture,
} from '../../research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.mjs';

import {
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

import {
  M31_MODULUS,
  inverse,
  mul,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import { foldPair } from './fold.mjs';

const OP = Object.freeze({
  OP_1: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_4: 0x54,
  OP_5: 0x55,
  OP_6: 0x56,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_MOD: 0x97,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
});

const HALF = (M31_MODULUS + 1n) / 2n;
const HALF_PUSH = Object.freeze(encodeDirectPush(encodeM31(HALF)));

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const raw = (value, supplied) => {
  const bytes = supplied ?? encodeM31(value);
  require(bytes instanceof Uint8Array, 'J-fold raw input must be a Uint8Array');
  return bytes;
};

const pushInputs = (...valuesBottomToTop) => Uint8Array.from(
  valuesBottomToTop.flatMap((value) => encodeDirectPush(value)),
);

const concat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));

const encodeMinimalPush = (value) => {
  require(value instanceof Uint8Array, 'push value must be a Uint8Array');
  if (value.length <= 75) return concat(Uint8Array.of(value.length), value);
  if (value.length <= 0xff) return concat(Uint8Array.of(0x4c, value.length), value);
  if (value.length <= 0xffff) {
    return concat(Uint8Array.of(0x4d, value.length & 0xff, value.length >>> 8), value);
  }
  throw new TypeError('push value exceeds OP_PUSHDATA2 capacity');
};

const decodeSixInputs = () => {
  const script = [];
  for (let index = 0; index < 6; index += 1) {
    script.push(...decodeFixedM31Top(), OP.OP_TOALTSTACK);
  }
  for (let index = 0; index < 6; index += 1) script.push(OP.OP_FROMALTSTACK);
  return script;
};

/**
 * Verify one M31 Circle-FRI J-fold relation:
 *
 * folded = (positive + negative)/2
 *        + beta * (positive - negative)/(2*y) mod p
 *
 * The prover supplies inverseTwoY, and Script checks
 * (2*y)*inverseTwoY = 1 before using it.
 */
export const buildM31JFoldLockingBytecode = () => Uint8Array.from([
  ...decodeSixInputs(),
  // Stack: expected, inverseTwoY, beta, y, negative, positive.
  OP.OP_5,
  OP.OP_ROLL,
  OP.OP_TOALTSTACK, // expected

  // Verify inverseTwoY * (2*y) == 1 while preserving all five inputs.
  OP.OP_4,
  OP.OP_PICK, // inverseTwoY
  OP.OP_3,
  OP.OP_PICK, // y
  OP.OP_2,
  OP.OP_MUL,
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_1,
  OP.OP_NUMEQUALVERIFY,

  // even = (positive + negative) / 2.
  OP.OP_DUP,
  OP.OP_2,
  OP.OP_PICK,
  OP.OP_ADD,
  ...HALF_PUSH,
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,

  // odd = (positive - negative) * inverseTwoY.
  OP.OP_1,
  OP.OP_PICK,
  OP.OP_3,
  OP.OP_PICK,
  OP.OP_SUB,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_ADD,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_6,
  OP.OP_PICK,
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,

  // folded = even + beta*odd.
  OP.OP_5,
  OP.OP_PICK,
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_ADD,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,

  // Remove preserved inputs, then compare against the expected fold.
  OP.OP_TOALTSTACK,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_DROP,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_NUMEQUAL,
]);

export const buildM31JFoldUnlockingBytecode = ({
  positive,
  negative,
  y,
  beta,
  inverseTwoY,
  folded,
  rawPositive,
  rawNegative,
  rawY,
  rawBeta,
  rawInverseTwoY,
  rawFolded,
} = {}) => pushInputs(
  raw(folded, rawFolded),
  raw(inverseTwoY, rawInverseTwoY),
  raw(beta, rawBeta),
  raw(y, rawY),
  raw(negative, rawNegative),
  raw(positive, rawPositive),
);

export const createM31JFoldFixture = ({ positive, negative, y, beta } = {}) => {
  const inverseTwoY = inverse(mul(2n, y));
  const folded = foldPair({ positive, negative, coordinate: y, beta }).value;
  return Object.freeze({ positive, negative, y, beta, inverseTwoY, folded });
};

export const materializeM31JFold = (entry) => Object.freeze({
  ...entry,
  lockingBytecode: buildM31JFoldLockingBytecode(),
  unlockingBytecode: buildM31JFoldUnlockingBytecode(entry),
});

export const evaluateM31JFold = (entry) => evaluateScriptFixture(materializeM31JFold(entry));
export const encodeM31JFoldTransactionFixture = (entry) => encodeScriptTransactionFixture(materializeM31JFold(entry));

/** Materialize the same relation as a standard 35-byte P2SH32 source. */
export const materializeM31JFoldP2sh32 = (entry) => {
  const redeemBytecode = buildM31JFoldLockingBytecode();
  const operandUnlockingBytecode = buildM31JFoldUnlockingBytecode(entry);
  const unlockingBytecode = concat(operandUnlockingBytecode, encodeMinimalPush(redeemBytecode));
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));
  return Object.freeze({
    ...entry,
    redeemBytecode,
    operandUnlockingBytecode,
    lockingBytecode,
    unlockingBytecode,
  });
};

export const evaluateM31JFoldP2sh32 = (entry) => evaluateScriptFixture(materializeM31JFoldP2sh32(entry));
export const encodeM31JFoldP2sh32TransactionFixture = (entry) => encodeScriptTransactionFixture(materializeM31JFoldP2sh32(entry));
