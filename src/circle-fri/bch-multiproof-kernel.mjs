/**
 * BCH-2026 P2SH32 kernel for the canonical two-leaf M31 Merkle multiproof.
 *
 * The witness carries only root, two ordered indices, two fixed-width M31
 * encodings, and the frontier emitted by openM31MerkleMulti. The redeem script
 * derives every frontier position from the two indices; it accepts neither
 * flags nor sibling positions.
 */

import {
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

import {
  encodeM31,
  decodeFixedM31Top,
  evaluateScriptFixture,
} from '../../research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.mjs';

import { M31_MODULUS } from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  buildM31MerkleTree,
  openM31MerkleMulti,
  M31_MERKLE_LEAF_DOMAIN,
  M31_MERKLE_NODE_DOMAIN,
} from './commitment.mjs';

import { equalBytes } from './bytes.mjs';

const OP = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_IF: 0x63,
  OP_BEGIN: 0x65,
  OP_UNTIL: 0x66,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_OVER: 0x78,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_SWAP: 0x7c,
  OP_CAT: 0x7e,
  OP_SPLIT: 0x7f,
  OP_SIZE: 0x82,
  OP_EQUAL: 0x87,
  OP_1ADD: 0x8b,
  OP_DIV: 0x96,
  OP_MOD: 0x97,
  OP_BOOLAND: 0x9a,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_NUMEQUAL: 0x9c,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_HASH256: 0xaa,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
});

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const concat = (...parts) => {
  const length = parts.reduce((sum, part) => {
    require(part instanceof Uint8Array, 'script parts must be Uint8Array values');
    return sum + part.length;
  }, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const encodeMinimalDataPush = (value) => {
  require(value instanceof Uint8Array, 'push value must be a Uint8Array');
  if (value.length === 0) return Uint8Array.of(OP.OP_0);
  if (value.length <= 75) return concat(Uint8Array.of(value.length), value);
  if (value.length <= 0xff) return concat(Uint8Array.of(0x4c, value.length), value);
  if (value.length <= 0xffff) return concat(Uint8Array.of(0x4d, value.length & 0xff, value.length >>> 8), value);
  throw new TypeError('kernel push exceeds OP_PUSHDATA2 capacity');
};

const encodeScriptNumber = (value) => {
  require(typeof value === 'bigint' && value >= 0n, 'Script number must be a nonnegative BigInt');
  if (value === 0n) return new Uint8Array();
  const bytes = [];
  let remaining = value;
  while (remaining > 0n) {
    bytes.push(Number(remaining & 0xffn));
    remaining >>= 8n;
  }
  if ((bytes.at(-1) & 0x80) !== 0) bytes.push(0);
  return Uint8Array.from(bytes);
};

const pushNumber = (value) => {
  const number = typeof value === 'bigint' ? value : BigInt(value);
  if (number === 0n) return Uint8Array.of(OP.OP_0);
  if (number >= 1n && number <= 16n) return Uint8Array.of(0x50 + Number(number));
  return encodeMinimalDataPush(encodeScriptNumber(number));
};

const isPowerOfTwo = (value) => Number.isSafeInteger(value) && value > 0 && (value & (value - 1)) === 0;

const assertM31 = (value, name) => {
  require(typeof value === 'bigint' && value >= 0n && value < M31_MODULUS, `${name} must be a canonical M31 element`);
  return value;
};

const assertIndexPair = (indices, length) => {
  require(Array.isArray(indices) && indices.length === 2, 'kernel requires exactly two Merkle indices');
  for (let ordinal = 0; ordinal < 2; ordinal += 1) {
    require(Number.isSafeInteger(indices[ordinal]) && indices[ordinal] >= 0 && indices[ordinal] < length, `indices[${ordinal}] is out of range`);
  }
  require(indices[0] < indices[1], 'Merkle indices must be strictly increasing and unique');
  return indices;
};

const assertHash = (value, name) => {
  require(value instanceof Uint8Array && value.length === 32, `${name} must be exactly 32 bytes`);
  return value;
};

const hashLeaf = () => [
  OP.OP_DUP,
  ...decodeFixedM31Top(),
  OP.OP_DROP,
  ...encodeMinimalDataPush(M31_MERKLE_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
];

const hashNode = () => [
  // Both child hashes are runtime values and must be exactly 32 bytes.
  OP.OP_1,
  OP.OP_PICK,
  OP.OP_SIZE,
  ...pushNumber(32),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_DROP,
  OP.OP_SIZE,
  ...pushNumber(32),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_CAT,
  ...encodeMinimalDataPush(M31_MERKLE_NODE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
];

/** Input: current hash, next 32-byte canonical frontier hash, current index. */
const hashFrontierStep = () => [
  OP.OP_DUP, OP.OP_2, OP.OP_MOD,
  OP.OP_IF,
  // Odd current index: sibling is left, current hash is right.
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  ...hashNode(),
  OP.OP_FROMALTSTACK, OP.OP_2, OP.OP_DIV,
  OP.OP_ELSE,
  // Even current index: current hash is left, sibling is right.
  OP.OP_TOALTSTACK,
  ...hashNode(),
  OP.OP_FROMALTSTACK, OP.OP_2, OP.OP_DIV,
  OP.OP_ENDIF,
];

/** Input: packed frontier, current hash, current index. Output: parent hash, parent index, remaining frontier. */
const popFrontierAndHashStep = () => [
  ...pushNumber(2), OP.OP_ROLL,
  ...pushNumber(32), OP.OP_SPLIT,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP,
  ...hashFrontierStep(),
  OP.OP_FROMALTSTACK,
];

/** Input: two duplicate indices. Output: one boolean proving an ordered sibling pair. */
const orderedSiblingPredicate = () => [
  OP.OP_OVER,
  OP.OP_2, OP.OP_MOD, OP.OP_0, OP.OP_NUMEQUAL,
  OP.OP_TOALTSTACK,
  OP.OP_SWAP, OP.OP_1ADD, OP.OP_NUMEQUAL,
  OP.OP_FROMALTSTACK, OP.OP_BOOLAND,
];

/** Duplicate the current indices from root, hash0, index0, hash1, index1, frontier. */
const currentIndicesAreSiblings = () => [
  ...pushNumber(3), OP.OP_PICK,
  ...pushNumber(2), OP.OP_PICK,
  ...orderedSiblingPredicate(),
];

/** Advance both independent paths by one level, preserving the canonical state layout. */
const stepBothPaths = () => [
  // The canonical frontier orders missing siblings by increasing known-node
  // index, so advance index0 before index1.
  ...pushNumber(4), OP.OP_ROLL,
  ...pushNumber(4), OP.OP_ROLL,
  ...popFrontierAndHashStep(),
  ...pushNumber(4), OP.OP_ROLL,
  ...pushNumber(4), OP.OP_ROLL,
  ...popFrontierAndHashStep(),
];

/** Compile one fixed tree length; no proof-specific index enters the redeem. */
export const buildBchM31MultiproofRedeemBytecode = (fixture) => {
  require(fixture?.kind === 'bch-m31-canonical-two-leaf-multiproof-v1', 'multiproof fixture is required');
  require(isPowerOfTwo(fixture.length), 'Merkle length must be a positive power of two');
  const script = [
    // Runtime indices must be canonical nonnegative ScriptNums in range and
    // strictly increasing. No concrete index values enter this redeem.
    ...pushNumber(4), OP.OP_PICK, OP.OP_0, OP.OP_GREATERTHANOREQUAL, OP.OP_VERIFY,
    ...pushNumber(3), OP.OP_PICK, OP.OP_0, OP.OP_GREATERTHANOREQUAL, OP.OP_VERIFY,
    ...pushNumber(4), OP.OP_PICK, ...pushNumber(fixture.length), OP.OP_LESSTHAN, OP.OP_VERIFY,
    ...pushNumber(3), OP.OP_PICK, ...pushNumber(fixture.length), OP.OP_LESSTHAN, OP.OP_VERIFY,
    ...pushNumber(4), OP.OP_PICK, ...pushNumber(4), OP.OP_PICK, OP.OP_LESSTHAN, OP.OP_VERIFY,

    // Hash both values, then normalize to:
    // root, hash0, index0, hash1, index1, packedFrontier.
    ...pushNumber(2), OP.OP_ROLL, ...hashLeaf(),
    ...pushNumber(2), OP.OP_ROLL, ...hashLeaf(),
    ...pushNumber(2), OP.OP_ROLL, OP.OP_TOALTSTACK,
    ...pushNumber(2), OP.OP_ROLL, OP.OP_TOALTSTACK,
    OP.OP_TOALTSTACK,
    OP.OP_1, OP.OP_ROLL, OP.OP_TOALTSTACK,
    OP.OP_TOALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,

    // Track the current layer width independently of witness length. This
    // makes the fixed tree length enforce the exact frontier item count.
    ...pushNumber(fixture.length), OP.OP_TOALTSTACK,

    // Consume two frontier hashes per level until the paths are siblings.
    ...currentIndicesAreSiblings(),
    OP.OP_IF,
    OP.OP_ELSE,
    OP.OP_BEGIN,
    ...stepBothPaths(),
    OP.OP_FROMALTSTACK, OP.OP_2, OP.OP_DIV, OP.OP_TOALTSTACK,
    ...currentIndicesAreSiblings(),
    OP.OP_UNTIL,
    OP.OP_ENDIF,

    // Merge the ordered sibling pair without consuming a frontier item.
    ...pushNumber(4), OP.OP_ROLL,
    ...pushNumber(3), OP.OP_ROLL,
    ...hashNode(),
    ...pushNumber(3), OP.OP_ROLL,
    OP.OP_2, OP.OP_DIV,
    ...pushNumber(3), OP.OP_ROLL, OP.OP_DROP,
    ...pushNumber(2), OP.OP_ROLL,

    // The sibling merge consumes one more tree level.
    OP.OP_FROMALTSTACK, OP.OP_2, OP.OP_DIV, OP.OP_TOALTSTACK,

    // Consume exactly one frontier hash per remaining committed tree level.
    // Never use caller-supplied frontier length as the loop bound.
    OP.OP_FROMALTSTACK, OP.OP_DUP, OP.OP_TOALTSTACK,
    OP.OP_1, OP.OP_NUMEQUAL,
    OP.OP_IF,
    OP.OP_ELSE,
    OP.OP_BEGIN,
    ...pushNumber(2), OP.OP_ROLL,
    ...pushNumber(2), OP.OP_ROLL,
    ...popFrontierAndHashStep(),
    OP.OP_FROMALTSTACK, OP.OP_2, OP.OP_DIV,
    OP.OP_DUP, OP.OP_TOALTSTACK,
    OP.OP_1, OP.OP_NUMEQUAL,
    OP.OP_UNTIL,
    OP.OP_ENDIF,
    OP.OP_FROMALTSTACK, OP.OP_1, OP.OP_NUMEQUALVERIFY,

    OP.OP_SIZE, OP.OP_0, OP.OP_NUMEQUALVERIFY, OP.OP_DROP,
    OP.OP_0, OP.OP_NUMEQUALVERIFY,
    OP.OP_EQUAL,
  ];
  require(script.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 0xff), 'compiled redeem contains an invalid byte');
  return Uint8Array.from(script);
};

export const buildBchM31MultiproofOperandUnlockingBytecode = (fixture) => {
  require(fixture?.kind === 'bch-m31-canonical-two-leaf-multiproof-v1', 'multiproof fixture is required');
  require(isPowerOfTwo(fixture.length), 'Merkle length must be a positive power of two');
  assertIndexPair(fixture.indices, fixture.length);
  require(Array.isArray(fixture.frontier), 'Merkle multiproof frontier must be an array');
  const rawValues = fixture.rawValues ?? fixture.values.map(encodeM31);
  const rawIndices = fixture.rawIndices ?? fixture.indices.map((index) => encodeScriptNumber(BigInt(index)));
  require(Array.isArray(rawValues) && rawValues.length === 2, 'multiproof needs two raw M31 values');
  require(Array.isArray(rawIndices) && rawIndices.length === 2, 'multiproof needs two raw indices');
  return concat(
    encodeMinimalDataPush(assertHash(fixture.root, 'Merkle root')),
    ...(fixture.rawIndices === undefined
      ? fixture.indices.map(pushNumber)
      : rawIndices.map((index, ordinal) => encodeMinimalDataPush((require(index instanceof Uint8Array, `rawIndices[${ordinal}] must be bytes`), index)))),
    ...rawValues.map((value, ordinal) => encodeMinimalDataPush((require(value instanceof Uint8Array, `rawValues[${ordinal}] must be bytes`), value))),
    encodeMinimalDataPush(concat(...fixture.frontier.map((hash, ordinal) => {
      require(hash instanceof Uint8Array, `frontier[${ordinal}] must be bytes`);
      return hash;
    }))),
  );
};

export const createBchM31MultiproofFixture = ({ values, indices }) => {
  require(Array.isArray(values) && isPowerOfTwo(values.length), 'Merkle values must have positive power-of-two length');
  values.forEach((value, ordinal) => assertM31(value, `values[${ordinal}]`));
  assertIndexPair(indices, values.length);
  const tree = buildM31MerkleTree(values);
  const opening = openM31MerkleMulti(tree, indices);
  return Object.freeze({
    kind: 'bch-m31-canonical-two-leaf-multiproof-v1',
    canonicalBottomUpFrontier: true,
    length: tree.length,
    indices: Object.freeze(opening.indices.slice()),
    values: Object.freeze(opening.indices.map((index) => values[index])),
    root: new Uint8Array(tree.root),
    frontier: Object.freeze(opening.siblings.map((hash) => new Uint8Array(hash))),
  });
};

export const materializeBchM31MultiproofP2sh32 = (fixture) => {
  const redeemBytecode = buildBchM31MultiproofRedeemBytecode(fixture);
  const operandUnlockingBytecode = buildBchM31MultiproofOperandUnlockingBytecode(fixture);
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));
  return Object.freeze({
    ...fixture,
    redeemBytecode,
    operandUnlockingBytecode,
    lockingBytecode,
    unlockingBytecode: concat(operandUnlockingBytecode, encodeMinimalDataPush(redeemBytecode)),
  });
};

export const evaluateBchM31MultiproofP2sh32 = (fixture) => evaluateScriptFixture(materializeBchM31MultiproofP2sh32(fixture));

export const isBchM31MultiproofRoot = (fixture, root) => root instanceof Uint8Array
  && root.length === 32
  && equalBytes(fixture.root, root);
