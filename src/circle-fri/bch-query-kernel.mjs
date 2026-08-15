import {
  M31_PRIME_SCRIPT_PUSH,
  decodeFixedM31Top,
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

import {
  M31_MERKLE_LEAF_DOMAIN,
  M31_MERKLE_NODE_DOMAIN,
} from './commitment.mjs';

import { buildStandardCoset } from './circle.mjs';

import {
  buildJFoldTopology,
  buildPiFoldTopology,
} from './fold.mjs';

import {
  assertCircleFriParameters,
  verifyCircleFriQueries,
} from './query-proof.mjs';

const OP = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_2DUP: 0x6e,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_SWAP: 0x7c,
  OP_CAT: 0x7e,
  OP_SIZE: 0x82,
  OP_EQUALVERIFY: 0x88,
  OP_DEFINE: 0x89,
  OP_INVOKE: 0x8a,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_MOD: 0x97,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_HASH256: 0xaa,
});

const FUNCTION = Object.freeze({
  HASH_LEAF: 1,
  HASH_NODE_LEFT: 2,
  HASH_NODE_RIGHT: 3,
  DECODE_M31: 4,
  FOLD_M31: 5,
});

const HALF = (M31_MODULUS + 1n) / 2n;

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const concat = (...parts) => {
  let length = 0;
  for (const part of parts) {
    require(part instanceof Uint8Array, 'script parts must be Uint8Array values');
    length += part.length;
  }
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
  if (value.length <= 0xffff) {
    return concat(Uint8Array.of(0x4d, value.length & 0xff, value.length >>> 8), value);
  }
  throw new TypeError('push value exceeds OP_PUSHDATA2 capacity');
};

const encodeScriptNumber = (value) => {
  require(typeof value === 'bigint' && value >= 0n, 'Script number constant must be a nonnegative BigInt');
  if (value === 0n) return new Uint8Array();
  const result = [];
  let remaining = value;
  while (remaining > 0n) {
    result.push(Number(remaining & 0xffn));
    remaining >>= 8n;
  }
  if ((result.at(-1) & 0x80) !== 0) result.push(0);
  return Uint8Array.from(result);
};

const pushNumber = (value) => {
  const n = typeof value === 'bigint' ? value : BigInt(value);
  if (n === 0n) return Uint8Array.of(OP.OP_0);
  if (n >= 1n && n <= 16n) return Uint8Array.of(0x50 + Number(n));
  return encodeMinimalDataPush(encodeScriptNumber(n));
};

const pushFunctionId = (identifier) => {
  require(Number.isSafeInteger(identifier) && identifier >= 1 && identifier <= 16, 'function identifier is out of range');
  return Uint8Array.of(0x50 + identifier);
};

const defineFunction = (identifier, bytecode) => concat(
  encodeMinimalDataPush(bytecode),
  pushFunctionId(identifier),
  Uint8Array.of(OP.OP_DEFINE),
);

const invokeFunction = (identifier) => [
  ...pushFunctionId(identifier),
  OP.OP_INVOKE,
];

const HASH_LEAF_FUNCTION = Uint8Array.from([
  OP.OP_DUP,
  OP.OP_TOALTSTACK,
  ...encodeMinimalDataPush(M31_MERKLE_LEAF_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
]);

const buildHashNodeFunction = (currentIsLeft) => Uint8Array.from([
  OP.OP_1,
  OP.OP_PICK,
  OP.OP_SIZE,
  ...pushNumber(32),
  OP.OP_NUMEQUALVERIFY,
  OP.OP_DROP,
  ...(currentIsLeft ? [OP.OP_SWAP] : []),
  OP.OP_CAT,
  ...encodeMinimalDataPush(M31_MERKLE_NODE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_HASH256,
]);

const HASH_NODE_LEFT_FUNCTION = buildHashNodeFunction(true);
const HASH_NODE_RIGHT_FUNCTION = buildHashNodeFunction(false);
const DECODE_M31_FUNCTION = Uint8Array.from(decodeFixedM31Top());
const FOLD_M31_FUNCTION = Uint8Array.from([
  // Input stack: left, right, inverse, coordinate, beta.
  OP.OP_TOALTSTACK, // beta
  OP.OP_1,
  OP.OP_PICK, // inverse
  OP.OP_1,
  OP.OP_PICK, // coordinate
  OP.OP_2,
  OP.OP_MUL,
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_1,
  OP.OP_NUMEQUALVERIFY,
  OP.OP_DROP, // coordinate

  // Stack: left, right, inverse. Alt: beta.
  OP.OP_TOALTSTACK,
  OP.OP_2DUP,
  OP.OP_ADD,
  ...pushNumber(HALF),
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_TOALTSTACK, // alt: beta, inverse, even
  OP.OP_SUB,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_ADD,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  OP.OP_2,
  OP.OP_ROLL,
  OP.OP_MUL, // odd
  OP.OP_FROMALTSTACK, // beta
  OP.OP_MUL,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
  OP.OP_ADD,
  ...M31_PRIME_SCRIPT_PUSH,
  OP.OP_MOD,
]);

export const BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES = (
  HASH_LEAF_FUNCTION.length
  + HASH_NODE_LEFT_FUNCTION.length
  + HASH_NODE_RIGHT_FUNCTION.length
  + DECODE_M31_FUNCTION.length
  + FOLD_M31_FUNCTION.length
);

const QUERY_FUNCTION_DEFINITIONS = concat(
  defineFunction(FUNCTION.HASH_LEAF, HASH_LEAF_FUNCTION),
  defineFunction(FUNCTION.HASH_NODE_LEFT, HASH_NODE_LEFT_FUNCTION),
  defineFunction(FUNCTION.HASH_NODE_RIGHT, HASH_NODE_RIGHT_FUNCTION),
  defineFunction(FUNCTION.DECODE_M31, DECODE_M31_FUNCTION),
  defineFunction(FUNCTION.FOLD_M31, FOLD_M31_FUNCTION),
);

const assertHash = (value, name) => {
  require(value instanceof Uint8Array && value.length === 32, `${name} must be exactly 32 bytes`);
  return value;
};

const buildMerklePartialVerification = ({ leafIndex, siblings }) => {
  require(Array.isArray(siblings), 'siblings must be an array');
  const script = [...invokeFunction(FUNCTION.HASH_LEAF)];
  let index = leafIndex;
  for (let level = 0; level < siblings.length; level += 1) {
    assertHash(siblings[level], `siblings[${level}]`);
    script.push(...invokeFunction(
      (index & 1) === 0 ? FUNCTION.HASH_NODE_LEFT : FUNCTION.HASH_NODE_RIGHT,
    ));
    index = Math.floor(index / 2);
  }
  return Object.freeze({ script, branchIndex: index });
};

const buildMerklePairVerification = ({ leftIndex, rightIndex, leftSiblings, rightSiblings, root }) => {
  assertHash(root, 'root');
  require(leftSiblings.length === rightSiblings.length && leftSiblings.length >= 1, 'paired Merkle paths must have equal nonzero length');
  const left = buildMerklePartialVerification({
    leafIndex: leftIndex,
    siblings: leftSiblings.slice(0, -1),
  });
  const right = buildMerklePartialVerification({
    leafIndex: rightIndex,
    siblings: rightSiblings.slice(0, -1),
  });
  require((left.branchIndex ^ 1) === right.branchIndex, 'fold partners must meet as sibling branches at the Merkle root');
  require(Math.floor(left.branchIndex / 2) === Math.floor(right.branchIndex / 2), 'fold partner branches do not share a Merkle parent');
  return [
    ...left.script,
    OP.OP_TOALTSTACK, // alt: leftRaw, leftBranchHash
    ...right.script, // alt: leftRaw, leftBranchHash, rightRaw; main: rightBranchHash
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    OP.OP_2,
    OP.OP_ROLL, // rightRaw, leftBranchHash, rightBranchHash
    ...((left.branchIndex & 1) === 0 ? [OP.OP_SWAP] : []),
    ...invokeFunction(FUNCTION.HASH_NODE_LEFT),
    ...encodeMinimalDataPush(root),
    OP.OP_EQUALVERIFY,
    OP.OP_TOALTSTACK, // alt: leftRaw, rightRaw
  ];
};

const buildFoldVerification = ({ coordinate, beta, continuitySide, finalExpected, isLast }) => {
  const script = [
    // Recover right then left raw values, leaving any prior folded value on altstack.
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    ...invokeFunction(FUNCTION.DECODE_M31), // left
    OP.OP_SWAP,
    ...invokeFunction(FUNCTION.DECODE_M31), // right
    OP.OP_2,
    OP.OP_ROLL,
    ...invokeFunction(FUNCTION.DECODE_M31), // inverse(2*coordinate)
  ];

  if (continuitySide !== null) {
    script.push(
      continuitySide === 'left' ? OP.OP_2 : OP.OP_1,
      OP.OP_PICK,
      OP.OP_FROMALTSTACK,
      OP.OP_NUMEQUALVERIFY,
    );
  }

  script.push(
    ...pushNumber(coordinate),
    ...pushNumber(beta),
    ...invokeFunction(FUNCTION.FOLD_M31),
  );
  if (isLast) {
    script.push(...pushNumber(finalExpected), OP.OP_NUMEQUAL);
  } else {
    script.push(OP.OP_TOALTSTACK);
  }
  return script;
};

const buildTopologies = (parameters) => {
  const result = [];
  let domain = buildStandardCoset(parameters.logDomain);
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const topology = round === 0 ? buildJFoldTopology(domain) : buildPiFoldTopology(domain);
    result.push(topology);
    domain = topology.domain;
  }
  return result;
};

/**
 * Bind one already Fiat-Shamir-selected query to its Merkle roots, fold
 * challenges, and final constant. This component intentionally excludes the
 * transcript derivation itself; it measures the full authenticated query path.
 */
export const createBchCircleFriQueryFixture = ({
  proof,
  expected,
  protocolContext = new Uint8Array(),
  queryOrdinal = 0,
}) => {
  const verdict = verifyCircleFriQueries({ proof, expected, protocolContext });
  require(verdict.ok, `Circle-FRI proof must verify before BCH lowering: ${verdict.reason ?? 'invalid'}`);
  const parameters = assertCircleFriParameters(expected);
  require(Number.isSafeInteger(queryOrdinal) && queryOrdinal >= 0 && queryOrdinal < parameters.queryCount, 'queryOrdinal is out of range');
  const topologies = buildTopologies(parameters);
  const query = proof.queries[queryOrdinal];
  let currentIndex = verdict.queryIndices[queryOrdinal];
  const rounds = [];
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const topology = topologies[round];
    const pairIndex = topology.pairs.findIndex(({ leftIndex, rightIndex }) => (
      leftIndex === currentIndex || rightIndex === currentIndex
    ));
    require(pairIndex >= 0, `query leaf missing from topology at round ${round}`);
    const pair = topology.pairs[pairIndex];
    const opening = query.layers[round];
    rounds.push(Object.freeze({
      round,
      root: proof.roots[round],
      beta: verdict.betas[round],
      coordinate: pair.coordinate,
      inverseTwoCoordinate: inverse(mul(2n, pair.coordinate)),
      leftIndex: pair.leftIndex,
      rightIndex: pair.rightIndex,
      continuitySide: round === 0 ? null : (currentIndex === pair.leftIndex ? 'left' : 'right'),
      opening,
    }));
    currentIndex = pairIndex;
  }
  return Object.freeze({
    kind: 'circle-fri-authenticated-query-component-v1',
    transcriptDerivationIncluded: false,
    parameters,
    queryOrdinal,
    initialQueryIndex: verdict.queryIndices[queryOrdinal],
    finalIndex: currentIndex,
    finalExpected: proof.finalCodeword[currentIndex],
    rounds,
  });
};

export const buildBchCircleFriQueryRedeemBytecode = (fixture) => {
  require(fixture?.kind === 'circle-fri-authenticated-query-component-v1', 'query fixture is required');
  const script = [...QUERY_FUNCTION_DEFINITIONS];
  for (let round = 0; round < fixture.rounds.length; round += 1) {
    const item = fixture.rounds[round];
    script.push(
      ...buildMerklePairVerification({
        leftIndex: item.leftIndex,
        rightIndex: item.rightIndex,
        leftSiblings: item.opening.leftSiblings,
        rightSiblings: item.opening.rightSiblings,
        root: item.root,
      }),
      ...buildFoldVerification({
        coordinate: item.coordinate,
        beta: item.beta,
        continuitySide: item.continuitySide,
        finalExpected: fixture.finalExpected,
        isLast: round === fixture.rounds.length - 1,
      }),
    );
  }
  return Uint8Array.from(script);
};

export const buildBchCircleFriQueryOperandUnlockingBytecode = (fixture) => {
  require(fixture?.kind === 'circle-fri-authenticated-query-component-v1', 'query fixture is required');
  const operands = [];
  for (let round = fixture.rounds.length - 1; round >= 0; round -= 1) {
    const item = fixture.rounds[round];
    operands.push(
      encodeM31(item.inverseTwoCoordinate),
      ...item.opening.rightSiblings.slice(0, -1).reverse(),
      encodeM31(item.opening.rightValue),
      ...item.opening.leftSiblings.slice(0, -1).reverse(),
      encodeM31(item.opening.leftValue),
    );
  }
  return concat(...operands.map(encodeMinimalDataPush));
};

export const materializeBchCircleFriQueryP2sh32 = (fixture) => {
  const redeemBytecode = buildBchCircleFriQueryRedeemBytecode(fixture);
  const operandUnlockingBytecode = buildBchCircleFriQueryOperandUnlockingBytecode(fixture);
  const unlockingBytecode = concat(operandUnlockingBytecode, encodeMinimalDataPush(redeemBytecode));
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));
  return Object.freeze({
    ...fixture,
    redeemBytecode,
    operandUnlockingBytecode,
    lockingBytecode,
    unlockingBytecode,
  });
};

export const evaluateBchCircleFriQueryP2sh32 = (fixture) => (
  evaluateScriptFixture(materializeBchCircleFriQueryP2sh32(fixture))
);

export const encodeBchCircleFriQueryP2sh32TransactionFixture = (fixture) => (
  encodeScriptTransactionFixture(materializeBchCircleFriQueryP2sh32(fixture))
);
