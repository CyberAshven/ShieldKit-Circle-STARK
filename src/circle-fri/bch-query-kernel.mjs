import {
  M31_PRIME_SCRIPT_PUSH,
  decodeFixedM31Top,
  encodeM31,
  encodeScriptTransactionFixture,
  evaluateScriptFixture,
} from '../../research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.mjs';

import {
  binToHex,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  encodeTransactionOutputs,
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
  encodeCircleFriParameters,
  verifyCircleFriQueries,
} from './query-proof.mjs';

import {
  frameBytes,
  sha256,
  u16le,
  u32le,
  utf8,
} from './bytes.mjs';

import {
  CIRCLE_FRI_SQUEEZE_DOMAIN,
  CIRCLE_FRI_TRANSCRIPT_DOMAIN,
  absorbCircleFriTranscriptState,
  initializeCircleFriTranscriptState,
  sampleCircleFriTranscriptState,
} from './transcript.mjs';

import {
  CIRCLE_FRI_TOPOLOGY_LEAF_DOMAIN,
  buildCircleFriTopologyTable,
  decodeCircleFriTopologyRecord,
  openCircleFriTopologyTable,
} from './topology-table.mjs';

const OP = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_IF: 0x63,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_2DROP: 0x6d,
  OP_2DUP: 0x6e,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_2SWAP: 0x72,
  OP_SWAP: 0x7c,
  OP_CAT: 0x7e,
  OP_SPLIT: 0x7f,
  OP_BIN2NUM: 0x81,
  OP_SIZE: 0x82,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_DEFINE: 0x89,
  OP_INVOKE: 0x8a,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_DIV: 0x96,
  OP_MOD: 0x97,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_NUMNOTEQUAL: 0x9e,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_SHA256: 0xa8,
  OP_HASH256: 0xaa,
});

const FUNCTION = Object.freeze({
  HASH_LEAF: 1,
  HASH_NODE_LEFT: 2,
  HASH_NODE_RIGHT: 3,
  DECODE_M31: 4,
  FOLD_M31: 5,
  SAMPLE_TRANSCRIPT: 6,
  HASH_PACKED_NODE_LEFT: 7,
  HASH_PACKED_NODE_RIGHT: 8,
  SAMPLE_M31_TRANSCRIPT: 9,
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

const TWO_TO_32 = 0x1_0000_0000;
const ZERO_BYTE = Uint8Array.of(0);

const framePrefix = (label, payloadLength) => {
  const labelBytes = utf8(label);
  return concat(u16le(labelBytes.length), labelBytes, u32le(payloadLength));
};

const buildTranscriptInitialization = ({ protocolContext, parameters }) => [
  ...encodeMinimalDataPush(concat(
    CIRCLE_FRI_TRANSCRIPT_DOMAIN,
    frameBytes('context', protocolContext),
  )),
  OP.OP_SHA256,
  ...encodeMinimalDataPush(frameBytes('fri-parameters', encodeCircleFriParameters(parameters))),
  OP.OP_CAT,
  OP.OP_SHA256,
];

/** Input: transcript state, runtime payload. Output: updated transcript state. */
const buildTranscriptAbsorbRuntime = (label, payloadLength) => [
  OP.OP_SIZE,
  ...pushNumber(payloadLength),
  OP.OP_NUMEQUALVERIFY,
  ...encodeMinimalDataPush(framePrefix(label, payloadLength)),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_CAT,
  OP.OP_SHA256,
];

const buildTranscriptCandidate = () => [
  OP.OP_DUP,
  ...pushNumber(4),
  OP.OP_SPLIT,
  OP.OP_DROP,
  ...encodeMinimalDataPush(ZERO_BYTE),
  OP.OP_CAT,
  OP.OP_BIN2NUM,
];

/**
 * Input: transcript state. Output: updated transcript state, sampled integer.
 * The accepted attempt is derived off-chain only to unroll the deterministic
 * rejection path; every rejected/accepted predicate is re-executed in Script.
 */
const buildTranscriptChallenge = ({ label, upperBound, acceptedAttempt }) => {
  require(Number.isSafeInteger(upperBound) && upperBound >= 1 && upperBound <= 0xffff_ffff, 'challenge upperBound is out of range');
  require(Number.isSafeInteger(acceptedAttempt) && acceptedAttempt >= 0, 'accepted challenge attempt is out of range');
  const acceptanceBound = Math.floor(TWO_TO_32 / upperBound) * upperBound;
  const labelFrame = frameBytes('accepted-challenge-label', utf8(label));
  const script = [];

  for (let attempt = 0; attempt <= acceptedAttempt; attempt += 1) {
    const drawSuffix = concat(
      frameBytes('label', utf8(label)),
      frameBytes('attempt', u32le(attempt)),
    );
    if (attempt === acceptedAttempt) {
      script.push(
        ...encodeMinimalDataPush(drawSuffix),
        ...encodeMinimalDataPush(labelFrame),
        ...encodeMinimalDataPush(frameBytes('accepted-challenge-attempt', u32le(attempt))),
        ...(upperBound === Number(M31_MODULUS)
          ? invokeFunction(FUNCTION.SAMPLE_M31_TRANSCRIPT)
          : [
              OP.OP_TOALTSTACK,
              OP.OP_TOALTSTACK,
              ...pushNumber(upperBound),
              ...pushNumber(acceptanceBound),
              OP.OP_FROMALTSTACK,
              OP.OP_FROMALTSTACK,
              ...invokeFunction(FUNCTION.SAMPLE_TRANSCRIPT),
            ]),
      );
      continue;
    }
    script.push(
      OP.OP_DUP,
      ...encodeMinimalDataPush(CIRCLE_FRI_SQUEEZE_DOMAIN),
      OP.OP_SWAP,
      OP.OP_CAT,
      ...encodeMinimalDataPush(drawSuffix),
      OP.OP_CAT,
      OP.OP_SHA256,
      ...buildTranscriptCandidate(),
      ...pushNumber(acceptanceBound),
      OP.OP_GREATERTHANOREQUAL,
      OP.OP_VERIFY,
      OP.OP_DROP,
    );
  }
  return script;
};

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
const buildPackedHashNodeFunction = (nodeFunction) => Uint8Array.from([
  // Input: packed siblings (next sibling is the final 32 bytes), current hash.
  OP.OP_SWAP,
  OP.OP_SIZE,
  ...pushNumber(32),
  OP.OP_SUB,
  OP.OP_SPLIT,
  OP.OP_2,
  OP.OP_ROLL,
  ...invokeFunction(nodeFunction),
]);
const HASH_PACKED_NODE_LEFT_FUNCTION = buildPackedHashNodeFunction(FUNCTION.HASH_NODE_LEFT);
const HASH_PACKED_NODE_RIGHT_FUNCTION = buildPackedHashNodeFunction(FUNCTION.HASH_NODE_RIGHT);
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

const SAMPLE_TRANSCRIPT_FUNCTION = Uint8Array.from([
  // Input: state, drawSuffix, upperBound, acceptanceBound, labelFrame, attemptFrame.
  OP.OP_TOALTSTACK, // attemptFrame
  OP.OP_TOALTSTACK, // labelFrame
  OP.OP_SWAP,
  OP.OP_TOALTSTACK, // upperBound
  OP.OP_TOALTSTACK, // acceptanceBound

  // Preserve state while hashing SQUEEZE_DOMAIN || state || drawSuffix.
  OP.OP_SWAP,
  OP.OP_DUP,
  ...encodeMinimalDataPush(CIRCLE_FRI_SQUEEZE_DOMAIN),
  OP.OP_SWAP,
  OP.OP_CAT,
  OP.OP_2,
  OP.OP_ROLL,
  OP.OP_CAT,
  OP.OP_SHA256, // state, digest

  ...buildTranscriptCandidate(), // state, digest, unsigned candidate
  OP.OP_DUP,
  OP.OP_FROMALTSTACK, // acceptanceBound
  OP.OP_LESSTHAN,
  OP.OP_VERIFY,
  OP.OP_FROMALTSTACK, // upperBound
  OP.OP_MOD, // state, digest, sampled value

  // Hash state || labelFrame || frame(digest) || attemptFrame.
  OP.OP_2,
  OP.OP_PICK, // state copy
  OP.OP_FROMALTSTACK, // labelFrame
  OP.OP_CAT,
  ...encodeMinimalDataPush(framePrefix('accepted-challenge-digest', 32)),
  OP.OP_CAT,
  OP.OP_2,
  OP.OP_PICK, // digest copy
  OP.OP_CAT,
  OP.OP_FROMALTSTACK, // attemptFrame
  OP.OP_CAT,
  OP.OP_SHA256, // state, digest, value, nextState
  OP.OP_2SWAP,
  OP.OP_2DROP,
  OP.OP_SWAP, // nextState, sampled value
]);

const SAMPLE_M31_TRANSCRIPT_FUNCTION = Uint8Array.from([
  // Input: state, drawSuffix, labelFrame, attemptFrame.
  OP.OP_TOALTSTACK,
  OP.OP_TOALTSTACK,
  ...pushNumber(M31_MODULUS),
  ...pushNumber(Number(M31_MODULUS) * 2),
  OP.OP_FROMALTSTACK,
  OP.OP_FROMALTSTACK,
  ...invokeFunction(FUNCTION.SAMPLE_TRANSCRIPT),
]);

export const BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES = (
  HASH_LEAF_FUNCTION.length
  + HASH_NODE_LEFT_FUNCTION.length
  + HASH_NODE_RIGHT_FUNCTION.length
  + DECODE_M31_FUNCTION.length
  + FOLD_M31_FUNCTION.length
  + SAMPLE_TRANSCRIPT_FUNCTION.length
  + HASH_PACKED_NODE_LEFT_FUNCTION.length
  + HASH_PACKED_NODE_RIGHT_FUNCTION.length
  + SAMPLE_M31_TRANSCRIPT_FUNCTION.length
);

const QUERY_FUNCTION_DEFINITIONS = concat(
  defineFunction(FUNCTION.HASH_LEAF, HASH_LEAF_FUNCTION),
  defineFunction(FUNCTION.HASH_NODE_LEFT, HASH_NODE_LEFT_FUNCTION),
  defineFunction(FUNCTION.HASH_NODE_RIGHT, HASH_NODE_RIGHT_FUNCTION),
  defineFunction(FUNCTION.DECODE_M31, DECODE_M31_FUNCTION),
  defineFunction(FUNCTION.FOLD_M31, FOLD_M31_FUNCTION),
  defineFunction(FUNCTION.SAMPLE_TRANSCRIPT, SAMPLE_TRANSCRIPT_FUNCTION),
  defineFunction(FUNCTION.HASH_PACKED_NODE_LEFT, HASH_PACKED_NODE_LEFT_FUNCTION),
  defineFunction(FUNCTION.HASH_PACKED_NODE_RIGHT, HASH_PACKED_NODE_RIGHT_FUNCTION),
  defineFunction(FUNCTION.SAMPLE_M31_TRANSCRIPT, SAMPLE_M31_TRANSCRIPT_FUNCTION),
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
      (index & 1) === 0 ? FUNCTION.HASH_PACKED_NODE_LEFT : FUNCTION.HASH_PACKED_NODE_RIGHT,
    ));
    index = Math.floor(index / 2);
  }
  script.push(OP.OP_SWAP, OP.OP_0, OP.OP_EQUALVERIFY);
  return Object.freeze({ script, branchIndex: index });
};

const buildMerklePairVerification = ({ leftIndex, rightIndex, leftSiblings, rightSiblings }) => {
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
    ...pushNumber(3),
    OP.OP_PICK, // runtime root below inverse and right raw value
    OP.OP_EQUALVERIFY,
    OP.OP_TOALTSTACK, // alt: leftRaw, rightRaw
  ];
};

const buildTranscriptBoundFoldVerification = ({ coordinate, continuitySide, isLast }) => {
  const script = [
    // Recover right then left raw values. Altstack is:
    // [previousFold?], transcriptState, derivedBeta, leftRaw, rightRaw.
    OP.OP_FROMALTSTACK,
    OP.OP_FROMALTSTACK,
    ...invokeFunction(FUNCTION.DECODE_M31), // left
    OP.OP_SWAP,
    ...invokeFunction(FUNCTION.DECODE_M31), // right
    OP.OP_2,
    OP.OP_ROLL,
    ...invokeFunction(FUNCTION.DECODE_M31), // inverse(2*coordinate)
    OP.OP_FROMALTSTACK, // derived beta
    OP.OP_FROMALTSTACK, // transcript state
  ];

  if (continuitySide !== null) {
    script.push(
      OP.OP_FROMALTSTACK, // previous fold
      ...(pushNumber(continuitySide === 'left' ? 5 : 4)),
      OP.OP_PICK,
      OP.OP_SWAP,
      OP.OP_NUMEQUALVERIFY,
    );
  }

  script.push(
    OP.OP_TOALTSTACK, // transcript state
    OP.OP_TOALTSTACK, // beta
    ...pushNumber(coordinate),
    OP.OP_FROMALTSTACK,
    ...invokeFunction(FUNCTION.FOLD_M31),
    OP.OP_SWAP,
    OP.OP_DROP, // consume the runtime root retained below the fold operands
  );
  if (!isLast) {
    script.push(
      OP.OP_FROMALTSTACK, // folded value, transcript state
      OP.OP_SWAP,
      OP.OP_TOALTSTACK, // transcript state on main, folded value on alt
    );
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

const encodeFinalCodeword = (values) => concat(...values.map(encodeM31));

const buildHostTranscriptTrace = ({ proof, parameters, protocolContext }) => {
  let state = initializeCircleFriTranscriptState(protocolContext);
  state = absorbCircleFriTranscriptState(
    state,
    'fri-parameters',
    encodeCircleFriParameters(parameters),
  );
  const rounds = proof.roots.map((root, round) => {
    state = absorbCircleFriTranscriptState(state, `fri-layer-root-${round}`, root);
    const sample = sampleCircleFriTranscriptState({
      state,
      label: `fri-fold-beta-${round}`,
      upperBound: Number(M31_MODULUS),
    });
    state = sample.state;
    return Object.freeze({ round, sample });
  });
  const finalCodewordBytes = encodeFinalCodeword(proof.finalCodeword);
  state = absorbCircleFriTranscriptState(state, 'fri-final-codeword', finalCodewordBytes);
  const seen = [];
  const queries = [];
  for (let query = 0; query < parameters.queryCount; query += 1) {
    const candidates = [];
    for (let retry = 0; ; retry += 1) {
      const sample = sampleCircleFriTranscriptState({
        state,
        label: `fri-query-${query}-candidate-${retry}`,
        upperBound: parameters.domainLength,
      });
      state = sample.state;
      const duplicateOf = seen.indexOf(sample.value);
      candidates.push(Object.freeze({ retry, duplicateOf, sample }));
      if (duplicateOf === -1) {
        seen.push(sample.value);
        queries.push(Object.freeze({ query, index: sample.value, candidates }));
        break;
      }
    }
  }
  return Object.freeze({
    rounds,
    finalCodewordBytes,
    queries,
    finalState: state,
  });
};

/**
 * Bind one Fiat-Shamir-selected query to its Merkle roots, fold challenges, and
 * final constant. The generated BCH Script replays the complete transcript and
 * derives every beta and the query index; the host trace only unrolls the
 * deterministic rejection attempts.
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
  const transcriptTrace = buildHostTranscriptTrace({ proof, parameters, protocolContext });
  for (let queryIndex = 0; queryIndex < parameters.queryCount; queryIndex += 1) {
    require(transcriptTrace.queries[queryIndex].index === verdict.queryIndices[queryIndex], `host transcript query trace disagrees at query ${queryIndex}`);
  }
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    require(BigInt(transcriptTrace.rounds[round].sample.value) === verdict.betas[round], `host transcript beta trace disagrees at round ${round}`);
  }
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
      transcriptSample: transcriptTrace.rounds[round].sample,
      coordinate: pair.coordinate,
      inverseTwoCoordinate: inverse(mul(2n, pair.coordinate)),
      leftIndex: pair.leftIndex,
      rightIndex: pair.rightIndex,
      continuitySide: round === 0 ? null : (currentIndex === pair.leftIndex ? 'left' : 'right'),
      opening,
    }));
    currentIndex = pairIndex;
  }
  const topologyTable = topologyTableFor(parameters);
  const topologyOpening = openCircleFriTopologyTable(topologyTable, verdict.queryIndices[queryOrdinal]);
  const topologyRecord = decodeCircleFriTopologyRecord(topologyOpening.record);
  for (let round = 0; round < rounds.length; round += 1) {
    require(topologyRecord.rounds[round].leftIndex === rounds[round].leftIndex, `topology table left index disagrees at round ${round}`);
    require(topologyRecord.rounds[round].rightIndex === rounds[round].rightIndex, `topology table right index disagrees at round ${round}`);
    require(topologyRecord.rounds[round].coordinate === rounds[round].coordinate, `topology table coordinate disagrees at round ${round}`);
  }
  return Object.freeze({
    kind: 'circle-fri-transcript-bound-query-component-v1',
    transcriptDerivationIncluded: true,
    proofCommitmentsRuntimeSupplied: true,
    topologyOpeningRuntimeSupplied: true,
    proofSpecificRedeem: true,
    parameters,
    protocolContext: new Uint8Array(protocolContext),
    transcriptTrace,
    selectedQueryTrace: transcriptTrace.queries[queryOrdinal],
    queryOrdinal,
    initialQueryIndex: verdict.queryIndices[queryOrdinal],
    finalIndex: currentIndex,
    finalCodeword: proof.finalCodeword.slice(),
    topologyRoot: new Uint8Array(topologyTable.root),
    topologyOpening,
    rounds,
  });
};

const buildCanonicalQueryDerivation = (fixture) => {
  const script = [];
  const previousAccepted = [];
  for (let query = 0; query <= fixture.queryOrdinal; query += 1) {
    const queryTrace = fixture.transcriptTrace.queries[query];
    for (const candidate of queryTrace.candidates) {
      const value = candidate.sample.value;
      script.push(
        ...buildTranscriptChallenge({
          label: `fri-query-${query}-candidate-${candidate.retry}`,
          upperBound: fixture.parameters.domainLength,
          acceptedAttempt: candidate.sample.attempt,
        }),
        OP.OP_DUP,
        ...pushNumber(value),
        OP.OP_NUMEQUALVERIFY,
      );
      if (candidate.duplicateOf !== -1) {
        script.push(
          ...pushNumber(previousAccepted[candidate.duplicateOf]),
          OP.OP_NUMEQUALVERIFY,
        );
        continue;
      }
      for (const prior of previousAccepted) {
        script.push(
          OP.OP_DUP,
          ...pushNumber(prior),
          OP.OP_NUMNOTEQUAL,
          OP.OP_VERIFY,
        );
      }
      previousAccepted.push(value);
      if (query === fixture.queryOrdinal) {
        script.push(
          OP.OP_DUP,
          ...pushNumber(fixture.initialQueryIndex),
          OP.OP_NUMEQUALVERIFY,
          OP.OP_TOALTSTACK,
        );
      } else {
        script.push(OP.OP_DROP);
      }
    }
  }
  return script;
};

const buildTopologyOpeningVerification = (fixture) => {
  const script = [
    OP.OP_FROMALTSTACK, // topology record, packed siblings, derived query index
    ...pushNumber(2),
    OP.OP_ROLL, // packed siblings, derived query index, topology record
    OP.OP_SIZE,
    ...pushNumber(fixture.topologyOpening.record.length),
    OP.OP_NUMEQUALVERIFY,
    OP.OP_DUP,
    ...pushNumber(10),
    OP.OP_SPLIT,
    OP.OP_SWAP,
    OP.OP_DROP,
    ...pushNumber(4),
    OP.OP_SPLIT,
    OP.OP_DROP,
    ...encodeMinimalDataPush(ZERO_BYTE),
    OP.OP_CAT,
    OP.OP_BIN2NUM,
    ...pushNumber(2),
    OP.OP_PICK,
    OP.OP_NUMEQUALVERIFY,
    ...encodeMinimalDataPush(CIRCLE_FRI_TOPOLOGY_LEAF_DOMAIN),
    OP.OP_SWAP,
    OP.OP_CAT,
    OP.OP_HASH256,
    OP.OP_SWAP, // packed siblings, leaf hash, query index
  ];
  for (let level = 0; level < fixture.parameters.logDomain; level += 1) {
    script.push(
      OP.OP_DUP,
      ...pushNumber(2),
      OP.OP_MOD,
      OP.OP_IF,
      OP.OP_TOALTSTACK,
      ...invokeFunction(FUNCTION.HASH_PACKED_NODE_RIGHT),
      OP.OP_FROMALTSTACK,
      OP.OP_ELSE,
      OP.OP_TOALTSTACK,
      ...invokeFunction(FUNCTION.HASH_PACKED_NODE_LEFT),
      OP.OP_FROMALTSTACK,
      OP.OP_ENDIF,
      ...pushNumber(2),
      OP.OP_DIV,
    );
  }
  script.push(
    OP.OP_0,
    OP.OP_NUMEQUALVERIFY,
    OP.OP_SWAP,
    OP.OP_0,
    OP.OP_EQUALVERIFY,
    ...encodeMinimalDataPush(fixture.topologyRoot),
    OP.OP_EQUAL,
  );
  return script;
};

const topologyTableCache = new Map();
const topologyTableFor = (parameters) => {
  const key = binToHex(encodeCircleFriParameters(parameters));
  const cached = topologyTableCache.get(key);
  if (cached !== undefined) return cached;
  const table = buildCircleFriTopologyTable(parameters);
  topologyTableCache.set(key, table);
  return table;
};

export const buildBchCircleFriQueryRedeemBytecode = (fixture) => {
  require(fixture?.kind === 'circle-fri-transcript-bound-query-component-v1', 'query fixture is required');
  const script = [
    ...QUERY_FUNCTION_DEFINITIONS,
    ...buildTranscriptInitialization({
      protocolContext: fixture.protocolContext,
      parameters: fixture.parameters,
    }),
  ];
  for (let round = 0; round < fixture.rounds.length; round += 1) {
    const item = fixture.rounds[round];
    script.push(
      ...pushNumber(6),
      OP.OP_PICK, // runtime root below this round's five opening operands
      ...buildTranscriptAbsorbRuntime(`fri-layer-root-${round}`, 32),
      ...buildTranscriptChallenge({
        label: `fri-fold-beta-${round}`,
        upperBound: Number(M31_MODULUS),
        acceptedAttempt: item.transcriptSample.attempt,
      }),
      OP.OP_SWAP,
      OP.OP_TOALTSTACK, // transcript state
      OP.OP_TOALTSTACK, // derived beta
      ...buildMerklePairVerification({
        leftIndex: item.leftIndex,
        rightIndex: item.rightIndex,
        leftSiblings: item.opening.leftSiblings,
        rightSiblings: item.opening.rightSiblings,
      }),
      ...buildTranscriptBoundFoldVerification({
        coordinate: item.coordinate,
        continuitySide: item.continuitySide,
        isLast: round === fixture.rounds.length - 1,
      }),
    );
  }
  script.push(
    OP.OP_FROMALTSTACK, // runtime final codeword, folded value, transcript state
    ...pushNumber(2),
    OP.OP_PICK,
    ...buildTranscriptAbsorbRuntime('fri-final-codeword', fixture.finalCodeword.length * 4),
    ...buildCanonicalQueryDerivation(fixture),
    OP.OP_DROP, // final transcript state
    OP.OP_SWAP, // folded value, runtime final codeword
    ...(fixture.finalIndex === 0 ? [] : [
      ...pushNumber(fixture.finalIndex * 4),
      OP.OP_SPLIT,
      OP.OP_SWAP,
      OP.OP_DROP,
    ]),
    ...pushNumber(4),
    OP.OP_SPLIT,
    OP.OP_DROP,
    ...invokeFunction(FUNCTION.DECODE_M31),
    OP.OP_NUMEQUALVERIFY,
    ...buildTopologyOpeningVerification(fixture),
  );
  return Uint8Array.from(script);
};

export const buildBchCircleFriQueryOperandUnlockingBytecode = (fixture) => {
  require(fixture?.kind === 'circle-fri-transcript-bound-query-component-v1', 'query fixture is required');
  const operands = [
    fixture.topologyOpening.record,
    concat(...fixture.topologyOpening.siblings.slice().reverse()),
    encodeFinalCodeword(fixture.finalCodeword),
  ];
  const packPartialPath = (siblings) => concat(...siblings.slice(0, -1).reverse());
  for (let round = fixture.rounds.length - 1; round >= 0; round -= 1) {
    const item = fixture.rounds[round];
    operands.push(
      item.root,
      encodeM31(item.inverseTwoCoordinate),
      packPartialPath(item.opening.rightSiblings),
      encodeM31(item.opening.rightValue),
      packPartialPath(item.opening.leftSiblings),
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

/**
 * Serialize one component transaction containing every query input for a proof.
 * This is a complete BCH transaction fixture for the FRI query layer only; it
 * does not claim PoolAction AIR or settlement binding.
 */
export const encodeBchCircleFriMultiQueryTransactionFixture = (fixtures) => {
  require(Array.isArray(fixtures) && fixtures.length >= 1, 'multi-query fixtures are required');
  const expectedCount = fixtures[0].parameters.queryCount;
  require(fixtures.length === expectedCount, 'multi-query fixture count must equal queryCount');
  const ordinals = fixtures.map(({ queryOrdinal }) => queryOrdinal);
  require(ordinals.every((ordinal, index) => ordinal === index), 'multi-query fixtures must be ordered by unique query ordinal');
  const transcriptIdentity = binToHex(fixtures[0].transcriptTrace.finalState);
  for (const fixture of fixtures) {
    require(fixture.kind === 'circle-fri-transcript-bound-query-component-v1', 'invalid multi-query fixture');
    require(fixture.parameters.queryCount === expectedCount, 'multi-query parameter mismatch');
    require(binToHex(fixture.transcriptTrace.finalState) === transcriptIdentity, 'multi-query transcript mismatch');
  }

  const materialized = fixtures.map(materializeBchCircleFriQueryP2sh32);
  const sourceOutputs = materialized.map(({ lockingBytecode }) => ({
    lockingBytecode,
    valueSatoshis: 1_000n,
  }));
  const transaction = {
    version: 2,
    inputs: materialized.map(({ unlockingBytecode }, inputIndex) => ({
      outpointTransactionHash: new Uint8Array(32).fill(0x11 + inputIndex),
      outpointIndex: inputIndex,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode,
    })),
    outputs: [{
      lockingBytecode: Uint8Array.of(OP.OP_1),
      valueSatoshis: 1_000n * BigInt(materialized.length),
    }],
    locktime: 0,
  };
  const transactionWire = encodeTransaction(transaction);
  const sourceOutputsWire = encodeTransactionOutputs(sourceOutputs);
  return Object.freeze({
    materialized,
    transactionHex: binToHex(transactionWire),
    sourceOutputsHex: binToHex(sourceOutputsWire),
    transactionBytes: transactionWire.length,
    sourceOutputsBytes: sourceOutputsWire.length,
    transactionDigestSha256: binToHex(sha256(transactionWire)),
    sourceOutputsDigestSha256: binToHex(sha256(sourceOutputsWire)),
  });
};
