import {
  M31_MODULUS,
  decodeM31,
  encodeM31,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  assertBytes,
  concatBytes,
  equalBytes,
  u16le,
  utf8,
} from './bytes.mjs';

import {
  buildStandardCoset,
} from './circle.mjs';

import {
  buildJFoldTopology,
  buildPiFoldTopology,
  foldJLayer,
  foldPair,
  foldPiLayer,
} from './fold.mjs';

import {
  circleFFT,
} from './cfft.mjs';

import {
  buildM31MerkleTree,
  openM31Merkle,
  verifyM31Merkle,
} from './commitment.mjs';

import {
  CircleFriTranscript,
} from './transcript.mjs';

export const CIRCLE_FRI_QUERY_PROOF_VERSION = 2;
export const CIRCLE_FRI_QUERY_PROOF_MAGIC = utf8('CFRP');
export const CIRCLE_FRI_QUERY_CANDIDATE_LABEL = 'fri-query-candidate';
export const DEFAULT_MAXIMUM_LOG_DOMAIN = 20;

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

const assertLog = (value, name, minimum = 0) => {
  if (!Number.isSafeInteger(value) || value < minimum || value > 30) {
    fail(`${name} must be an integer in [${minimum}, 30]`);
  }
  return value;
};

export const assertCircleFriParameters = ({
  logDegreeBound,
  logBlowup,
  queryCount,
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  const logDegree = assertLog(logDegreeBound, 'logDegreeBound', 1);
  const logRate = assertLog(logBlowup, 'logBlowup');
  const maximum = assertLog(maximumLogDomain, 'maximumLogDomain', 1);
  const logDomain = logDegree + logRate;
  if (logDomain > maximum) fail(`log domain ${logDomain} exceeds maximumLogDomain=${maximum}`);
  const domainLength = 2 ** logDomain;
  if (!Number.isSafeInteger(queryCount) || queryCount < 1 || queryCount > 0xffff || queryCount > domainLength) {
    fail('queryCount must be in [1, min(65535, domainLength)]');
  }
  return Object.freeze({
    logDegreeBound: logDegree,
    logBlowup: logRate,
    logDomain,
    degreeBound: 2 ** logDegree,
    blowup: 2 ** logRate,
    domainLength,
    queryCount,
  });
};

export const encodeCircleFriParameters = (parameters) => Uint8Array.of(
  CIRCLE_FRI_QUERY_PROOF_VERSION,
  parameters.logDegreeBound,
  parameters.logBlowup,
  ...u16le(parameters.queryCount),
);

const encodeM31Vector = (values, name) => concatBytes(...values.map(
  (value, index) => encodeM31(assertElement(value, `${name}[${index}]`)),
));

const deriveUniqueQueryIndices = (transcript, queryCount, domainLength) => {
  const indices = [];
  const seen = new Set();
  for (let query = 0; query < queryCount; query += 1) {
    for (;;) {
      const index = transcript.challengeIndex(CIRCLE_FRI_QUERY_CANDIDATE_LABEL, domainLength);
      if (!seen.has(index)) {
        seen.add(index);
        indices.push(index);
        break;
      }
    }
  }
  return indices;
};

const prepareTranscript = (protocolContext, parameters) => {
  const transcript = new CircleFriTranscript(assertBytes(protocolContext, 'protocolContext'));
  transcript.absorb('fri-parameters', encodeCircleFriParameters(parameters));
  return transcript;
};

const indexTopology = (topology, layerLength) => {
  const pairByLeaf = new Array(layerLength);
  for (let pairIndex = 0; pairIndex < topology.pairs.length; pairIndex += 1) {
    const pair = topology.pairs[pairIndex];
    if (pairByLeaf[pair.leftIndex] !== undefined || pairByLeaf[pair.rightIndex] !== undefined) {
      fail('fold topology reuses a leaf');
    }
    pairByLeaf[pair.leftIndex] = pairIndex;
    pairByLeaf[pair.rightIndex] = pairIndex;
  }
  if (pairByLeaf.some((value) => value === undefined)) fail('fold topology does not cover every leaf');
  return Object.freeze({ ...topology, pairByLeaf, layerLength });
};

export const buildCircleFriPublicTopologies = (parameters) => {
  const topologies = [];
  let domain = buildStandardCoset(parameters.logDomain);
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const topology = round === 0
      ? buildJFoldTopology(domain)
      : buildPiFoldTopology(domain);
    topologies.push(indexTopology(topology, domain.length));
    domain = topology.domain;
  }
  if (domain.length !== parameters.blowup) fail('fold topology does not terminate at blowup length');
  return topologies;
};

const cloneSiblings = (siblings) => siblings.map((sibling) => new Uint8Array(sibling));

/** Prove low degree for one CFFT coefficient vector using complete query paths. */
export const proveCircleFriQueries = ({
  coefficients,
  logBlowup,
  queryCount,
  protocolContext = new Uint8Array(),
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  if (!Array.isArray(coefficients) || coefficients.length < 2 || (coefficients.length & (coefficients.length - 1)) !== 0) {
    fail('coefficients length must be a power of two of at least two');
  }
  const logDegreeBound = Math.log2(coefficients.length);
  const parameters = assertCircleFriParameters({
    logDegreeBound,
    logBlowup,
    queryCount,
    maximumLogDomain,
  });
  const canonicalCoefficients = coefficients.map((value, index) => assertElement(value, `coefficients[${index}]`));
  const extendedCoefficients = new Array(parameters.domainLength).fill(0n);
  for (let index = 0; index < canonicalCoefficients.length; index += 1) {
    extendedCoefficients[index * parameters.blowup] = canonicalCoefficients[index];
  }

  const transcript = prepareTranscript(protocolContext, parameters);
  const committedLayers = [];
  const roots = [];
  let domain = buildStandardCoset(parameters.logDomain);
  let codeword = circleFFT(domain, extendedCoefficients);

  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    const tree = buildM31MerkleTree(codeword);
    roots.push(new Uint8Array(tree.root));
    transcript.absorb(`fri-layer-root-${round}`, tree.root);
    const beta = transcript.challengeField(`fri-fold-beta-${round}`);
    const folded = round === 0
      ? foldJLayer(domain, codeword, beta)
      : foldPiLayer(domain, codeword, beta);
    committedLayers.push(Object.freeze({ domain, codeword, tree, folded }));
    domain = folded.domain;
    codeword = folded.codeword;
  }

  if (codeword.length !== parameters.blowup) fail('prover fold length does not equal blowup');
  const finalValue = codeword[0];
  if (!codeword.every((value) => value === finalValue)) {
    throw new Error('low-degree coefficients did not fold to a constant final codeword');
  }
  const finalCodeword = codeword.slice();
  transcript.absorb('fri-final-codeword', encodeM31Vector(finalCodeword, 'finalCodeword'));
  const queryIndices = deriveUniqueQueryIndices(transcript, parameters.queryCount, parameters.domainLength);

  const queries = queryIndices.map((initialIndex) => {
    let currentIndex = initialIndex;
    const layers = committedLayers.map((layer) => {
      const pairIndex = layer.folded.pairs.findIndex(({ leftIndex, rightIndex }) => (
        leftIndex === currentIndex || rightIndex === currentIndex
      ));
      if (pairIndex < 0) throw new Error('prover could not locate query leaf in fold topology');
      const pair = layer.folded.pairs[pairIndex];
      const leftOpening = openM31Merkle(layer.tree, pair.leftIndex);
      const rightOpening = openM31Merkle(layer.tree, pair.rightIndex);
      currentIndex = pairIndex;
      return Object.freeze({
        leftValue: layer.codeword[pair.leftIndex],
        rightValue: layer.codeword[pair.rightIndex],
        leftSiblings: cloneSiblings(leftOpening.siblings),
        rightSiblings: cloneSiblings(rightOpening.siblings),
      });
    });
    return Object.freeze({ layers });
  });

  return Object.freeze({
    version: CIRCLE_FRI_QUERY_PROOF_VERSION,
    logDegreeBound: parameters.logDegreeBound,
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    roots,
    finalCodeword,
    queries,
  });
};

const assertHash = (value, name) => {
  const bytes = assertBytes(value, name);
  if (bytes.length !== 32) fail(`${name} must be exactly 32 bytes`);
  return bytes;
};

const assertProofShape = (proof, maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN) => {
  if (proof === null || typeof proof !== 'object') fail('proof must be an object');
  if (proof.version !== CIRCLE_FRI_QUERY_PROOF_VERSION) fail('unsupported Circle-FRI proof version');
  const parameters = assertCircleFriParameters({
    logDegreeBound: proof.logDegreeBound,
    logBlowup: proof.logBlowup,
    queryCount: proof.queryCount,
    maximumLogDomain,
  });
  if (!Array.isArray(proof.roots) || proof.roots.length !== parameters.logDegreeBound) {
    fail('proof root count must equal logDegreeBound');
  }
  proof.roots.forEach((root, index) => assertHash(root, `roots[${index}]`));
  if (!Array.isArray(proof.finalCodeword) || proof.finalCodeword.length !== parameters.blowup) {
    fail('finalCodeword length must equal blowup');
  }
  proof.finalCodeword.forEach((value, index) => assertElement(value, `finalCodeword[${index}]`));
  if (!Array.isArray(proof.queries) || proof.queries.length !== parameters.queryCount) {
    fail('proof query count does not match queryCount');
  }
  for (let query = 0; query < proof.queries.length; query += 1) {
    const item = proof.queries[query];
    if (item === null || typeof item !== 'object' || !Array.isArray(item.layers)
        || item.layers.length !== parameters.logDegreeBound) {
      fail(`queries[${query}] layer count must equal logDegreeBound`);
    }
    for (let round = 0; round < item.layers.length; round += 1) {
      const opening = item.layers[round];
      const pathLength = parameters.logDomain - round;
      if (opening === null || typeof opening !== 'object') fail(`queries[${query}].layers[${round}] must be an object`);
      assertElement(opening.leftValue, `queries[${query}].layers[${round}].leftValue`);
      assertElement(opening.rightValue, `queries[${query}].layers[${round}].rightValue`);
      for (const side of ['leftSiblings', 'rightSiblings']) {
        if (!Array.isArray(opening[side]) || opening[side].length !== pathLength) {
          fail(`queries[${query}].layers[${round}].${side} has wrong length`);
        }
        opening[side].forEach((hash, index) => assertHash(hash, `queries[${query}].layers[${round}].${side}[${index}]`));
      }
    }
  }
  return parameters;
};

const verifyCircleFriQueriesOrThrow = ({
  proof,
  expected,
  protocolContext = new Uint8Array(),
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  const parameters = assertProofShape(proof, maximumLogDomain);
  if (expected === null || typeof expected !== 'object') fail('expected parameters are required');
  const expectedParameters = assertCircleFriParameters({ ...expected, maximumLogDomain });
  for (const field of ['logDegreeBound', 'logBlowup', 'queryCount']) {
    if (parameters[field] !== expectedParameters[field]) fail(`proof ${field} does not match expected parameters`);
  }

  const finalValue = proof.finalCodeword[0];
  if (!proof.finalCodeword.every((value) => value === finalValue)) fail('final codeword is not constant');

  const transcript = prepareTranscript(protocolContext, parameters);
  const betas = [];
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    transcript.absorb(`fri-layer-root-${round}`, proof.roots[round]);
    betas.push(transcript.challengeField(`fri-fold-beta-${round}`));
  }
  transcript.absorb('fri-final-codeword', encodeM31Vector(proof.finalCodeword, 'finalCodeword'));
  const queryIndices = deriveUniqueQueryIndices(transcript, parameters.queryCount, parameters.domainLength);
  const topologies = buildCircleFriPublicTopologies(parameters);

  for (let query = 0; query < queryIndices.length; query += 1) {
    let currentIndex = queryIndices[query];
    let previousFold;
    for (let round = 0; round < parameters.logDegreeBound; round += 1) {
      const topology = topologies[round];
      const pairIndex = topology.pairByLeaf[currentIndex];
      const pair = topology.pairs[pairIndex];
      const opening = proof.queries[query].layers[round];
      const root = proof.roots[round];

      const leftValid = verifyM31Merkle({
        root,
        length: topology.layerLength,
        index: pair.leftIndex,
        value: opening.leftValue,
        siblings: opening.leftSiblings,
      });
      const rightValid = verifyM31Merkle({
        root,
        length: topology.layerLength,
        index: pair.rightIndex,
        value: opening.rightValue,
        siblings: opening.rightSiblings,
      });
      if (!leftValid || !rightValid) fail(`query ${query} round ${round} Merkle opening failed`);

      if (previousFold !== undefined) {
        const authenticatedCurrent = currentIndex === pair.leftIndex
          ? opening.leftValue
          : opening.rightValue;
        if (previousFold !== authenticatedCurrent) fail(`query ${query} round ${round} fold continuity failed`);
      }

      previousFold = foldPair({
        positive: opening.leftValue,
        negative: opening.rightValue,
        coordinate: pair.coordinate,
        beta: betas[round],
      }).value;
      currentIndex = pairIndex;
    }
    if (previousFold !== proof.finalCodeword[currentIndex]) {
      fail(`query ${query} final low-degree check failed`);
    }
  }
  return Object.freeze({ ok: true, queryIndices, betas });
};

/** Fail-closed verifier: malformed and invalid proofs both return ok=false. */
export const verifyCircleFriQueries = (input) => {
  try {
    return verifyCircleFriQueriesOrThrow(input);
  } catch (error) {
    return Object.freeze({ ok: false, reason: error instanceof Error ? error.message : String(error) });
  }
};

export const estimateCircleFriQueryProofBytes = ({
  logDegreeBound,
  logBlowup,
  queryCount,
  maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN,
}) => {
  const parameters = assertCircleFriParameters({ logDegreeBound, logBlowup, queryCount, maximumLogDomain });
  let bytes = 9 + parameters.logDegreeBound * 32 + parameters.blowup * 4;
  let perQuery = 0;
  for (let round = 0; round < parameters.logDegreeBound; round += 1) {
    perQuery += 8 + 64 * (parameters.logDomain - round);
  }
  bytes += parameters.queryCount * perQuery;
  return bytes;
};

export const encodeCircleFriQueryProof = (proof, { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {}) => {
  const parameters = assertProofShape(proof, maximumLogDomain);
  const chunks = [
    CIRCLE_FRI_QUERY_PROOF_MAGIC,
    encodeCircleFriParameters(parameters),
    ...proof.roots,
    encodeM31Vector(proof.finalCodeword, 'finalCodeword'),
  ];
  for (const query of proof.queries) {
    for (const opening of query.layers) {
      chunks.push(
        encodeM31(opening.leftValue),
        encodeM31(opening.rightValue),
        ...opening.leftSiblings,
        ...opening.rightSiblings,
      );
    }
  }
  const encoded = concatBytes(...chunks);
  const expectedLength = estimateCircleFriQueryProofBytes({ ...parameters, maximumLogDomain });
  if (encoded.length !== expectedLength) throw new Error('internal Circle-FRI proof length mismatch');
  return encoded;
};

export const decodeCircleFriQueryProof = (encoded, { maximumLogDomain = DEFAULT_MAXIMUM_LOG_DOMAIN } = {}) => {
  const bytes = assertBytes(encoded, 'encoded proof');
  let offset = 0;
  const read = (length, name) => {
    if (!Number.isSafeInteger(length) || length < 0 || offset + length > bytes.length) fail(`${name} is truncated`);
    const result = bytes.slice(offset, offset + length);
    offset += length;
    return result;
  };
  const magic = read(4, 'proof magic');
  if (!equalBytes(magic, CIRCLE_FRI_QUERY_PROOF_MAGIC)) fail('invalid Circle-FRI proof magic');
  const header = read(5, 'proof header');
  const version = header[0];
  if (version !== CIRCLE_FRI_QUERY_PROOF_VERSION) fail('unsupported Circle-FRI proof version');
  const logDegreeBound = header[1];
  const logBlowup = header[2];
  const queryCount = header[3] + header[4] * 0x100;
  const parameters = assertCircleFriParameters({
    logDegreeBound,
    logBlowup,
    queryCount,
    maximumLogDomain,
  });
  const expectedLength = estimateCircleFriQueryProofBytes({ ...parameters, maximumLogDomain });
  if (bytes.length !== expectedLength) fail(`encoded proof length ${bytes.length} does not equal canonical length ${expectedLength}`);

  const roots = Array.from({ length: parameters.logDegreeBound }, (_, index) => read(32, `roots[${index}]`));
  const finalCodeword = Array.from({ length: parameters.blowup }, (_, index) => (
    decodeM31(read(4, `finalCodeword[${index}]`))
  ));
  const queries = Array.from({ length: parameters.queryCount }, (_, query) => ({
    layers: Array.from({ length: parameters.logDegreeBound }, (_, round) => {
      const pathLength = parameters.logDomain - round;
      return Object.freeze({
        leftValue: decodeM31(read(4, `queries[${query}].layers[${round}].leftValue`)),
        rightValue: decodeM31(read(4, `queries[${query}].layers[${round}].rightValue`)),
        leftSiblings: Array.from({ length: pathLength }, (_, index) => (
          read(32, `queries[${query}].layers[${round}].leftSiblings[${index}]`)
        )),
        rightSiblings: Array.from({ length: pathLength }, (_, index) => (
          read(32, `queries[${query}].layers[${round}].rightSiblings[${index}]`)
        )),
      });
    }),
  }));
  if (offset !== bytes.length) fail('encoded proof has trailing bytes');
  return Object.freeze({
    version,
    logDegreeBound,
    logBlowup,
    queryCount,
    roots,
    finalCodeword,
    queries,
  });
};
