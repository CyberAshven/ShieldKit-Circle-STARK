import { createHash } from 'node:crypto';

import { generateRabinCertificate } from '../field-cert/node/generate.mjs';
import { replayRabinCertificate } from '../field-cert/node/replay.mjs';
import { mersenneModulus } from '../field-cert/node/mersenne.mjs';

export const SEARCH_CONTRACT = Object.freeze({
  modulusRule: 'p=2^q-1',
  targets: Object.freeze([
    Object.freeze({ q: 31, degree: 5 }),
    Object.freeze({ q: 31, degree: 6 }),
    Object.freeze({ q: 61, degree: 3 })
  ]),
  K: 16,
  monic: true,
  lowerVectorSupport: Object.freeze([1, 2]),
  t0Nonzero: true,
  signedMagnitudeOrder: '-1,+1,-2,+2,...,-16,+16',
  candidateOrder: 'target-order;support-1-before-support-2;support-2-secondary-index-k-ascending;within-support-t0-signed-order-then-tk-signed-order',
  polynomialForm: 'f=x^d+sum(i=0..d-1,t_i*x^i)',
  coefficientOrientation: 'tCentered-and-tCanonical-are-c0-through-c(d-1);monic-leading-coefficient-is-implicit-1',
  reductionRecurrence: 'R_d[j]=center_p(-t_j);R_(k+1)[0]=center_p(R_k[d-1]*R_d[0]);R_(k+1)[j]=center_p(R_k[j-1]+R_k[d-1]*R_d[j]) for j=1..d-1; k=d..2d-3',
  reductionRowOrder: 'rows-are-R_d-through-R_(2d-2);each-row-coefficients-are-c0-through-c(d-1);each-row-entry-is-canonical-centered-signed-decimal',
  reductionCentering: 'center_p(z) is the unique integer in [-(p-1)/2,(p-1)/2] congruent to z modulo p',
  winnerOrientation: 'minimum-lexicographic-numeric-score;ties-break-by-first-row-in-the-frozen-candidate-order',
  scoreTupleOrder: 'nonZeroNonSignedUnitEntryCount,nonZeroEntryCount,bitLengthSum,peakBitLength,peakRowFanIn,polynomialMaxAbsCoefficient,polynomialSupport,polynomialL1,signedLexRanks(t0..t(d-1))',
  scoreMetricDefinitions: 'over-all-reduction-row-entries:nonZeroNonSignedUnitEntryCount=count(abs(entry)>1);nonZeroEntryCount=count(entry!=0);bitLength(0)=0-and-otherwise-bitLength(abs(entry));bitLengthSum=sum(bitLength);peakBitLength=max(bitLength);peakRowFanIn=max-per-row-count(entry!=0);over-all-polynomial-coefficients-(t_0..t_(d-1),1):polynomialMaxAbsCoefficient=max(abs(coefficient));polynomialSupport=count(coefficient!=0);polynomialL1=sum(abs(coefficient));signedLexRank(0)=0,signedLexRank(-m)=2m-1,signedLexRank(+m)=2m',
  irreducibleScoreDomain: 'only-candidates-whose-repository-Rabin-replay-classification-is-irreducible',
  scoreInterpretation: 'symbolic-heuristic-not-BCH-cost-or-lower-bound',
  serialization: 'UTF-8;object-keys-in-declaration-order;arrays-in-declared-order;transcript-minified;exactly-one-final-LF;no-CR'
});

export const PROVENANCE = Object.freeze({
  bchnSourceCommit: '864c53ee34924cca6c6b6d96607ff2cedcdccf02',
  sourceFile: 'src/script/script.h',
  sourceFileSha256: 'fdd6f1326c72032b4eeb5cf6605b1153d47798e84f8a39a69a66d83a64fc52ed',
  sourceFact: 'OP_1=0x51 through OP_16=0x60.',
  K16Rationale: 'K=16 is a design rationale for dedicated small-integer constants only; it is not a measured-cost or lower-bound claim.',
  rabinGenerator: 'p2/field-cert/node/generate.mjs:generateRabinCertificate',
  rabinReplay: 'p2/field-cert/node/replay.mjs:replayRabinCertificate',
  legacyFilesModified: false
});

export const FAIL_CLOSED_POLICY = Object.freeze({
  eliminationScope: 'A result can eliminate only the exact construction+codec+algorithm+track evaluated by this artifact.',
  familyPolicy: 'No exact-construction result may eliminate an entire (p,d) family.',
  measuredCostClaim: 'none',
  protocolSelection: 'none'
});

export const SHAKEDOWN_EXCEPTION = Object.freeze({
  id: 'shakedown:m89-d2-x2-plus-1',
  q: 89,
  degree: 2,
  p: mersenneModulus(89).toString(),
  tCentered: [1, 0],
  tCanonical: ['1', '0'],
  polynomialCanonical: ['1', '0', '1'],
  status: 'non-selected-outside-search',
  selection: 'none',
  reason: 'Fixed M89 x^2+1 Rabin shakedown exception; it is outside the frozen target search and cannot select or eliminate any target family.'
});

const signedValues = () => {
  const values = [];
  for (let magnitude = 1; magnitude <= SEARCH_CONTRACT.K; magnitude += 1) values.push(-magnitude, magnitude);
  return values;
};

const signedRank = (value) => {
  if (value === 0) return 0;
  const magnitude = Math.abs(value);
  return value < 0 ? 2 * magnitude - 1 : 2 * magnitude;
};

const canonicalResidue = (value, modulus) => (((BigInt(value) % modulus) + modulus) % modulus).toString();

const centered = (value, modulus) => {
  const residue = ((value % modulus) + modulus) % modulus;
  return residue > modulus / 2n ? residue - modulus : residue;
};

const bitLength = (value) => {
  const magnitude = value < 0n ? -value : value;
  return magnitude === 0n ? 0 : magnitude.toString(2).length;
};

const canonicalize = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
};

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const contentDigestFor = (value) => {
  const clone = structuredClone(value);
  delete clone.contentDigest;
  return sha256(canonicalize(clone));
};

const reductionRows = (t, modulus, degree) => {
  const rows = [t.map((coefficient) => centered(-BigInt(coefficient), modulus))];
  for (let exponent = degree; exponent < (2 * degree) - 2; exponent += 1) {
    const previous = rows.at(-1);
    rows.push(previous.map((entry, index) => centered(
      index === 0 ? previous[degree - 1] * rows[0][0] : previous[index - 1] + previous[degree - 1] * rows[0][index],
      modulus
    )));
  }
  return rows;
};

const scoreReductionRows = (rows, t) => {
  const flat = rows.flat();
  const bitLengths = flat.map(bitLength);
  const polynomialAbs = [...t, 1].map((coefficient) => Math.abs(coefficient));
  const signedLexRanks = t.map(signedRank);
  const score = {
    nonZeroNonSignedUnitEntryCount: flat.filter((entry) => entry < -1n || entry > 1n).length,
    nonZeroEntryCount: flat.filter((entry) => entry !== 0n).length,
    bitLengthSum: bitLengths.reduce((sum, value) => sum + value, 0),
    peakBitLength: Math.max(...bitLengths),
    peakRowFanIn: Math.max(...rows.map((row) => row.filter((entry) => entry !== 0n).length)),
    polynomialMaxAbsCoefficient: Math.max(...polynomialAbs),
    polynomialSupport: polynomialAbs.filter((coefficient) => coefficient !== 0).length,
    polynomialL1: polynomialAbs.reduce((sum, value) => sum + value, 0),
    signedLexRanks
  };
  score.lexicographicTuple = [
    score.nonZeroNonSignedUnitEntryCount,
    score.nonZeroEntryCount,
    score.bitLengthSum,
    score.peakBitLength,
    score.peakRowFanIn,
    score.polynomialMaxAbsCoefficient,
    score.polynomialSupport,
    score.polynomialL1,
    ...signedLexRanks
  ];
  return score;
};

const candidateVectors = (degree) => {
  const values = signedValues();
  const candidates = [];
  for (const value0 of values) candidates.push({ support: 1, secondaryIndex: null, t: [value0, ...Array(degree - 1).fill(0)] });
  for (let secondaryIndex = 1; secondaryIndex < degree; secondaryIndex += 1) {
    for (const value0 of values) {
      for (const valueK of values) {
        const t = Array(degree).fill(0);
        t[0] = value0;
        t[secondaryIndex] = valueK;
        candidates.push({ support: 2, secondaryIndex, t });
      }
    }
  }
  return candidates;
};

const scoreCompare = (left, right) => {
  for (let index = 0; index < left.lexicographicTuple.length; index += 1) {
    if (left.lexicographicTuple[index] !== right.lexicographicTuple[index]) return left.lexicographicTuple[index] - right.lexicographicTuple[index];
  }
  return 0;
};

const generateTarget = ({ q, degree }, targetOrderIndex) => {
  const modulus = mersenneModulus(q);
  const candidates = [];
  for (const candidate of candidateVectors(degree)) {
    const polynomialCanonical = [...candidate.t.map((value) => canonicalResidue(value, modulus)), '1'];
    // The repository generator emits a certificate attempt for every candidate;
    // only the independent replay boolean is admitted to the neutral transcript.
    const certificate = generateRabinCertificate({ mersenneExponent: String(q), polynomialCoefficients: polynomialCanonical });
    const irreducible = replayRabinCertificate(certificate);
    const reductions = reductionRows(candidate.t, modulus, degree);
    const score = scoreReductionRows(reductions, candidate.t);
    candidates.push({
      targetOrderIndex,
      candidateIndex: candidates.length,
      globalOrderIndex: 0,
      support: candidate.support,
      secondaryIndex: candidate.secondaryIndex,
      q,
      degree,
      p: modulus.toString(),
      tCentered: candidate.t,
      tCanonical: candidate.t.map((value) => canonicalResidue(value, modulus)),
      polynomialCanonical,
      irreducible,
      reductionExponents: Array.from({ length: degree - 1 }, (_, index) => degree + index),
      reductionRows: reductions.map((row) => row.map((entry) => entry.toString())),
      score
    });
  }
  const irreducibles = candidates.filter((candidate) => candidate.irreducible);
  const winner = irreducibles.reduce((best, candidate) => scoreCompare(candidate.score, best.score) < 0 ? candidate : best, irreducibles[0]);
  return {
    q,
    degree,
    p: modulus.toString(),
    candidateCount: candidates.length,
    irreducibleCount: irreducibles.length,
    reducibleCount: candidates.length - irreducibles.length,
    winnerCandidateIndex: winner.candidateIndex,
    winner: {
      candidateIndex: winner.candidateIndex,
      support: winner.support,
      secondaryIndex: winner.secondaryIndex,
      tCentered: winner.tCentered,
      tCanonical: winner.tCanonical,
      polynomialCanonical: winner.polynomialCanonical,
      irreducible: winner.irreducible,
      reductionExponents: winner.reductionExponents,
      reductionRows: winner.reductionRows,
      score: winner.score
    },
    candidates
  };
};

export const canonicalJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
export const canonicalTranscriptJson = (value) => `${JSON.stringify(value)}\n`;

export const generateConstructionFreezeBundle = () => {
  const targetResults = SEARCH_CONTRACT.targets.map(generateTarget);
  let globalOrderIndex = 0;
  const transcriptRows = [];
  const summaries = [];
  for (const target of targetResults) {
    for (const candidate of target.candidates) transcriptRows.push({ ...candidate, globalOrderIndex: globalOrderIndex++ });
    summaries.push({
      q: target.q,
      degree: target.degree,
      p: target.p,
      testedCount: target.candidateCount,
      irreducibleCount: target.irreducibleCount,
      reducibleCount: target.reducibleCount,
      winnerCandidateIndex: target.winnerCandidateIndex,
      winner: target.winner
    });
  }
  const transcript = {
    schema: 'shieldkit-labs/p2/construction-freeze-normalized-transcript/v1',
    transcriptId: 'construction-freeze:normalized-decision-transcript-v1',
    rows: transcriptRows,
    rowCount: transcriptRows.length,
    contentDigest: null
  };
  transcript.contentDigest = contentDigestFor(transcript);
  const transcriptBytes = canonicalTranscriptJson(transcript);
  const summary = {
    schema: 'shieldkit-labs/p2/construction-freeze/v1',
    artifactId: 'construction-freeze:p2-direct-polynomial-small-integer-v1',
    status: 'frozen-premeasurement-construction-heuristic',
    evidenceClassification: 'not-evidence',
    selection: 'none',
    tupleRef: null,
    protocolBoundary: 'component-only',
    searchContract: SEARCH_CONTRACT,
    transcriptBinding: {
      path: 'construction-freeze.normalized-transcript.v1.json',
      schema: transcript.schema,
      rowCount: transcript.rowCount,
      byteCount: Buffer.byteLength(transcriptBytes),
      sha256: sha256(Buffer.from(transcriptBytes, 'utf8')),
      contentDigest: transcript.contentDigest
    },
    targets: summaries,
    shakedownException: SHAKEDOWN_EXCEPTION,
    provenance: PROVENANCE,
    failClosedPolicy: FAIL_CLOSED_POLICY,
    contentDigest: null
  };
  summary.contentDigest = contentDigestFor(summary);
  return { summary, transcript, transcriptBytes };
};

export const generateConstructionFreeze = () => generateConstructionFreezeBundle().summary;
export const validateConstructionFreezeSemantics = (summary, transcript, expected = generateConstructionFreezeBundle()) => (
  canonicalize(summary) === canonicalize(expected.summary)
  && canonicalize(transcript) === canonicalize(expected.transcript)
);
