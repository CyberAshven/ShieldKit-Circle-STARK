import { M31_MODULUS } from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  assertBytes,
  concatBytes,
  frameBytes,
  readU32le,
  sha256,
  u32le,
  utf8,
} from './bytes.mjs';

const TRANSCRIPT_DOMAIN = utf8('ShieldKit/CircleFRI/Transcript/v1\0');
const SQUEEZE_DOMAIN = utf8('ShieldKit/CircleFRI/Squeeze/v1\0');
const TWO_TO_32 = 0x1_0000_0000;

const fail = (message) => {
  throw new TypeError(message);
};

const assertLabel = (label) => {
  if (typeof label !== 'string' || label.length === 0) fail('challenge label must be a nonempty string');
  return label;
};

/** Draw an unbiased integer by rejecting the incomplete tail of the u32 range. */
export const sampleUniformUint32 = ({ upperBound, draw, maximumAttempts = 1_000_000 }) => {
  if (!Number.isSafeInteger(upperBound) || upperBound < 1 || upperBound > 0xffff_ffff) {
    fail('upperBound must be an integer in [1, 2^32-1]');
  }
  if (typeof draw !== 'function') fail('draw must be a function');
  if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1) fail('maximumAttempts must be positive');
  const acceptanceBound = Math.floor(TWO_TO_32 / upperBound) * upperBound;
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const candidate = draw(attempt);
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate > 0xffff_ffff) {
      fail('draw must return an unsigned 32-bit integer');
    }
    if (candidate < acceptanceBound) {
      return Object.freeze({ value: candidate % upperBound, candidate, attempt, acceptanceBound });
    }
  }
  fail('rejection sampling exceeded maximumAttempts');
};

export class CircleFriTranscript {
  #state;

  constructor(protocolContext = new Uint8Array()) {
    const context = assertBytes(protocolContext, 'protocolContext');
    this.#state = sha256(concatBytes(TRANSCRIPT_DOMAIN, frameBytes('context', context)));
  }

  get digest() {
    return new Uint8Array(this.#state);
  }

  absorb(label, bytes) {
    if (typeof label !== 'string' || label.length === 0) fail('absorb label must be a nonempty string');
    this.#state = sha256(concatBytes(this.#state, frameBytes(label, assertBytes(bytes))));
    return this;
  }

  #draw(label, attempt) {
    return sha256(concatBytes(
      SQUEEZE_DOMAIN,
      this.#state,
      frameBytes('label', utf8(label)),
      frameBytes('attempt', u32le(attempt)),
    ));
  }

  #sample(label, upperBound) {
    const challengeLabel = assertLabel(label);
    let acceptedDigest;
    const sample = sampleUniformUint32({
      upperBound,
      draw: (attempt) => {
        const digest = this.#draw(challengeLabel, attempt);
        const candidate = readU32le(digest);
        const acceptanceBound = Math.floor(TWO_TO_32 / upperBound) * upperBound;
        if (candidate < acceptanceBound) acceptedDigest = digest;
        return candidate;
      },
    });
    this.#state = sha256(concatBytes(
      this.#state,
      frameBytes('accepted-challenge-label', utf8(challengeLabel)),
      frameBytes('accepted-challenge-digest', acceptedDigest),
      frameBytes('accepted-challenge-attempt', u32le(sample.attempt)),
    ));
    return sample.value;
  }

  challengeField(label) {
    return BigInt(this.#sample(label, Number(M31_MODULUS)));
  }

  challengeIndex(label, range) {
    if (!Number.isSafeInteger(range) || range < 1 || range > 0xffff_ffff) {
      fail('challenge index range must be an integer in [1, 2^32-1]');
    }
    return this.#sample(label, range);
  }
}
