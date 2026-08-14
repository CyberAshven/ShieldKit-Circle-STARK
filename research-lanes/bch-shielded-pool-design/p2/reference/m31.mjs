/**
 * Independent M31 base-field reference for P2 Tranche 0.
 *
 * This module intentionally implements only p = 2^31 - 1. Elements are
 * BigInt values in the canonical interval [0, p); Numbers are rejected so no
 * arithmetic can silently pass through a 53-bit Number conversion.
 */

export const M31_MODULUS = 2147483647n;
export const M31_WIRE_BYTES = 4;
export const M31_SCHEMA = "shieldkit-labs/m31-reference/v1";

export class M31Error extends TypeError {}

function fail(message) {
  throw new M31Error(message);
}

function assertElement(value, name = "element") {
  if (typeof value !== "bigint") fail(`${name} must be a BigInt`);
  if (value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be in [0, ${M31_MODULUS - 1n}]`);
  }
  return value;
}

function assertBytes(value, name) {
  if (!(value instanceof Uint8Array)) fail(`${name} must be a Uint8Array`);
  return value;
}

function assertOffset(offset, name = "offset") {
  if (!Number.isSafeInteger(offset) || offset < 0) fail(`${name} must be a nonnegative safe integer`);
  return offset;
}

/** Convert strictly lowercase, even-length hexadecimal text to bytes. */
export function hexToBytesStrict(hex, name = "hex") {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    fail(`${name} must be lowercase even-length hex`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes, name = "bytes") {
  assertBytes(bytes, name);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Encode one canonical field element as exactly four unsigned LE bytes. */
export function encodeM31(value) {
  let n = assertElement(value);
  const bytes = new Uint8Array(M31_WIRE_BYTES);
  for (let i = 0; i < M31_WIRE_BYTES; i += 1) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

export function encodeM31Hex(value) {
  return bytesToHex(encodeM31(value));
}

/** Decode exactly four canonical unsigned LE bytes with full consumption. */
export function decodeM31(input) {
  const bytes = assertBytes(input, "M31 input");
  if (bytes.length !== M31_WIRE_BYTES) {
    fail(`M31 input must be exactly ${M31_WIRE_BYTES} bytes; got ${bytes.length}`);
  }
  let value = 0n;
  for (let i = M31_WIRE_BYTES - 1; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  if (value >= M31_MODULUS) fail(`M31 wire value ${value} is not canonical (>= p)`);
  return value;
}

export function decodeM31Hex(hex) {
  if (typeof hex !== "string" || hex.length !== M31_WIRE_BYTES * 2) {
    fail(`M31 hex input must be exactly ${M31_WIRE_BYTES * 2} lowercase hex characters`);
  }
  return decodeM31(hexToBytesStrict(hex, "M31 hex input"));
}

/** Read one element from a larger byte sequence without accepting truncation. */
export function readM31(input, offset = 0) {
  const bytes = assertBytes(input, "M31 input");
  const start = assertOffset(offset);
  if (start + M31_WIRE_BYTES > bytes.length) {
    fail(`M31 input ends before offset ${start + M31_WIRE_BYTES}`);
  }
  return { value: decodeM31(bytes.slice(start, start + M31_WIRE_BYTES)), nextOffset: start + M31_WIRE_BYTES };
}

export function assertFullConsumption(offset, length, name = "input") {
  const consumed = assertOffset(offset, `${name} offset`);
  const total = assertOffset(length, `${name} length`);
  if (consumed !== total) fail(`${name} has trailing or unconsumed bytes: ${total - consumed}`);
  return true;
}

/** Decode a sequence of elements and require every byte to be consumed. */
export function decodeM31Sequence(input) {
  const bytes = assertBytes(input, "M31 sequence");
  const values = [];
  let offset = 0;
  while (offset < bytes.length) {
    const read = readM31(bytes, offset);
    values.push(read.value);
    offset = read.nextOffset;
  }
  assertFullConsumption(offset, bytes.length, "M31 sequence");
  return values;
}

export function add(left, right) {
  return (assertElement(left, "left") + assertElement(right, "right")) % M31_MODULUS;
}

export function sub(left, right) {
  return (assertElement(left, "left") - assertElement(right, "right") + M31_MODULUS) % M31_MODULUS;
}

export function neg(value) {
  const n = assertElement(value);
  return n === 0n ? 0n : M31_MODULUS - n;
}

export function mul(left, right) {
  return (assertElement(left, "left") * assertElement(right, "right")) % M31_MODULUS;
}

export function square(value) {
  return mul(value, value);
}

export function inverse(value) {
  const input = assertElement(value);
  if (input === 0n) fail("zero has no M31 inverse");

  // Extended Euclid over BigInt; no Number conversion occurs in the field path.
  let oldR = input;
  let r = M31_MODULUS;
  let oldT = 1n;
  let t = 0n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldT, t] = [t, oldT - quotient * t];
  }
  if (oldR !== 1n) fail("M31 inverse failed: non-unit element");
  return ((oldT % M31_MODULUS) + M31_MODULUS) % M31_MODULUS;
}

/** Verify a prover-supplied inverse hint without calculating the inverse. */
export function verifyInverseHint(value, hint) {
  const input = assertElement(value, "value");
  const candidate = assertElement(hint, "inverse hint");
  if (input === 0n) fail("zero has no inverse hint");
  return mul(input, candidate) === 1n;
}

export function inverseWithHint(value, hint) {
  if (!verifyInverseHint(value, hint)) fail("inverse hint does not verify");
  return hint;
}
