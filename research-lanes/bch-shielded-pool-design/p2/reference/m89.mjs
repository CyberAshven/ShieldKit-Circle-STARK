/**
 * Native, host-only reference for the frozen M89^2 Gate-B0 shakedown.
 *
 * Fp uses p = 2^89 - 1. Fp2 is Fp[u]/(u^2 + 1), represented as the ordered
 * pair [c0, c1] for c0 + c1*u. This is neither a protocol field selection nor
 * an on-chain implementation.
 */
export const M89_MODULUS = (1n << 89n) - 1n;
export const M89_LIMB_BYTES = 12;
export const M89_ELEMENT_BYTES = 24;
export const M89_SCHEMA = 'shieldkit-labs/m89-d2-reference/v1';

export class M89Error extends TypeError {}
const fail = (message) => { throw new M89Error(message); };

export function assertFp(value, name = 'Fp element') {
  if (typeof value !== 'bigint') fail(`${name} must be a BigInt`);
  if (value < 0n || value >= M89_MODULUS) fail(`${name} must be in [0, ${M89_MODULUS - 1n}]`);
  return value;
}

export function assertM89(value, name = 'M89^2 element') {
  if (!Array.isArray(value) || value.length !== 2) fail(`${name} must be a two-coefficient array`);
  return [assertFp(value[0], `${name}.c0`), assertFp(value[1], `${name}.c1`)];
}

const assertBytes = (value, name) => {
  if (!(value instanceof Uint8Array)) fail(`${name} must be a Uint8Array`);
  return value;
};
const assertOffset = (offset, name = 'offset') => {
  if (!Number.isSafeInteger(offset) || offset < 0) fail(`${name} must be a nonnegative safe integer`);
  return offset;
};
const modP = (value) => ((value % M89_MODULUS) + M89_MODULUS) % M89_MODULUS;

export function hexToBytesStrict(hex, name = 'hex') {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hex)) fail(`${name} must be lowercase even-length hex`);
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

export function bytesToHex(bytes, name = 'bytes') {
  assertBytes(bytes, name);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Encode one canonical Fp coefficient as exactly 12 unsigned LE bytes. */
export function encodeFp(value) {
  let current = assertFp(value);
  const bytes = new Uint8Array(M89_LIMB_BYTES);
  for (let index = 0; index < M89_LIMB_BYTES; index += 1) {
    bytes[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
}

/** Decode one exact-width Fp limb. High bits reject before numeric decode. */
export function decodeFp(input) {
  const bytes = assertBytes(input, 'M89 Fp input');
  if (bytes.length !== M89_LIMB_BYTES) fail(`M89 Fp input must be exactly ${M89_LIMB_BYTES} bytes; got ${bytes.length}`);
  if ((bytes[M89_LIMB_BYTES - 1] & 0xfe) !== 0) fail('M89 Fp input has a set unused high bit');
  let value = 0n;
  for (let index = M89_LIMB_BYTES - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]);
  if (value >= M89_MODULUS) fail(`M89 Fp wire value ${value} is not canonical (>= p)`);
  return value;
}

export const encodeFpHex = (value) => bytesToHex(encodeFp(value));
export function decodeFpHex(hex) {
  if (typeof hex !== 'string' || hex.length !== M89_LIMB_BYTES * 2) fail(`M89 Fp hex input must be exactly ${M89_LIMB_BYTES * 2} lowercase hex characters`);
  return decodeFp(hexToBytesStrict(hex, 'M89 Fp hex input'));
}

/** Encode c0||c1, each a canonical fixed-width little-endian limb. */
export function encodeM89(value) {
  const [c0, c1] = assertM89(value);
  const bytes = new Uint8Array(M89_ELEMENT_BYTES);
  bytes.set(encodeFp(c0), 0);
  bytes.set(encodeFp(c1), M89_LIMB_BYTES);
  return bytes;
}

export function decodeM89(input) {
  const bytes = assertBytes(input, 'M89^2 input');
  if (bytes.length !== M89_ELEMENT_BYTES) fail(`M89^2 input must be exactly ${M89_ELEMENT_BYTES} bytes; got ${bytes.length}`);
  return [decodeFp(bytes.slice(0, M89_LIMB_BYTES)), decodeFp(bytes.slice(M89_LIMB_BYTES, M89_ELEMENT_BYTES))];
}

export const encodeM89Hex = (value) => bytesToHex(encodeM89(value));
export function decodeM89Hex(hex) {
  if (typeof hex !== 'string' || hex.length !== M89_ELEMENT_BYTES * 2) fail(`M89^2 hex input must be exactly ${M89_ELEMENT_BYTES * 2} lowercase hex characters`);
  return decodeM89(hexToBytesStrict(hex, 'M89^2 hex input'));
}

export function readM89(input, offset = 0) {
  const bytes = assertBytes(input, 'M89^2 input');
  const start = assertOffset(offset);
  if (start + M89_ELEMENT_BYTES > bytes.length) fail(`M89^2 input ends before offset ${start + M89_ELEMENT_BYTES}`);
  return { value: decodeM89(bytes.slice(start, start + M89_ELEMENT_BYTES)), nextOffset: start + M89_ELEMENT_BYTES };
}

export function assertFullConsumption(offset, length, name = 'input') {
  const consumed = assertOffset(offset, `${name} offset`);
  const total = assertOffset(length, `${name} length`);
  if (consumed !== total) fail(`${name} has trailing or unconsumed bytes: ${total - consumed}`);
  return true;
}

export function decodeM89Sequence(input) {
  const bytes = assertBytes(input, 'M89^2 sequence');
  const values = [];
  let offset = 0;
  while (offset < bytes.length) {
    const read = readM89(bytes, offset);
    values.push(read.value);
    offset = read.nextOffset;
  }
  assertFullConsumption(offset, bytes.length, 'M89^2 sequence');
  return values;
}

export const fpAdd = (left, right) => modP(assertFp(left, 'left') + assertFp(right, 'right'));
export const fpSub = (left, right) => modP(assertFp(left, 'left') - assertFp(right, 'right'));
export const fpNeg = (value) => { const input = assertFp(value); return input === 0n ? 0n : M89_MODULUS - input; };
export const fpMul = (left, right) => modP(assertFp(left, 'left') * assertFp(right, 'right'));
export const fpSquare = (value) => fpMul(value, value);

export function fpInverse(value) {
  const input = assertFp(value);
  if (input === 0n) fail('zero has no M89 Fp inverse');
  let oldR = input;
  let r = M89_MODULUS;
  let oldT = 1n;
  let t = 0n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldT, t] = [t, oldT - quotient * t];
  }
  if (oldR !== 1n) fail('M89 Fp inverse failed: non-unit element');
  return modP(oldT);
}

export function add(left, right) {
  const [a0, a1] = assertM89(left, 'left');
  const [b0, b1] = assertM89(right, 'right');
  return [fpAdd(a0, b0), fpAdd(a1, b1)];
}
export function sub(left, right) {
  const [a0, a1] = assertM89(left, 'left');
  const [b0, b1] = assertM89(right, 'right');
  return [fpSub(a0, b0), fpSub(a1, b1)];
}
export function neg(value) {
  const [a0, a1] = assertM89(value);
  return [fpNeg(a0), fpNeg(a1)];
}
export function mul(left, right) {
  const [a0, a1] = assertM89(left, 'left');
  const [b0, b1] = assertM89(right, 'right');
  return [fpSub(fpMul(a0, b0), fpMul(a1, b1)), fpAdd(fpMul(a0, b1), fpMul(a1, b0))];
}
export function square(value) {
  const [a0, a1] = assertM89(value);
  return [fpSub(fpSquare(a0), fpSquare(a1)), fpAdd(fpMul(a0, a1), fpMul(a0, a1))];
}
export function equal(left, right) {
  const [a0, a1] = assertM89(left, 'left');
  const [b0, b1] = assertM89(right, 'right');
  return a0 === b0 && a1 === b1;
}
export const isZero = (value) => { const [c0, c1] = assertM89(value); return c0 === 0n && c1 === 0n; };

export function inverse(value) {
  const [a0, a1] = assertM89(value);
  if (a0 === 0n && a1 === 0n) fail('zero has no M89^2 inverse');
  const denominatorInverse = fpInverse(fpAdd(fpSquare(a0), fpSquare(a1)));
  return [fpMul(a0, denominatorInverse), fpNeg(fpMul(a1, denominatorInverse))];
}

/** Verify a prover-supplied inverse hint; this does not calculate an inverse. */
export function verifyInverseHint(value, hint) {
  const input = assertM89(value, 'value');
  const candidate = assertM89(hint, 'inverse hint');
  if (isZero(input)) fail('zero has no inverse hint');
  return equal(mul(input, candidate), [1n, 0n]);
}
export function inverseWithHint(value, hint) {
  if (!verifyInverseHint(value, hint)) fail('inverse hint does not verify');
  return assertM89(hint, 'inverse hint');
}
