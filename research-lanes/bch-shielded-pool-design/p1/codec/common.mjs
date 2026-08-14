/**
 * Dependency-light canonical wire helpers for the P1 semantic codecs.
 *
 * This module deliberately has no digest implementation.  All digest-shaped
 * fields are opaque bytes32 values and are only serialized as supplied.
 */

export class CodecError extends TypeError {}

export const U64_MAX = (1n << 64n) - 1n;
export const I64_MIN = -(1n << 63n);
export const I64_MAX = (1n << 63n) - 1n;
export const VARBYTES_MAX = 10_000;

const NETWORK_TAGS = Object.freeze({ mainnet: 0x00, chipnet: 0x01, regtest: 0x02 });
const NETWORK_NAMES = Object.freeze(["mainnet", "chipnet", "regtest"]);

export const ACTION_TAGS = Object.freeze({ DEPOSIT: 0x00, WITHDRAWAL: 0x01 });
export const ACTION_NAMES = Object.freeze(["DEPOSIT", "WITHDRAWAL"]);

export const INPUT_ROLE_TAGS = Object.freeze({
  STATE: 0x00,
  VERIFIER_CARRIER: 0x01,
  DEPOSIT_FUNDING: 0x02,
  FEE_FUNDING: 0x03,
});
export const INPUT_ROLE_NAMES = Object.freeze([
  "STATE",
  "VERIFIER_CARRIER",
  "DEPOSIT_FUNDING",
  "FEE_FUNDING",
]);

export const OUTPUT_ROLE_TAGS = Object.freeze({
  STATE_SUCCESSOR: 0x10,
  VERIFIER_CARRIER_SUCCESSOR: 0x11,
  PAYOUT: 0x12,
  TRANSPARENT_CHANGE: 0x13,
});
export const OUTPUT_ROLE_NAMES = Object.freeze({
  0x10: "STATE_SUCCESSOR",
  0x11: "VERIFIER_CARRIER_SUCCESSOR",
  0x12: "PAYOUT",
  0x13: "TRANSPARENT_CHANGE",
});

export const TOKEN_KIND_TAGS = Object.freeze({
  none: 0x00,
  "fungible-only": 0x01,
  immutable: 0x02,
  mutable: 0x03,
  minting: 0x04,
});
export const TOKEN_KIND_NAMES = Object.freeze([
  "none",
  "fungible-only",
  "immutable",
  "mutable",
  "minting",
]);

export function fail(message) {
  throw new CodecError(message);
}

export function assertObject(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${name} must be an object`);
  }
  return value;
}

export function assertExactKeys(value, required, optional = [], name = "object") {
  assertObject(value, name);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${name}.${key} is not canonical`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      fail(`${name}.${key} is required`);
    }
  }
}

export function assertInteger(value, name, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) {
    fail(`${name} must be an integer in [${min}, ${max}]`);
  }
  return value;
}

export function assertU8(value, name) {
  return assertInteger(value, name, 0, 0xff);
}

export function assertU16(value, name) {
  return assertInteger(value, name, 0, 0xffff);
}

export function assertU32(value, name) {
  return assertInteger(value, name, 0, 0xffffffff);
}

export function decimalBigInt(value, name, { signed = false } = {}) {
  if (typeof value !== "string") fail(`${name} must be a canonical decimal string`);
  const pattern = signed ? /^(0|-?[1-9][0-9]*)$/ : /^(0|[1-9][0-9]*)$/;
  if (!pattern.test(value)) fail(`${name} must be a canonical decimal string`);
  let result;
  try {
    result = BigInt(value);
  } catch {
    fail(`${name} is not an integer`);
  }
  return result;
}

export function assertU64(value, name) {
  const result = decimalBigInt(value, name);
  if (result > U64_MAX) fail(`${name} exceeds uint64`);
  return result;
}

export function assertI64(value, name) {
  const result = decimalBigInt(value, name, { signed: true });
  if (result < I64_MIN || result > I64_MAX) fail(`${name} exceeds int64`);
  return result;
}

export function assertHex(value, name, bytes, { allowEmpty = false } = {}) {
  if (typeof value !== "string") fail(`${name} must be lowercase hex`);
  if (allowEmpty && value === "") return value;
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    fail(`${name} must be exactly ${bytes} lowercase bytes`);
  }
  return value;
}

export function assertBytecodeHex(value, name) {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) {
    fail(`${name} must be nonempty lowercase even-length hex`);
  }
  if (value.length > VARBYTES_MAX * 2) fail(`${name} exceeds varbytes limit`);
  return value;
}

export function hexToBytes(value, name = "hex") {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) {
    fail(`${name} must be lowercase even-length hex`);
  }
  const result = new Uint8Array(value.length / 2);
  for (let i = 0; i < result.length; i += 1) result[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return result;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

export function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) if (left[i] !== right[i]) return false;
  return true;
}

export function networkTagFor(networkId) {
  if (typeof networkId !== "string" || !Object.prototype.hasOwnProperty.call(NETWORK_TAGS, networkId)) {
    fail(`networkId must be one of ${NETWORK_NAMES.join(", ")}`);
  }
  return NETWORK_TAGS[networkId];
}

export function networkIdForTag(tag) {
  assertU8(tag, "networkTag");
  if (tag > 2) fail(`networkTag ${tag} is reserved`);
  return NETWORK_NAMES[tag];
}

export function actionTagFor(actionKind) {
  if (!Object.prototype.hasOwnProperty.call(ACTION_TAGS, actionKind)) fail(`unknown actionKind ${actionKind}`);
  return ACTION_TAGS[actionKind];
}

export function actionKindForTag(tag) {
  assertU8(tag, "actionTag");
  if (tag > 1) fail(`actionTag ${tag} is reserved`);
  return ACTION_NAMES[tag];
}

export function roleTagFor(name, table, label) {
  if (!Object.prototype.hasOwnProperty.call(table, name)) fail(`unknown ${label} ${name}`);
  return table[name];
}

export function roleNameFor(tag, names, label) {
  assertU8(tag, `${label}Tag`);
  const name = names[tag];
  if (name === undefined) fail(`${label} tag ${tag} is reserved`);
  return name;
}

export class Writer {
  #parts = [];

  u8(value) {
    assertU8(value, "u8");
    this.#parts.push(Uint8Array.of(value));
  }

  u16(value) {
    assertU16(value, "u16");
    this.#parts.push(Uint8Array.of(value & 0xff, (value >>> 8) & 0xff));
  }

  u32(value) {
    assertU32(value, "u32");
    this.#parts.push(Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff));
  }

  u64(value, name = "u64") {
    let n = assertU64(value, name);
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i += 1) { out[i] = Number(n & 0xffn); n >>= 8n; }
    this.#parts.push(out);
  }

  i64(value, name = "i64") {
    let n = assertI64(value, name);
    if (n < 0n) n += 1n << 64n;
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i += 1) { out[i] = Number(n & 0xffn); n >>= 8n; }
    this.#parts.push(out);
  }

  bytes(value, name, length) {
    const bytes = value instanceof Uint8Array ? value : hexToBytes(value, name);
    if (bytes.length !== length) fail(`${name} must be exactly ${length} bytes`);
    this.#parts.push(bytes.slice());
  }

  varbytes(value, name) {
    const bytes = value instanceof Uint8Array ? value : hexToBytes(value, name);
    if (bytes.length > VARBYTES_MAX) fail(`${name} exceeds varbytes limit`);
    this.u16(bytes.length);
    this.#parts.push(bytes.slice());
  }

  finish() {
    const length = this.#parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of this.#parts) { result.set(part, offset); offset += part.length; }
    return result;
  }
}

export class Reader {
  #bytes;
  #offset = 0;

  constructor(value, name = "input") {
    if (!(value instanceof Uint8Array)) fail(`${name} must be Uint8Array`);
    this.#bytes = value;
  }

  get offset() { return this.#offset; }
  get remaining() { return this.#bytes.length - this.#offset; }

  need(length, name) {
    if (this.remaining < length) fail(`${name} is truncated at offset ${this.#offset}`);
  }

  u8(name = "u8") { this.need(1, name); return this.#bytes[this.#offset++]; }

  u16(name = "u16") {
    this.need(2, name);
    const value = this.#bytes[this.#offset] | (this.#bytes[this.#offset + 1] << 8);
    this.#offset += 2;
    return value;
  }

  u32(name = "u32") {
    this.need(4, name);
    const value = (this.#bytes[this.#offset]
      | (this.#bytes[this.#offset + 1] << 8)
      | (this.#bytes[this.#offset + 2] << 16)
      | (this.#bytes[this.#offset + 3] << 24)) >>> 0;
    this.#offset += 4;
    return value;
  }

  u64(name = "u64") {
    this.need(8, name);
    let value = 0n;
    for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(this.#bytes[this.#offset + i]);
    this.#offset += 8;
    return value.toString(10);
  }

  i64(name = "i64") {
    const unsigned = BigInt(this.u64(name));
    return (unsigned >= (1n << 63n) ? unsigned - (1n << 64n) : unsigned).toString(10);
  }

  bytes(length, name) {
    this.need(length, name);
    const result = this.#bytes.slice(this.#offset, this.#offset + length);
    this.#offset += length;
    return result;
  }

  varbytes(name) {
    const length = this.u16(`${name}.length`);
    if (length > VARBYTES_MAX) fail(`${name} exceeds varbytes limit`);
    return this.bytes(length, name);
  }

  done(name = "input") {
    if (this.remaining !== 0) fail(`${name} has ${this.remaining} trailing bytes`);
  }
}

export function asBytes(input, name = "input") {
  if (input instanceof Uint8Array) return input;
  if (typeof input === "string") return hexToBytes(input, name);
  fail(`${name} must be Uint8Array or lowercase hex`);
}

export function zeroHex(bytes) {
  return "00".repeat(bytes);
}

export function isZeroHex(value) {
  return /^0+$/.test(value);
}
