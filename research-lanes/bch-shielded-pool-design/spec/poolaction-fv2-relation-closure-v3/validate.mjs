// SPDX-License-Identifier: CC0-1.0
// PoolActionFv2 ABI-v3 structural relation-closure reference validator.
// This module is intentionally proof-rejecting and does not execute BCH VM code.

import crypto from "node:crypto";

export const RELATION_ID = "PoolActionFv2";
export const RELATION_VERSION = 2;
export const ABI_VERSION = 3;
export const UNSELECTED_PROOF_VERDICT = "REJECT_UNSELECTED_PROOF_SUITE";
export const MAX_RUNTIME_U64 = 0x7fffffffffffffffn;
export const TICKET_SATS = 10000000n;
export const MAX_SCRIPT_BYTES = 10000;
export const MAX_MONEY = 2100000000000000n;
export const MAX_CARRIER_COUNT = 483;

const ZERO32 = Buffer.alloc(32);
const ZERO8_HEX = "0000000000000000";
const TOOLCHAIN_LITERAL = "poolaction-fv2-structural-compiler-v3";
const STRUCTURAL_PROGRAM = Buffer.from("00000175020001750100", "hex");
const SEGMENT_FRAME_HEADER_BYTES = 18;
const NETWORK_TAGS = Object.freeze({ mainnet: 0, chipnet: 1, regtest: 2 });
const TAG_NETWORKS = Object.freeze(["mainnet", "chipnet", "regtest"]);
const ALLOWED_SOURCE_CLASSES = new Set([
  "CODEC_CONSTANT",
  "LOCK_SELECTED_EMBEDDED",
  "INTROSPECTED",
  "DERIVED_AND_CHECKED",
]);

export class PoolActionFv2Abi3Error extends Error {
  constructor(code, message, layer = "STRUCTURAL") {
    super(`${code}: ${message}`);
    this.name = "PoolActionFv2Abi3Error";
    this.code = code;
    this.layer = layer;
  }
}

function fail(code, message, layer) {
  throw new PoolActionFv2Abi3Error(code, message, layer);
}

function requireOk(condition, code, message, layer) {
  if (!condition) fail(code, message, layer);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireObject(value, name) {
  requireOk(isPlainObject(value), "ERR_TYPE", `${name} must be an object`, "SCHEMA");
  return value;
}

function requireExactKeys(value, keys, name) {
  requireObject(value, name);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  requireOk(
    JSON.stringify(actual) === JSON.stringify(expected),
    "ERR_SCHEMA_KEYS",
    `${name} keys must be exactly ${expected.join(",")}`,
    "SCHEMA",
  );
}

function requireArray(value, name) {
  requireOk(Array.isArray(value), "ERR_TYPE", `${name} must be an array`, "SCHEMA");
  return value;
}

export function hexToBytes(hex, name = "hex", expectedLength) {
  requireOk(typeof hex === "string", "ERR_HEX", `${name} must be a string`, "PARSER");
  requireOk(/^(?:[0-9a-f]{2})*$/.test(hex), "ERR_HEX", `${name} must be lowercase even hex`, "PARSER");
  const bytes = Buffer.from(hex, "hex");
  if (expectedLength !== undefined) {
    requireOk(bytes.length === expectedLength, "ERR_HEX_LENGTH", `${name} must be ${expectedLength} bytes`, "PARSER");
  }
  return bytes;
}

export function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

export function u8(value, name = "u8") {
  requireOk(Number.isInteger(value) && value >= 0 && value <= 0xff, "ERR_RANGE", `${name} outside u8`, "PARSER");
  return Buffer.from([value]);
}

export function u16be(value, name = "u16be") {
  requireOk(Number.isInteger(value) && value >= 0 && value <= 0xffff, "ERR_RANGE", `${name} outside u16`, "PARSER");
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

export function u32be(value, name = "u32be") {
  requireOk(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "ERR_RANGE", `${name} outside u32`, "PARSER");
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

export function u64le(value, name = "u64le") {
  requireOk(typeof value === "bigint" && value >= 0n && value <= MAX_RUNTIME_U64, "ERR_RUNTIME_U64", `${name} outside signed runtime u64`, "PARSER");
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(value);
  return out;
}

function readU16be(bytes, cursor, name) {
  requireOk(cursor + 2 <= bytes.length, "ERR_TRUNCATED", `${name} truncated`, "PARSER");
  return [bytes.readUInt16BE(cursor), cursor + 2];
}

function readU32be(bytes, cursor, name) {
  requireOk(cursor + 4 <= bytes.length, "ERR_TRUNCATED", `${name} truncated`, "PARSER");
  return [bytes.readUInt32BE(cursor), cursor + 4];
}

function readBytes(bytes, cursor, length, name) {
  requireOk(cursor + length <= bytes.length, "ERR_TRUNCATED", `${name} truncated`, "PARSER");
  return [bytes.subarray(cursor, cursor + length), cursor + length];
}

export function parseRuntimeU64LeHex(hex, name = "runtime integer") {
  const bytes = hexToBytes(hex, name, 8);
  const value = bytes.readBigUInt64LE();
  requireOk(value <= MAX_RUNTIME_U64, "ERR_RUNTIME_U64", `${name} exceeds 0x7fffffffffffffff`, "PARSER");
  return value;
}

export function runtimeU64LeHex(value, name = "runtime integer") {
  return bytesToHex(u64le(value, name));
}

function parseU32Runtime(hex, name) {
  const value = parseRuntimeU64LeHex(hex, name);
  requireOk(value <= 0xffffffffn, "ERR_U32_RUNTIME", `${name} exceeds u32`, "PARSER");
  return Number(value);
}

function parseExactRuntimeBytes(bytes, name) {
  requireOk(Buffer.isBuffer(bytes) && bytes.length === 8, "ERR_RUNTIME_U64", `${name} must be eight bytes`, "PARSER");
  const value = bytes.readBigUInt64LE();
  requireOk(value <= MAX_RUNTIME_U64, "ERR_RUNTIME_U64", `${name} exceeds 0x7fffffffffffffff`, "PARSER");
  return value;
}

export function lp(bytes, name = "LP payload") {
  const value = Buffer.from(bytes);
  requireOk(value.length <= 0xffffffff, "ERR_LP_LENGTH", `${name} too long`, "PARSER");
  return Buffer.concat([u32be(value.length, `${name} length`), value]);
}

function readLp(bytes, cursor, name) {
  let length;
  [length, cursor] = readU32be(bytes, cursor, `${name} length`);
  let payload;
  [payload, cursor] = readBytes(bytes, cursor, length, name);
  return [payload, cursor];
}

export function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

export function hash160(bytes) {
  return crypto.createHash("ripemd160").update(sha256(bytes)).digest();
}

export function domainBytes(domain) {
  requireOk(typeof domain === "string" && domain.endsWith("/v3"), "ERR_DOMAIN", `domain must end /v3: ${domain}`, "CODEC");
  return Buffer.concat([Buffer.from(domain, "ascii"), Buffer.from([0])]);
}

function domainHash(domain, ...parts) {
  return sha256(Buffer.concat([domainBytes(domain), ...parts.map((part) => lp(part))]));
}

function equalBytes(actual, expected, code, name, layer = "STRUCTURAL") {
  requireOk(Buffer.isBuffer(actual) && Buffer.isBuffer(expected) && actual.equals(expected), code, `${name} mismatch`, layer);
}

export function encodeMinimalPush(value) {
  const payload = Buffer.from(value);
  if (payload.length === 0) return Buffer.from([0x00]);
  if (payload.length === 1 && payload[0] === 0x81) return Buffer.from([0x4f]);
  if (payload.length === 1 && payload[0] >= 1 && payload[0] <= 16) return Buffer.from([0x50 + payload[0]]);
  if (payload.length <= 75) return Buffer.concat([Buffer.from([payload.length]), payload]);
  if (payload.length <= 0xff) return Buffer.concat([Buffer.from([0x4c, payload.length]), payload]);
  if (payload.length <= 0xffff) {
    const length = Buffer.alloc(2);
    length.writeUInt16LE(payload.length);
    return Buffer.concat([Buffer.from([0x4d]), length, payload]);
  }
  fail("ERR_PUSH_LENGTH", "minimal push payload exceeds PUSHDATA2 range", "PARSER");
}

export function parseMinimalPush(bytes, cursor = 0, name = "push") {
  requireOk(cursor < bytes.length, "ERR_TRUNCATED", `${name} opcode missing`, "PARSER");
  const start = cursor;
  const opcode = bytes[cursor++];
  let payload;
  if (opcode === 0x00) payload = Buffer.alloc(0);
  else if (opcode === 0x4f) payload = Buffer.from([0x81]);
  else if (opcode >= 0x51 && opcode <= 0x60) payload = Buffer.from([opcode - 0x50]);
  else {
    let length;
    if (opcode >= 1 && opcode <= 75) length = opcode;
    else if (opcode === 0x4c) {
      requireOk(cursor < bytes.length, "ERR_TRUNCATED", `${name} PUSHDATA1 length missing`, "PARSER");
      length = bytes[cursor++];
    } else if (opcode === 0x4d) {
      requireOk(cursor + 2 <= bytes.length, "ERR_TRUNCATED", `${name} PUSHDATA2 length missing`, "PARSER");
      length = bytes.readUInt16LE(cursor);
      cursor += 2;
    } else {
      fail("ERR_PUSH_OPCODE", `${name} has non-push opcode 0x${opcode.toString(16)}`, "PARSER");
    }
    [payload, cursor] = readBytes(bytes, cursor, length, name);
  }
  const raw = bytes.subarray(start, cursor);
  equalBytes(raw, encodeMinimalPush(payload), "ERR_NON_MINIMAL_PUSH", name, "PARSER");
  return { payload: Buffer.from(payload), start, end: cursor, raw: Buffer.from(raw) };
}

function requireNoTrailing(bytes, cursor, name) {
  requireOk(cursor === bytes.length, "ERR_TRAILING", `${name} has trailing bytes`, "PARSER");
}

function roleTagValue(roleClass) {
  if (roleClass === "STATE") return 0;
  if (roleClass === "CARRIER") return 1;
  fail("ERR_ROLE", `unknown role class ${roleClass}`, "CODEC");
}

function roleClassFromTag(tag) {
  if (tag === 0) return "STATE";
  if (tag === 1) return "CARRIER";
  fail("ERR_ROLE", `unknown role tag ${tag}`, "PARSER");
}

export function encodeRoleInstanceV3({ roleClass, ordinal, fixedInputIndex, fixedOutputIndex }) {
  const tag = roleTagValue(roleClass);
  return Buffer.concat([
    Buffer.from("P3RI", "ascii"),
    u16be(3),
    u8(tag),
    u32be(ordinal, "role ordinal"),
    u32be(fixedInputIndex, "fixed input index"),
    u32be(fixedOutputIndex, "fixed output index"),
  ]);
}

export function parseRoleInstanceV3(bytes) {
  const value = Buffer.from(bytes);
  requireOk(value.length === 19, "ERR_ROLE_LENGTH", "RoleInstanceV3 must be 19 bytes", "PARSER");
  equalBytes(value.subarray(0, 4), Buffer.from("P3RI"), "ERR_ROLE_MAGIC", "RoleInstanceV3 magic", "PARSER");
  const version = value.readUInt16BE(4);
  requireOk(version === 3, "ERR_ROLE_VERSION", "RoleInstanceV3 version", "PARSER");
  const roleClass = roleClassFromTag(value[6]);
  const ordinal = value.readUInt32BE(7);
  const fixedInputIndex = value.readUInt32BE(11);
  const fixedOutputIndex = value.readUInt32BE(15);
  if (roleClass === "STATE") {
    requireOk(ordinal === 0 && fixedInputIndex === 0 && fixedOutputIndex === 0, "ERR_ROLE_TOPOLOGY", "state role instance is not fixed at zero", "STRUCTURAL");
  } else {
    requireOk(fixedInputIndex === ordinal + 1 && fixedOutputIndex === ordinal + 1, "ERR_ROLE_TOPOLOGY", "carrier role instance is not ordinal-fixed", "STRUCTURAL");
  }
  return { bytes: value, roleClass, roleTag: value[6], ordinal, fixedInputIndex, fixedOutputIndex };
}

function encodeRoleFromManifest(roleClass, ordinal) {
  if (roleClass === "STATE") return encodeRoleInstanceV3({ roleClass, ordinal: 0, fixedInputIndex: 0, fixedOutputIndex: 0 });
  return encodeRoleInstanceV3({ roleClass, ordinal, fixedInputIndex: ordinal + 1, fixedOutputIndex: ordinal + 1 });
}

function networkTag(networkId) {
  requireOk(Object.hasOwn(NETWORK_TAGS, networkId), "ERR_NETWORK", "networkId must be mainnet, chipnet, or regtest", "CODEC");
  return NETWORK_TAGS[networkId];
}

function checkedDigestHex(value, name) {
  return hexToBytes(value, name, 32);
}

function requireMoney(value, name) {
  requireOk(value >= 0n && value <= MAX_MONEY, "ERR_MONEY_RANGE", `${name} outside MoneyRange`, "STRUCTURAL");
  return value;
}

function checkedMoneyAdd(left, right, name) {
  requireMoney(left, `${name} left`);
  requireMoney(right, `${name} right`);
  const total = left + right;
  requireMoney(total, name);
  return total;
}

function canonicalRoleMapBytes(carrierCount) {
  return Buffer.concat([
    u32be(0), u32be(carrierCount + 1), u32be(0), u8(0), u32be(0), u8(1), u32be(carrierCount + 1),
    u32be(0), u32be(carrierCount + 1), u32be(0), u8(1), u32be(carrierCount + 1), u8(1), u32be(carrierCount + 2),
  ]);
}

function canonicalCarrierLayoutBytes(spec, carrierCount) {
  const parts = [];
  for (let i = 0; i < carrierCount; i += 1) {
    const row = spec.carrierLayout[i];
    parts.push(u32be(i), u32be(i + 1), u32be(i + 1), hexToBytes(row.expectedValueSatsLeHex, `carrierLayout[${i}].expectedValueSatsLeHex`, 8));
  }
  return Buffer.concat(parts);
}

function statusByteFromHex(hex) {
  const bytes = hexToBytes(hex, "proofSuiteStatusHex", 1);
  requireOk(bytes[0] === 0 || bytes[0] === 1, "ERR_PROOF_SUITE", "proof suite status must be 00 or 01", "STRUCTURAL");
  return bytes[0];
}

function validateStatusDigestPair(status, digest, name) {
  const zero = digest.equals(ZERO32);
  requireOk((status === 0 && zero) || (status === 1 && !zero), "ERR_PROOF_SUITE", `${name} status/digest pairing`, "STRUCTURAL");
}

function strictManifestSpec(spec) {
  requireExactKeys(spec, [
    "networkId", "protocolTemplateDigestHex", "poolInstanceIdHex", "preExistingAnchorDigestHex", "genesisAncestryDigestHex",
    "stateCategoryWireHex", "stateCarrierBaseSatsLeHex", "maxLifetimeDepositsLeHex", "feePolicyMaxSatsLeHex",
    "proofSuiteStatusHex", "proofSuiteManifestDigestHex", "carrierCountLeHex", "carrierLayout",
  ], "manifest spec");
  const n = parseU32Runtime(spec.carrierCountLeHex, "manifest carrierCountLeHex");
  requireOk(n >= 1 && n <= MAX_CARRIER_COUNT, "ERR_CARRIER_COUNT", "carrier count must be in 1..483", "STRUCTURAL");
  requireArray(spec.carrierLayout, "manifest carrierLayout");
  requireOk(spec.carrierLayout.length === n, "ERR_CARRIER_LAYOUT", "carrier layout count mismatch", "STRUCTURAL");
  for (let i = 0; i < n; i += 1) {
    const row = spec.carrierLayout[i];
    requireExactKeys(row, ["ordinalLeHex", "inputIndexLeHex", "outputIndexLeHex", "expectedValueSatsLeHex"], `carrierLayout[${i}]`);
    requireOk(parseU32Runtime(row.ordinalLeHex, `carrierLayout[${i}].ordinalLeHex`) === i, "ERR_CARRIER_LAYOUT", `carrier ${i} ordinal`, "STRUCTURAL");
    requireOk(parseU32Runtime(row.inputIndexLeHex, `carrierLayout[${i}].inputIndexLeHex`) === i + 1, "ERR_CARRIER_LAYOUT", `carrier ${i} input index`, "STRUCTURAL");
    requireOk(parseU32Runtime(row.outputIndexLeHex, `carrierLayout[${i}].outputIndexLeHex`) === i + 1, "ERR_CARRIER_LAYOUT", `carrier ${i} output index`, "STRUCTURAL");
    requireMoney(parseRuntimeU64LeHex(row.expectedValueSatsLeHex, `carrierLayout[${i}].expectedValueSatsLeHex`), `carrier ${i} expected value`);
  }
  const base = requireMoney(parseRuntimeU64LeHex(spec.stateCarrierBaseSatsLeHex, "stateCarrierBaseSatsLeHex"), "stateCarrierBaseSats");
  const capacity = parseRuntimeU64LeHex(spec.maxLifetimeDepositsLeHex, "maxLifetimeDepositsLeHex");
  requireOk(capacity >= 1n, "ERR_CAPACITY", "maxLifetimeDeposits must be at least one", "STRUCTURAL");
  const reserveBound = capacity * TICKET_SATS;
  requireOk(reserveBound <= MAX_MONEY && base <= MAX_MONEY - reserveBound, "ERR_CAPACITY", "base plus lifetime reserve exceeds MoneyRange", "STRUCTURAL");
  requireMoney(parseRuntimeU64LeHex(spec.feePolicyMaxSatsLeHex, "feePolicyMaxSatsLeHex"), "feePolicyMaxSats");
  const status = statusByteFromHex(spec.proofSuiteStatusHex);
  const suiteDigest = checkedDigestHex(spec.proofSuiteManifestDigestHex, "proofSuiteManifestDigestHex");
  validateStatusDigestPair(status, suiteDigest, "manifest");
  checkedDigestHex(spec.protocolTemplateDigestHex, "protocolTemplateDigestHex");
  checkedDigestHex(spec.poolInstanceIdHex, "poolInstanceIdHex");
  checkedDigestHex(spec.preExistingAnchorDigestHex, "preExistingAnchorDigestHex");
  checkedDigestHex(spec.genesisAncestryDigestHex, "genesisAncestryDigestHex");
  checkedDigestHex(spec.stateCategoryWireHex, "stateCategoryWireHex");
  networkTag(spec.networkId);
  return { n, base, capacity, status, suiteDigest };
}

function identityPartsFromSpec(spec, checked) {
  return {
    network: networkTag(spec.networkId),
    protocolTemplateDigest: checkedDigestHex(spec.protocolTemplateDigestHex, "protocolTemplateDigestHex"),
    preExistingAnchorDigest: checkedDigestHex(spec.preExistingAnchorDigestHex, "preExistingAnchorDigestHex"),
    stateCategoryWire: checkedDigestHex(spec.stateCategoryWireHex, "stateCategoryWireHex"),
    base: checked.base,
    capacity: checked.capacity,
    fee: parseRuntimeU64LeHex(spec.feePolicyMaxSatsLeHex, "feePolicyMaxSatsLeHex"),
    status: checked.status,
    suiteDigest: checked.suiteDigest,
    carrierLayout: canonicalCarrierLayoutBytes(spec, checked.n),
    roleMaps: canonicalRoleMapBytes(checked.n),
    carrierCount: checked.n,
  };
}

export function encodePoolIdentityConfigV3(spec) {
  const checked = strictManifestSpec(spec);
  const parts = identityPartsFromSpec(spec, checked);
  const bytes = Buffer.concat([
    Buffer.from("P3PI"), u16be(3), u8(parts.network), u8(0), parts.protocolTemplateDigest,
    parts.preExistingAnchorDigest, parts.stateCategoryWire, u64le(TICKET_SATS), u64le(parts.base),
    u64le(parts.capacity), u64le(parts.fee), u8(parts.status), parts.suiteDigest, u8(1), u32be(parts.carrierCount),
    parts.carrierLayout, parts.roleMaps,
  ]);
  requireOk(bytes.length === 218 + (20 * checked.n), "ERR_POOL_IDENTITY", "P3PI byte length", "CODEC");
  return bytes;
}

export function derivePoolInstanceIdV3(spec) {
  return domainHash("PoolActionFv2/pool-instance/v3", encodePoolIdentityConfigV3(spec));
}

export function encodeDeploymentManifestV3Core(spec) {
  const checked = strictManifestSpec(spec);
  const poolIdentityConfig = encodePoolIdentityConfigV3(spec);
  equalBytes(checkedDigestHex(spec.poolInstanceIdHex, "poolInstanceIdHex"), domainHash("PoolActionFv2/pool-instance/v3", poolIdentityConfig), "ERR_POOL_IDENTITY", "manifest poolInstanceId", "STRUCTURAL");
  const core = Buffer.concat([
    Buffer.from("P3DM", "ascii"), u16be(3), u8(networkTag(spec.networkId)), u8(0),
    checkedDigestHex(spec.protocolTemplateDigestHex, "protocolTemplateDigestHex"),
    checkedDigestHex(spec.poolInstanceIdHex, "poolInstanceIdHex"),
    checkedDigestHex(spec.preExistingAnchorDigestHex, "preExistingAnchorDigestHex"),
    checkedDigestHex(spec.genesisAncestryDigestHex, "genesisAncestryDigestHex"),
    checkedDigestHex(spec.stateCategoryWireHex, "stateCategoryWireHex"), u64le(TICKET_SATS), u64le(checked.base),
    u64le(checked.capacity), u64le(parseRuntimeU64LeHex(spec.feePolicyMaxSatsLeHex, "feePolicyMaxSatsLeHex")),
    u8(checked.status), checked.suiteDigest, u8(1), u32be(checked.n), canonicalCarrierLayoutBytes(spec, checked.n), canonicalRoleMapBytes(checked.n),
  ]);
  requireOk(core.length === 282 + (20 * checked.n), "ERR_MANIFEST_LENGTH", "P3DM byte length", "CODEC");
  requireOk(core.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "manifest core exceeds structural script limit", "STRUCTURAL");
  return core;
}

export function parseDeploymentManifestV3Core(input) {
  const bytes = Buffer.from(input);
  requireOk(bytes.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "manifest core exceeds structural script limit", "PARSER");
  let cursor = 0;
  let magic; [magic, cursor] = readBytes(bytes, cursor, 4, "manifest magic");
  equalBytes(magic, Buffer.from("P3DM"), "ERR_MANIFEST_MAGIC", "manifest magic", "PARSER");
  let version; [version, cursor] = readU16be(bytes, cursor, "manifest version");
  requireOk(version === 3, "ERR_MANIFEST_VERSION", "manifest ABI version", "PARSER");
  let tag; [tag, cursor] = readBytes(bytes, cursor, 1, "manifest network tag");
  requireOk(tag[0] <= 2, "ERR_NETWORK", "manifest network tag", "PARSER");
  let reserved; [reserved, cursor] = readBytes(bytes, cursor, 1, "manifest reserved");
  requireOk(reserved[0] === 0, "ERR_RESERVED", "manifest reserved byte", "PARSER");
  const names = ["protocolTemplateDigest", "poolInstanceId", "preExistingAnchorDigest", "genesisAncestryDigest", "stateCategoryWire"];
  const digests = {};
  for (const name of names) { let value; [value, cursor] = readBytes(bytes, cursor, 32, `manifest ${name}`); digests[name] = Buffer.from(value); }
  let ticketBytes; [ticketBytes, cursor] = readBytes(bytes, cursor, 8, "manifest ticket");
  requireOk(parseExactRuntimeBytes(ticketBytes, "manifest ticket") === TICKET_SATS, "ERR_TICKET", "manifest ticket is not fixed", "PARSER");
  let baseBytes; [baseBytes, cursor] = readBytes(bytes, cursor, 8, "manifest state base");
  const stateCarrierBaseSats = requireMoney(parseExactRuntimeBytes(baseBytes, "manifest state base"), "manifest state base");
  let capacityBytes; [capacityBytes, cursor] = readBytes(bytes, cursor, 8, "manifest lifetime capacity");
  const maxLifetimeDeposits = parseExactRuntimeBytes(capacityBytes, "manifest lifetime capacity");
  requireOk(maxLifetimeDeposits >= 1n, "ERR_CAPACITY", "manifest lifetime capacity", "PARSER");
  const reserveBound = maxLifetimeDeposits * TICKET_SATS;
  requireOk(reserveBound <= MAX_MONEY && stateCarrierBaseSats <= MAX_MONEY - reserveBound, "ERR_CAPACITY", "manifest base/capacity MoneyRange", "PARSER");
  let feeBytes; [feeBytes, cursor] = readBytes(bytes, cursor, 8, "manifest fee cap");
  const feePolicyMaxSats = requireMoney(parseExactRuntimeBytes(feeBytes, "manifest fee cap"), "manifest fee cap");
  let suiteStatusBytes; [suiteStatusBytes, cursor] = readBytes(bytes, cursor, 1, "manifest proof suite status");
  const suiteStatus = suiteStatusBytes[0];
  requireOk(suiteStatus === 0 || suiteStatus === 1, "ERR_PROOF_SUITE", "manifest proof suite status", "PARSER");
  let suiteDigest; [suiteDigest, cursor] = readBytes(bytes, cursor, 32, "manifest proof suite digest");
  validateStatusDigestPair(suiteStatus, suiteDigest, "manifest");
  let noUpgrade; [noUpgrade, cursor] = readBytes(bytes, cursor, 1, "manifest no-upgrade");
  requireOk(noUpgrade[0] === 1, "ERR_NO_UPGRADE", "manifest no-upgrade byte", "PARSER");
  let carrierCount; [carrierCount, cursor] = readU32be(bytes, cursor, "manifest carrier count");
  requireOk(carrierCount >= 1 && carrierCount <= MAX_CARRIER_COUNT, "ERR_CARRIER_COUNT", "manifest carrier count", "PARSER");
  const carrierLayout = [];
  const carrierLayoutBytes = [];
  for (let i = 0; i < carrierCount; i += 1) {
    let ordinal; let inputIndex; let outputIndex; let expectedValueBytes;
    [ordinal, cursor] = readU32be(bytes, cursor, `carrier ${i} ordinal`);
    [inputIndex, cursor] = readU32be(bytes, cursor, `carrier ${i} input index`);
    [outputIndex, cursor] = readU32be(bytes, cursor, `carrier ${i} output index`);
    [expectedValueBytes, cursor] = readBytes(bytes, cursor, 8, `carrier ${i} expected value`);
    requireOk(ordinal === i && inputIndex === i + 1 && outputIndex === i + 1, "ERR_CARRIER_LAYOUT", `carrier ${i} layout is not canonical`, "PARSER");
    const expectedValueSats = requireMoney(parseExactRuntimeBytes(expectedValueBytes, `carrier ${i} expected value`), `carrier ${i} expected value`);
    carrierLayout.push({ ordinal, inputIndex, outputIndex, expectedValueSats });
    carrierLayoutBytes.push(u32be(ordinal), u32be(inputIndex), u32be(outputIndex), Buffer.from(expectedValueBytes));
  }
  const readRoleMap = (action) => {
    let stateInputIndex; let externalInputIndex; let stateOutputIndex; let payoutPresent; let payoutOutputIndex; let changeOptional; let changeOutputIndex;
    [stateInputIndex, cursor] = readU32be(bytes, cursor, `${action} state input`);
    [externalInputIndex, cursor] = readU32be(bytes, cursor, `${action} external input`);
    [stateOutputIndex, cursor] = readU32be(bytes, cursor, `${action} state output`);
    let flag; [flag, cursor] = readBytes(bytes, cursor, 1, `${action} payout present`); payoutPresent = flag[0];
    [payoutOutputIndex, cursor] = readU32be(bytes, cursor, `${action} payout index`);
    [flag, cursor] = readBytes(bytes, cursor, 1, `${action} change optional`); changeOptional = flag[0];
    [changeOutputIndex, cursor] = readU32be(bytes, cursor, `${action} change index`);
    const expected = action === "deposit" ? [0, carrierCount + 1, 0, 0, 0, 1, carrierCount + 1] : [0, carrierCount + 1, 0, 1, carrierCount + 1, 1, carrierCount + 2];
    const actual = [stateInputIndex, externalInputIndex, stateOutputIndex, payoutPresent, payoutOutputIndex, changeOptional, changeOutputIndex];
    requireOk(JSON.stringify(actual) === JSON.stringify(expected), "ERR_ROLE_MAP", `${action} role map is not fixed`, "PARSER");
    return { stateInputIndex, externalInputIndex, stateOutputIndex, payoutPresent, payoutOutputIndex, changeOptional, changeOutputIndex };
  };
  const depositRoleMap = readRoleMap("deposit");
  const withdrawalRoleMap = readRoleMap("withdrawal");
  requireNoTrailing(bytes, cursor, "manifest core");
  requireOk(bytes.length === 282 + (20 * carrierCount), "ERR_MANIFEST_LENGTH", "manifest core exact length", "PARSER");
  const poolIdentityConfig = Buffer.concat([
    Buffer.from("P3PI"), u16be(3), Buffer.from([tag[0], 0]), digests.protocolTemplateDigest, digests.preExistingAnchorDigest,
    digests.stateCategoryWire, u64le(TICKET_SATS), u64le(stateCarrierBaseSats), u64le(maxLifetimeDeposits), u64le(feePolicyMaxSats),
    u8(suiteStatus), Buffer.from(suiteDigest), u8(1), u32be(carrierCount), Buffer.concat(carrierLayoutBytes), canonicalRoleMapBytes(carrierCount),
  ]);
  requireOk(poolIdentityConfig.length === 218 + (20 * carrierCount), "ERR_POOL_IDENTITY", "P3PI byte length", "PARSER");
  const recomputedPoolId = domainHash("PoolActionFv2/pool-instance/v3", poolIdentityConfig);
  equalBytes(digests.poolInstanceId, recomputedPoolId, "ERR_POOL_IDENTITY", "manifest poolInstanceId", "STRUCTURAL");
  const core = Buffer.from(bytes);
  return {
    core, networkId: TAG_NETWORKS[tag[0]], networkTag: tag[0], ...digests,
    poolIdentityConfig, stateCarrierBaseSats, maxLifetimeDeposits, feePolicyMaxSats,
    proofSuiteStatus: suiteStatus === 0 ? "UNSELECTED" : "SELECTED", proofSuiteStatusByte: suiteStatus,
    proofSuiteManifestDigest: Buffer.from(suiteDigest), noUpgrade: true, carrierCount, carrierLayout,
    depositRoleMap, withdrawalRoleMap, deploymentCommitment: domainHash("PoolActionFv2/deployment/v3", core),
  };
}

export function parsePoolIdentityConfigV3(input) {
  const bytes = Buffer.from(input);
  let cursor = 0;
  let magic; [magic, cursor] = readBytes(bytes, cursor, 4, "pool identity magic");
  equalBytes(magic, Buffer.from("P3PI"), "ERR_POOL_IDENTITY", "pool identity magic", "PARSER");
  let version; [version, cursor] = readU16be(bytes, cursor, "pool identity version");
  requireOk(version === 3, "ERR_POOL_IDENTITY", "pool identity version", "PARSER");
  let network; [network, cursor] = readBytes(bytes, cursor, 1, "pool identity network");
  requireOk(network[0] <= 2, "ERR_NETWORK", "pool identity network", "PARSER");
  let reserved; [reserved, cursor] = readBytes(bytes, cursor, 1, "pool identity reserved");
  requireOk(reserved[0] === 0, "ERR_RESERVED", "pool identity reserved", "PARSER");
  let protocolTemplateDigest; let preExistingAnchorDigest; let stateCategoryWire;
  [protocolTemplateDigest, cursor] = readBytes(bytes, cursor, 32, "pool identity protocol template");
  [preExistingAnchorDigest, cursor] = readBytes(bytes, cursor, 32, "pool identity anchor");
  [stateCategoryWire, cursor] = readBytes(bytes, cursor, 32, "pool identity category");
  let ticket; [ticket, cursor] = readBytes(bytes, cursor, 8, "pool identity ticket");
  requireOk(parseExactRuntimeBytes(ticket, "pool identity ticket") === TICKET_SATS, "ERR_TICKET", "pool identity ticket", "PARSER");
  let base; [base, cursor] = readBytes(bytes, cursor, 8, "pool identity base");
  const stateCarrierBaseSats = requireMoney(parseExactRuntimeBytes(base, "pool identity base"), "pool identity base");
  let capacity; [capacity, cursor] = readBytes(bytes, cursor, 8, "pool identity capacity");
  const maxLifetimeDeposits = parseExactRuntimeBytes(capacity, "pool identity capacity");
  requireOk(maxLifetimeDeposits >= 1n, "ERR_CAPACITY", "pool identity capacity", "PARSER");
  let fee; [fee, cursor] = readBytes(bytes, cursor, 8, "pool identity fee");
  const feePolicyMaxSats = requireMoney(parseExactRuntimeBytes(fee, "pool identity fee"), "pool identity fee");
  const reserveBound = maxLifetimeDeposits * TICKET_SATS;
  requireOk(reserveBound <= MAX_MONEY && stateCarrierBaseSats <= MAX_MONEY - reserveBound, "ERR_CAPACITY", "pool identity base/capacity", "PARSER");
  let status; [status, cursor] = readBytes(bytes, cursor, 1, "pool identity suite status");
  requireOk(status[0] === 0 || status[0] === 1, "ERR_PROOF_SUITE", "pool identity suite status", "PARSER");
  let suiteDigest; [suiteDigest, cursor] = readBytes(bytes, cursor, 32, "pool identity suite digest");
  validateStatusDigestPair(status[0], suiteDigest, "pool identity");
  let noUpgrade; [noUpgrade, cursor] = readBytes(bytes, cursor, 1, "pool identity no-upgrade");
  requireOk(noUpgrade[0] === 1, "ERR_NO_UPGRADE", "pool identity no-upgrade", "PARSER");
  let carrierCount; [carrierCount, cursor] = readU32be(bytes, cursor, "pool identity carrier count");
  requireOk(carrierCount >= 1 && carrierCount <= MAX_CARRIER_COUNT, "ERR_CARRIER_COUNT", "pool identity carrier count", "PARSER");
  const carrierLayout = [];
  for (let i = 0; i < carrierCount; i += 1) {
    let ordinal; let inputIndex; let outputIndex; let value;
    [ordinal, cursor] = readU32be(bytes, cursor, `pool identity carrier ${i} ordinal`);
    [inputIndex, cursor] = readU32be(bytes, cursor, `pool identity carrier ${i} input index`);
    [outputIndex, cursor] = readU32be(bytes, cursor, `pool identity carrier ${i} output index`);
    [value, cursor] = readBytes(bytes, cursor, 8, `pool identity carrier ${i} value`);
    requireOk(ordinal === i && inputIndex === i + 1 && outputIndex === i + 1, "ERR_CARRIER_LAYOUT", `pool identity carrier ${i} layout`, "PARSER");
    carrierLayout.push({ ordinal, inputIndex, outputIndex, expectedValueSats: requireMoney(parseExactRuntimeBytes(value, `pool identity carrier ${i} value`), `pool identity carrier ${i} value`) });
  }
  const expectedMaps = canonicalRoleMapBytes(carrierCount);
  let roleMaps; [roleMaps, cursor] = readBytes(bytes, cursor, expectedMaps.length, "pool identity role maps");
  equalBytes(roleMaps, expectedMaps, "ERR_ROLE_MAP", "pool identity role maps", "PARSER");
  requireNoTrailing(bytes, cursor, "pool identity config");
  requireOk(bytes.length === 218 + (20 * carrierCount), "ERR_POOL_IDENTITY", "P3PI exact length", "PARSER");
  return {
    bytes, networkTag: network[0], networkId: TAG_NETWORKS[network[0]], protocolTemplateDigest: Buffer.from(protocolTemplateDigest),
    preExistingAnchorDigest: Buffer.from(preExistingAnchorDigest), stateCategoryWire: Buffer.from(stateCategoryWire), stateCarrierBaseSats,
    maxLifetimeDeposits, feePolicyMaxSats, proofSuiteStatusByte: status[0], proofSuiteManifestDigest: Buffer.from(suiteDigest),
    carrierCount, carrierLayout, poolInstanceId: domainHash("PoolActionFv2/pool-instance/v3", bytes),
  };
}

export function encodeTokenObservationV3(raw, role, stateCategoryWire) {
  requireExactKeys(raw, ["categoryWireHex", "commitmentHex", "amountLeHex"], `${role} token projection`);
  const category = hexToBytes(raw.categoryWireHex, `${role}.categoryWireHex`);
  const commitment = hexToBytes(raw.commitmentHex, `${role}.commitmentHex`);
  const amount = hexToBytes(raw.amountLeHex, `${role}.amountLeHex`, 8);
  requireOk(parseExactRuntimeBytes(amount, `${role}.amountLeHex`) === 0n, "ERR_TOKEN_AMOUNT", `${role} token amount must be zero`, "STRUCTURAL");
  if (role === "STATE_SOURCE" || role === "STATE_SUCCESSOR") {
    requireOk(category.length === 33 && commitment.length === 128, "ERR_TOKEN_LANGUAGE", `${role} must expose the 33-byte mutable-NFT-zero category observation`, "STRUCTURAL");
    equalBytes(category.subarray(0, 32), stateCategoryWire, "ERR_TOKEN_CATEGORY", `${role} base category`, "STRUCTURAL");
    requireOk(category[32] === 0x01, "ERR_TOKEN_CATEGORY", `${role} mutable capability suffix`, "STRUCTURAL");
    return Buffer.concat([u8(1), u16be(33), category, u16be(128), commitment, amount]);
  }
  requireOk(category.length === 0 && commitment.length === 0, "ERR_TOKEN_LANGUAGE", `${role} must be token-free NONE`, "STRUCTURAL");
  return Buffer.concat([u8(0), u16be(0), u16be(0), amount]);
}

function parseStateCodec(commitment, expectedPoolId, name) {
  const bytes = Buffer.from(commitment);
  requireOk(bytes.length === 128, "ERR_STATE_CODEC", `${name} state commitment length`, "STRUCTURAL");
  equalBytes(bytes.subarray(0, 4), Buffer.from("PAF1"), "ERR_STATE_CODEC", `${name} magic`, "STRUCTURAL");
  requireOk(bytes.readUInt16LE(4) === 1, "ERR_STATE_CODEC", `${name} codec version`, "STRUCTURAL");
  requireOk(bytes[6] === 0 && bytes[7] === 0, "ERR_STATE_CODEC", `${name} reserved`, "STRUCTURAL");
  const sequence = parseExactRuntimeBytes(bytes.subarray(8, 16), `${name} sequence`);
  const depositCount = parseExactRuntimeBytes(bytes.subarray(16, 24), `${name} depositCount`);
  const withdrawalCount = parseExactRuntimeBytes(bytes.subarray(24, 32), `${name} withdrawalCount`);
  requireOk(withdrawalCount <= depositCount, "ERR_STATE_CODEC", `${name} withdrawal count exceeds deposit count`, "STRUCTURAL");
  equalBytes(bytes.subarray(32, 64), expectedPoolId, "ERR_STATE_POOL", `${name} pool identity`, "STRUCTURAL");
  return {
    bytes,
    sequence,
    depositCount,
    withdrawalCount,
    poolInstanceId: bytes.subarray(32, 64),
    noteRoot: bytes.subarray(64, 96),
    nullifierRoot: bytes.subarray(96, 128),
  };
}

function checkStateInvariants(state, stateValueSats, manifest, name) {
  requireMoney(stateValueSats, `${name} state value`);
  requireOk(state.withdrawalCount <= state.depositCount && state.depositCount <= manifest.maxLifetimeDeposits, "ERR_STATE_INVARIANT", `${name} state counts`, "STRUCTURAL");
  const outstanding = state.depositCount - state.withdrawalCount;
  const reserve = outstanding * TICKET_SATS;
  requireOk(reserve <= MAX_MONEY && manifest.stateCarrierBaseSats <= MAX_MONEY - reserve, "ERR_STATE_INVARIANT", `${name} reserve overflow`, "STRUCTURAL");
  requireOk(stateValueSats === manifest.stateCarrierBaseSats + reserve, "ERR_STATE_INVARIANT", `${name} state value equation`, "STRUCTURAL");
}

function checkStateTransition(oldState, newState, action, manifest) {
  requireOk(oldState.sequence < MAX_RUNTIME_U64, "ERR_STATE_TRANSITION", "state sequence overflows", "STRUCTURAL");
  requireOk(newState.sequence === oldState.sequence + 1n, "ERR_STATE_TRANSITION", "state sequence transition", "STRUCTURAL");
  if (action === "DEPOSIT") {
    requireOk(oldState.depositCount < manifest.maxLifetimeDeposits && newState.depositCount === oldState.depositCount + 1n, "ERR_STATE_TRANSITION", "deposit count transition", "STRUCTURAL");
    requireOk(newState.withdrawalCount === oldState.withdrawalCount, "ERR_STATE_TRANSITION", "deposit withdrawal count transition", "STRUCTURAL");
    equalBytes(newState.nullifierRoot, oldState.nullifierRoot, "ERR_STATE_TRANSITION", "deposit nullifier root", "STRUCTURAL");
  } else {
    requireOk(oldState.withdrawalCount < MAX_RUNTIME_U64 && newState.withdrawalCount === oldState.withdrawalCount + 1n, "ERR_STATE_TRANSITION", "withdrawal count transition", "STRUCTURAL");
    requireOk(newState.depositCount === oldState.depositCount, "ERR_STATE_TRANSITION", "withdrawal deposit count transition", "STRUCTURAL");
    equalBytes(newState.noteRoot, oldState.noteRoot, "ERR_STATE_TRANSITION", "withdrawal note root", "STRUCTURAL");
  }
}

export function encodeSegmentFrameV3({ ordinal, inputIndex, payload }) {
  const body = Buffer.from(payload);
  requireOk(body.length > 0, "ERR_FRAME_PAYLOAD", "carrier payload must be nonempty", "STRUCTURAL");
  requireOk(body.length <= MAX_SCRIPT_BYTES - SEGMENT_FRAME_HEADER_BYTES, "ERR_SCRIPT_SIZE", "carrier payload exceeds structural frame limit", "STRUCTURAL");
  const frame = Buffer.concat([Buffer.from("P3SG"), u16be(3), u32be(ordinal), u32be(inputIndex), u32be(body.length), body]);
  requireOk(frame.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "carrier frame exceeds structural limit", "STRUCTURAL");
  return frame;
}

export function parseSegmentFrameV3(input) {
  const bytes = Buffer.from(input);
  requireOk(bytes.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "carrier frame exceeds structural limit", "PARSER");
  let cursor = 0;
  let magic;
  [magic, cursor] = readBytes(bytes, cursor, 4, "segment magic");
  equalBytes(magic, Buffer.from("P3SG"), "ERR_FRAME_MAGIC", "segment frame magic", "PARSER");
  let version;
  [version, cursor] = readU16be(bytes, cursor, "segment version");
  requireOk(version === 3, "ERR_FRAME_VERSION", "segment frame version", "PARSER");
  let ordinal; let inputIndex; let length;
  [ordinal, cursor] = readU32be(bytes, cursor, "segment ordinal");
  [inputIndex, cursor] = readU32be(bytes, cursor, "segment input index");
  [length, cursor] = readU32be(bytes, cursor, "segment payload length");
  requireOk(length > 0, "ERR_FRAME_PAYLOAD", "segment payload must be nonempty", "PARSER");
  requireOk(length <= MAX_SCRIPT_BYTES - SEGMENT_FRAME_HEADER_BYTES, "ERR_SCRIPT_SIZE", "segment payload exceeds structural limit", "PARSER");
  let payload;
  [payload, cursor] = readBytes(bytes, cursor, length, "segment payload");
  requireNoTrailing(bytes, cursor, "segment frame");
  return { bytes, ordinal, inputIndex, payload: Buffer.from(payload) };
}

export function compileStructuralRedeemV3(manifestCore, roleInstance) {
  const manifest = Buffer.from(manifestCore);
  const role = Buffer.from(roleInstance);
  requireOk(manifest.length > 0, "ERR_REDEEM", "manifest must be nonempty", "CODEC");
  requireOk(manifest.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "manifest exceeds structural script limit", "CODEC");
  parseRoleInstanceV3(role);
  const redeem = Buffer.concat([encodeMinimalPush(manifest), Buffer.from([0x75]), encodeMinimalPush(role), Buffer.from([0x75, 0x00])]);
  requireOk(redeem.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "structural redeem exceeds current script limit", "CODEC");
  return redeem;
}

export function compileStructuralLockV3(redeem) {
  const value = Buffer.from(redeem);
  return Buffer.concat([Buffer.from([0xa9, 0x14]), hash160(value), Buffer.from([0x87])]);
}

export function parseStructuralRedeemV3(input) {
  const bytes = Buffer.from(input);
  requireOk(bytes.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "structural redeem exceeds current script limit", "PARSER");
  let cursor = 0;
  const manifestPush = parseMinimalPush(bytes, cursor, "manifest redeem push");
  cursor = manifestPush.end;
  requireOk(manifestPush.payload.length > 0, "ERR_REDEEM", "manifest redeem push must be nonempty", "PARSER");
  requireOk(bytes[cursor] === 0x75, "ERR_REDEEM", "manifest OP_DROP missing", "PARSER");
  cursor += 1;
  const rolePush = parseMinimalPush(bytes, cursor, "role redeem push");
  cursor = rolePush.end;
  requireOk(rolePush.payload.length > 0, "ERR_REDEEM", "role redeem push must be nonempty", "PARSER");
  requireOk(bytes[cursor] === 0x75 && bytes[cursor + 1] === 0x00, "ERR_REDEEM", "role OP_DROP/OP_FALSE suffix missing", "PARSER");
  cursor += 2;
  requireNoTrailing(bytes, cursor, "structural redeem");
  const manifest = parseDeploymentManifestV3Core(manifestPush.payload);
  const role = parseRoleInstanceV3(rolePush.payload);
  const canonical = compileStructuralRedeemV3(manifest.core, role.bytes);
  equalBytes(bytes, canonical, "ERR_REDEEM", "structural redeem canonical encoding", "PARSER");
  return { bytes, manifest, role, manifestPush, rolePush };
}

export function parseStructuralLockV3(input, expectedRedeem, name = "structural lock") {
  const bytes = hexToBytes(typeof input === "string" ? input : bytesToHex(input), name, 23);
  requireOk(bytes[0] === 0xa9 && bytes[1] === 0x14 && bytes[22] === 0x87, "ERR_LOCK", `${name} is not P2SH20`, "STRUCTURAL");
  if (expectedRedeem !== undefined) equalBytes(bytes.subarray(2, 22), hash160(expectedRedeem), "ERR_LOCK", `${name} redeem hash`, "STRUCTURAL");
  return bytes;
}

export function parseCarrierUnlockingBytecodeV3(input) {
  const bytes = Buffer.isBuffer(input) ? Buffer.from(input) : hexToBytes(input, "carrier unlocking bytecode");
  requireOk(bytes.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "carrier unlocking bytecode exceeds structural limit", "STRUCTURAL");
  let cursor = 0;
  const framePush = parseMinimalPush(bytes, cursor, "carrier frame push");
  cursor = framePush.end;
  requireOk(framePush.payload.length > 0, "ERR_FRAME_PAYLOAD", "carrier frame push empty", "PARSER");
  requireOk(framePush.payload.length <= MAX_SCRIPT_BYTES && framePush.raw.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "carrier frame push exceeds structural limit", "PARSER");
  const redeemPush = parseMinimalPush(bytes, cursor, "carrier final redeem push");
  cursor = redeemPush.end;
  requireOk(redeemPush.payload.length > 0, "ERR_REDEEM", "carrier redeem push empty", "PARSER");
  requireOk(redeemPush.payload.length <= MAX_SCRIPT_BYTES && redeemPush.raw.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "carrier redeem push exceeds structural limit", "PARSER");
  requireNoTrailing(bytes, cursor, "carrier unlocking bytecode");
  const frame = parseSegmentFrameV3(framePush.payload);
  const redeem = parseStructuralRedeemV3(redeemPush.payload);
  return { bytes, framePush, redeemPush, frame, redeem };
}

export function encodeNormalizedRoleTemplateV3(roleClass) {
  const roleTag = roleTagValue(roleClass);
  return Buffer.concat([Buffer.from("P3RT"), u16be(3), u8(roleTag), u8(5), STRUCTURAL_PROGRAM]);
}

export function parseNormalizedRoleTemplateV3(input) {
  const bytes = Buffer.from(input);
  requireOk(bytes.length === 18, "ERR_TEMPLATE", "normalized role template length", "PARSER");
  equalBytes(bytes.subarray(0, 4), Buffer.from("P3RT"), "ERR_TEMPLATE", "normalized role template magic", "PARSER");
  requireOk(bytes.readUInt16BE(4) === 3, "ERR_TEMPLATE", "normalized role template version", "PARSER");
  const roleClass = roleClassFromTag(bytes[6]);
  requireOk(bytes[7] === 5, "ERR_TEMPLATE", "normalized role template instruction count", "PARSER");
  equalBytes(bytes.subarray(8), STRUCTURAL_PROGRAM, "ERR_TEMPLATE", "normalized role template program", "PARSER");
  return { bytes, roleClass };
}

export function encodeTemplateSetV3() {
  const state = encodeNormalizedRoleTemplateV3("STATE");
  const carrier = encodeNormalizedRoleTemplateV3("CARRIER");
  return Buffer.concat([
    Buffer.from("P3TS"), u16be(3), lp(Buffer.from(TOOLCHAIN_LITERAL, "ascii")), lp(state), lp(carrier),
  ]);
}

export function parseTemplateSetV3(input) {
  const bytes = Buffer.from(input);
  let cursor = 0;
  let magic;
  [magic, cursor] = readBytes(bytes, cursor, 4, "template set magic");
  equalBytes(magic, Buffer.from("P3TS"), "ERR_TEMPLATE", "template set magic", "PARSER");
  let version;
  [version, cursor] = readU16be(bytes, cursor, "template set version");
  requireOk(version === 3, "ERR_TEMPLATE", "template set version", "PARSER");
  let toolchain; let state; let carrier;
  [toolchain, cursor] = readLp(bytes, cursor, "template toolchain");
  equalBytes(toolchain, Buffer.from(TOOLCHAIN_LITERAL), "ERR_TEMPLATE", "template toolchain literal", "PARSER");
  [state, cursor] = readLp(bytes, cursor, "state template");
  [carrier, cursor] = readLp(bytes, cursor, "carrier template");
  requireNoTrailing(bytes, cursor, "template set");
  requireOk(parseNormalizedRoleTemplateV3(state).roleClass === "STATE", "ERR_TEMPLATE", "state template role class", "PARSER");
  requireOk(parseNormalizedRoleTemplateV3(carrier).roleClass === "CARRIER", "ERR_TEMPLATE", "carrier template role class", "PARSER");
  const canonical = encodeTemplateSetV3();
  equalBytes(bytes, canonical, "ERR_TEMPLATE", "template set canonical bytes", "PARSER");
  return { bytes, protocolTemplateDigest: domainHash("PoolActionFv2/protocol-template/v3", bytes) };
}

function deriveAnchorDigest(anchorTxHashOpcodeOrder, anchorOutputIndex) {
  return domainHash("PoolActionFv2/pre-existing-anchor/v3", anchorTxHashOpcodeOrder, u32be(anchorOutputIndex));
}

export function deriveStructuralProvenanceV3(spec) {
  requireExactKeys(spec, ["anchorTxHashOpcodeOrderHex", "anchorOutputIndexLeHex", "networkId", "stateCarrierBaseSatsLeHex", "maxLifetimeDepositsLeHex", "feePolicyMaxSatsLeHex", "carrierExpectedValuesSatsLeHex", "genesisInitialStateValueSatsLeHex"], "structural provenance input");
  const anchorTxHash = hexToBytes(spec.anchorTxHashOpcodeOrderHex, "anchorTxHashOpcodeOrderHex", 32);
  const anchorOutputIndex = parseU32Runtime(spec.anchorOutputIndexLeHex, "anchorOutputIndexLeHex");
  networkTag(spec.networkId);
  const stateCarrierBaseSats = requireMoney(parseRuntimeU64LeHex(spec.stateCarrierBaseSatsLeHex, "stateCarrierBaseSatsLeHex"), "stateCarrierBaseSats");
  const fee = requireMoney(parseRuntimeU64LeHex(spec.feePolicyMaxSatsLeHex, "feePolicyMaxSatsLeHex"), "feePolicyMaxSats");
  const capacity = parseRuntimeU64LeHex(spec.maxLifetimeDepositsLeHex, "maxLifetimeDepositsLeHex");
  requireOk(capacity >= 1n && capacity * TICKET_SATS <= MAX_MONEY && stateCarrierBaseSats <= MAX_MONEY - (capacity * TICKET_SATS), "ERR_CAPACITY", "structural provenance base/capacity", "PROVENANCE");
  const genesisValue = parseRuntimeU64LeHex(spec.genesisInitialStateValueSatsLeHex, "genesisInitialStateValueSatsLeHex");
  requireOk(genesisValue === stateCarrierBaseSats, "ERR_PROVENANCE_GENESIS", "structural genesis value must equal state carrier base", "PROVENANCE");
  requireArray(spec.carrierExpectedValuesSatsLeHex, "carrierExpectedValuesSatsLeHex");
  requireOk(spec.carrierExpectedValuesSatsLeHex.length >= 1 && spec.carrierExpectedValuesSatsLeHex.length <= MAX_CARRIER_COUNT, "ERR_CARRIER_COUNT", "provenance carrier count", "STRUCTURAL");
  const templateSet = encodeTemplateSetV3();
  const protocolTemplateDigest = domainHash("PoolActionFv2/protocol-template/v3", templateSet);
  const preExistingAnchorDigest = deriveAnchorDigest(anchorTxHash, anchorOutputIndex);
  const stateCategoryWire = Buffer.from(anchorTxHash);
  const layout = spec.carrierExpectedValuesSatsLeHex.map((value, ordinal) => ({
    ordinalLeHex: runtimeU64LeHex(BigInt(ordinal)), inputIndexLeHex: runtimeU64LeHex(BigInt(ordinal + 1)),
    outputIndexLeHex: runtimeU64LeHex(BigInt(ordinal + 1)), expectedValueSatsLeHex: runtimeU64LeHex(requireMoney(parseRuntimeU64LeHex(value, `carrierExpectedValuesSatsLeHex[${ordinal}]`), `carrier ${ordinal} expected value`)),
  }));
  const identitySpec = {
    networkId: spec.networkId, protocolTemplateDigestHex: bytesToHex(protocolTemplateDigest), poolInstanceIdHex: bytesToHex(ZERO32),
    preExistingAnchorDigestHex: bytesToHex(preExistingAnchorDigest), genesisAncestryDigestHex: bytesToHex(ZERO32),
    stateCategoryWireHex: bytesToHex(stateCategoryWire), stateCarrierBaseSatsLeHex: runtimeU64LeHex(stateCarrierBaseSats),
    maxLifetimeDepositsLeHex: runtimeU64LeHex(capacity), feePolicyMaxSatsLeHex: runtimeU64LeHex(fee),
    proofSuiteStatusHex: "00", proofSuiteManifestDigestHex: bytesToHex(ZERO32),
    carrierCountLeHex: runtimeU64LeHex(BigInt(layout.length)), carrierLayout: layout,
  };
  const poolIdentityConfig = encodePoolIdentityConfigV3(identitySpec);
  const poolInstanceId = domainHash("PoolActionFv2/pool-instance/v3", poolIdentityConfig);
  const genesisAncestryDigest = domainHash(
    "PoolActionFv2/genesis-ancestry/v3",
    preExistingAnchorDigest,
    poolInstanceId,
    stateCategoryWire,
  );
  const manifestSpec = {
    networkId: spec.networkId,
    protocolTemplateDigestHex: bytesToHex(protocolTemplateDigest),
    poolInstanceIdHex: bytesToHex(poolInstanceId),
    preExistingAnchorDigestHex: bytesToHex(preExistingAnchorDigest),
    genesisAncestryDigestHex: bytesToHex(genesisAncestryDigest),
    stateCategoryWireHex: bytesToHex(stateCategoryWire),
    stateCarrierBaseSatsLeHex: runtimeU64LeHex(stateCarrierBaseSats),
    maxLifetimeDepositsLeHex: runtimeU64LeHex(capacity),
    feePolicyMaxSatsLeHex: runtimeU64LeHex(fee),
    proofSuiteStatusHex: "00",
    proofSuiteManifestDigestHex: bytesToHex(ZERO32),
    carrierCountLeHex: runtimeU64LeHex(BigInt(layout.length)),
    carrierLayout: layout,
  };
  const manifestCore = encodeDeploymentManifestV3Core(manifestSpec);
  const manifest = parseDeploymentManifestV3Core(manifestCore);
  const roles = [];
  const stateRole = encodeRoleFromManifest("STATE", 0);
  const stateRedeem = compileStructuralRedeemV3(manifestCore, stateRole);
  roles.push(makeRoleArtifact("STATE", 0, stateRole, stateRedeem));
  for (let i = 0; i < manifest.carrierCount; i += 1) {
    const role = encodeRoleFromManifest("CARRIER", i);
    const redeem = compileStructuralRedeemV3(manifestCore, role);
    roles.push(makeRoleArtifact("CARRIER", i, role, redeem));
  }
  return {
    templateSet,
    protocolTemplateDigest,
    anchorTxHashOpcodeOrder: anchorTxHash,
    anchorOutputIndex,
    preExistingAnchorDigest,
    poolInstanceId,
    poolIdentityConfig,
    stateCategoryWire,
    genesisAncestryDigest,
    manifestSpec,
    manifestCore,
    deploymentCommitment: manifest.deploymentCommitment,
    roles,
    genesisInitialStateValueSats: genesisValue,
  };
}

function makeRoleArtifact(roleClass, ordinal, roleInstance, redeem) {
  const manifestPush = encodeMinimalPush(parseStructuralRedeemV3(redeem).manifest.core);
  const rolePush = encodeMinimalPush(roleInstance);
  const redeemIntervals = [
    { start: 0, end: manifestPush.length, origin: "LOCK_SELECTED_EMBEDDED:manifestMinimalPush" },
    { start: manifestPush.length, end: manifestPush.length + 1, origin: "CODEC_CONSTANT:OP_DROP" },
    { start: manifestPush.length + 1, end: manifestPush.length + 1 + rolePush.length, origin: "LOCK_SELECTED_EMBEDDED:roleMinimalPush" },
    { start: manifestPush.length + 1 + rolePush.length, end: manifestPush.length + 2 + rolePush.length, origin: "CODEC_CONSTANT:OP_DROP" },
    { start: manifestPush.length + 2 + rolePush.length, end: manifestPush.length + 3 + rolePush.length, origin: "CODEC_CONSTANT:OP_FALSE" },
  ];
  const lock = compileStructuralLockV3(redeem);
  const lockIntervals = [
    { start: 0, end: 1, origin: "CODEC_CONSTANT:OP_HASH160" },
    { start: 1, end: 2, origin: "CODEC_CONSTANT:Push20" },
    { start: 2, end: 22, origin: "DERIVED_AND_CHECKED:HASH160(redeem)" },
    { start: 22, end: 23, origin: "CODEC_CONSTANT:OP_EQUAL" },
  ];
  validateByteOriginIntervals(redeemIntervals, redeem.length, `redeem ${roleClass}/${ordinal}`);
  validateByteOriginIntervals(lockIntervals, lock.length, `lock ${roleClass}/${ordinal}`);
  return { roleClass, ordinal, roleInstance, redeem, lock, redeemIntervals, lockIntervals };
}

export function validateByteOriginIntervals(intervals, totalLength, name = "byte origin intervals") {
  requireArray(intervals, name);
  let cursor = 0;
  for (let index = 0; index < intervals.length; index += 1) {
    const interval = intervals[index];
    requireExactKeys(interval, ["start", "end", "origin"], `${name}[${index}]`);
    requireOk(Number.isInteger(interval.start) && Number.isInteger(interval.end) && interval.start === cursor && interval.end > interval.start && typeof interval.origin === "string" && interval.origin.length > 0, "ERR_PROVENANCE_INTERVAL", `${name}[${index}] is not contiguous`, "PROVENANCE");
    cursor = interval.end;
  }
  requireOk(cursor === totalLength, "ERR_PROVENANCE_INTERVAL", `${name} does not cover all bytes`, "PROVENANCE");
  return true;
}

export function validateStructuralProvenanceV3(value) {
  requireExactKeys(value, [
    "templateSetHex", "protocolTemplateDigestHex", "anchorTxHashOpcodeOrderHex", "anchorOutputIndexLeHex",
    "preExistingAnchorDigestHex", "poolIdentityConfigHex", "poolInstanceIdHex", "stateCategoryWireHex",
    "genesisAncestryDigestHex", "deploymentManifestCoreHex", "deploymentCommitmentHex",
    "genesisInitialStateValueSatsLeHex", "roles", "structuralOnly", "nonDeployable", "proofSuite",
  ], "structural provenance");
  requireOk(value.structuralOnly === true && value.nonDeployable === true && value.proofSuite === "UNSELECTED", "ERR_PROVENANCE_FLAGS", "structural provenance nonclaim flags", "PROVENANCE");
  const templateSet = parseTemplateSetV3(hexToBytes(value.templateSetHex, "provenance template set"));
  equalBytes(templateSet.protocolTemplateDigest, hexToBytes(value.protocolTemplateDigestHex, "provenance protocol template digest", 32), "ERR_PROVENANCE", "protocol template digest", "PROVENANCE");
  const anchorTxHash = hexToBytes(value.anchorTxHashOpcodeOrderHex, "provenance anchor transaction hash", 32);
  const anchorOutputIndex = parseU32Runtime(value.anchorOutputIndexLeHex, "provenance anchor output index");
  const preExistingAnchorDigest = deriveAnchorDigest(anchorTxHash, anchorOutputIndex);
  equalBytes(preExistingAnchorDigest, hexToBytes(value.preExistingAnchorDigestHex, "provenance anchor digest", 32), "ERR_PROVENANCE", "pre-existing anchor digest", "PROVENANCE");
  const poolIdentityConfig = parsePoolIdentityConfigV3(hexToBytes(value.poolIdentityConfigHex, "provenance pool identity config"));
  equalBytes(poolIdentityConfig.protocolTemplateDigest, templateSet.protocolTemplateDigest, "ERR_PROVENANCE", "pool identity protocol template digest", "PROVENANCE");
  equalBytes(poolIdentityConfig.preExistingAnchorDigest, preExistingAnchorDigest, "ERR_PROVENANCE", "pool identity anchor digest", "PROVENANCE");
  equalBytes(poolIdentityConfig.stateCategoryWire, anchorTxHash, "ERR_PROVENANCE", "pool identity state category", "PROVENANCE");
  equalBytes(poolIdentityConfig.poolInstanceId, hexToBytes(value.poolInstanceIdHex, "provenance pool instance id", 32), "ERR_PROVENANCE", "pool instance id", "PROVENANCE");
  equalBytes(anchorTxHash, hexToBytes(value.stateCategoryWireHex, "provenance state category wire", 32), "ERR_PROVENANCE", "state category wire", "PROVENANCE");
  const genesisAncestryDigest = domainHash("PoolActionFv2/genesis-ancestry/v3", preExistingAnchorDigest, poolIdentityConfig.poolInstanceId, anchorTxHash);
  equalBytes(genesisAncestryDigest, hexToBytes(value.genesisAncestryDigestHex, "provenance genesis ancestry digest", 32), "ERR_PROVENANCE", "genesis ancestry digest", "PROVENANCE");
  const manifest = parseDeploymentManifestV3Core(hexToBytes(value.deploymentManifestCoreHex, "provenance deployment manifest"));
  equalBytes(manifest.protocolTemplateDigest, templateSet.protocolTemplateDigest, "ERR_PROVENANCE", "manifest protocol template digest", "PROVENANCE");
  equalBytes(manifest.preExistingAnchorDigest, preExistingAnchorDigest, "ERR_PROVENANCE", "manifest pre-existing anchor digest", "PROVENANCE");
  equalBytes(manifest.poolIdentityConfig, poolIdentityConfig.bytes, "ERR_PROVENANCE", "manifest pool identity config", "PROVENANCE");
  equalBytes(manifest.poolInstanceId, poolIdentityConfig.poolInstanceId, "ERR_PROVENANCE", "manifest pool identity", "PROVENANCE");
  equalBytes(manifest.stateCategoryWire, anchorTxHash, "ERR_PROVENANCE", "manifest state category", "PROVENANCE");
  equalBytes(manifest.genesisAncestryDigest, genesisAncestryDigest, "ERR_PROVENANCE", "manifest genesis ancestry", "PROVENANCE");
  equalBytes(manifest.deploymentCommitment, hexToBytes(value.deploymentCommitmentHex, "provenance deployment commitment", 32), "ERR_PROVENANCE", "deployment commitment", "PROVENANCE");
  const genesisInitialStateValueSats = parseRuntimeU64LeHex(value.genesisInitialStateValueSatsLeHex, "provenance genesis initial state value");
  requireOk(genesisInitialStateValueSats === manifest.stateCarrierBaseSats, "ERR_PROVENANCE_GENESIS", "provenance genesis state value must equal manifest base", "PROVENANCE");
  requireArray(value.roles, "provenance roles");
  requireOk(value.roles.length === manifest.carrierCount + 1, "ERR_PROVENANCE", "provenance role count", "PROVENANCE");
  for (let index = 0; index < value.roles.length; index += 1) {
    const artifact = value.roles[index];
    requireExactKeys(artifact, ["roleClass", "ordinalLeHex", "roleInstanceHex", "redeemHex", "lockHex", "redeemIntervals", "lockIntervals"], `provenance role ${index}`);
    const roleClass = index === 0 ? "STATE" : "CARRIER";
    const ordinal = index === 0 ? 0 : index - 1;
    requireOk(artifact.roleClass === roleClass && parseU32Runtime(artifact.ordinalLeHex, `provenance role ${index} ordinal`) === ordinal, "ERR_PROVENANCE", `provenance role ${index} class/ordinal`, "PROVENANCE");
    const expected = expectedRoleLock(manifest, roleClass, ordinal);
    equalBytes(hexToBytes(artifact.roleInstanceHex, `provenance role ${index} instance`), expected.role, "ERR_PROVENANCE", `provenance role ${index} instance`, "PROVENANCE");
    const redeem = parseStructuralRedeemV3(hexToBytes(artifact.redeemHex, `provenance role ${index} redeem`));
    equalBytes(redeem.bytes, expected.redeem, "ERR_PROVENANCE", `provenance role ${index} redeem`, "PROVENANCE");
    equalBytes(redeem.manifest.core, manifest.core, "ERR_PROVENANCE", `provenance role ${index} manifest prefix`, "PROVENANCE");
    parseStructuralLockV3(artifact.lockHex, expected.redeem, `provenance role ${index} lock`);
    const manifestPushLength = redeem.manifestPush.raw.length;
    const rolePushLength = redeem.rolePush.raw.length;
    const expectedRedeemIntervals = [
      { start: 0, end: manifestPushLength, origin: "LOCK_SELECTED_EMBEDDED:manifestMinimalPush" },
      { start: manifestPushLength, end: manifestPushLength + 1, origin: "CODEC_CONSTANT:OP_DROP" },
      { start: manifestPushLength + 1, end: manifestPushLength + 1 + rolePushLength, origin: "LOCK_SELECTED_EMBEDDED:roleMinimalPush" },
      { start: manifestPushLength + 1 + rolePushLength, end: manifestPushLength + 2 + rolePushLength, origin: "CODEC_CONSTANT:OP_DROP" },
      { start: manifestPushLength + 2 + rolePushLength, end: manifestPushLength + 3 + rolePushLength, origin: "CODEC_CONSTANT:OP_FALSE" },
    ];
    const expectedLockIntervals = [
      { start: 0, end: 1, origin: "CODEC_CONSTANT:OP_HASH160" },
      { start: 1, end: 2, origin: "CODEC_CONSTANT:Push20" },
      { start: 2, end: 22, origin: "DERIVED_AND_CHECKED:HASH160(redeem)" },
      { start: 22, end: 23, origin: "CODEC_CONSTANT:OP_EQUAL" },
    ];
    validateByteOriginIntervals(artifact.redeemIntervals, expected.redeem.length, `provenance role ${index} redeem intervals`);
    validateByteOriginIntervals(artifact.lockIntervals, expected.lock.length, `provenance role ${index} lock intervals`);
    requireOk(JSON.stringify(artifact.redeemIntervals) === JSON.stringify(expectedRedeemIntervals) && JSON.stringify(artifact.lockIntervals) === JSON.stringify(expectedLockIntervals), "ERR_PROVENANCE_INTERVAL", `provenance role ${index} exact byte origins`, "PROVENANCE");
  }
  return true;
}

function parseProjection(raw, name) {
  requireExactKeys(raw, ["categoryWireHex", "commitmentHex", "amountLeHex"], name);
  return raw;
}

function parseInputEvidence(raw, index) {
  requireExactKeys(raw, ["outpointTxHashOpcodeOrderHex", "outpointIndexLeHex", "sequenceLeHex", "sourceValueSatsLeHex", "sourceLockingBytecodeHex", "tokenProjection"], `transaction.inputs[${index}]`);
  const sourceLockingBytecode = hexToBytes(raw.sourceLockingBytecodeHex, `input ${index} source lock`);
  requireOk(sourceLockingBytecode.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", `input ${index} source lock exceeds structural limit`, "STRUCTURAL");
  return {
    outpointTxHashOpcodeOrder: hexToBytes(raw.outpointTxHashOpcodeOrderHex, `input ${index} outpoint hash`, 32),
    outpointIndex: parseRuntimeU64LeHex(raw.outpointIndexLeHex, `input ${index} outpoint index`),
    sequence: parseRuntimeU64LeHex(raw.sequenceLeHex, `input ${index} sequence`),
    sourceValueSats: requireMoney(parseRuntimeU64LeHex(raw.sourceValueSatsLeHex, `input ${index} source value`), `input ${index} source value`),
    sourceLockingBytecode,
    tokenProjection: parseProjection(raw.tokenProjection, `input ${index} token projection`),
  };
}

function parseOutputEvidence(raw, index) {
  requireExactKeys(raw, ["valueSatsLeHex", "lockingBytecodeHex", "tokenProjection"], `transaction.outputs[${index}]`);
  const lockingBytecode = hexToBytes(raw.lockingBytecodeHex, `output ${index} lock`);
  requireOk(lockingBytecode.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", `output ${index} lock exceeds structural limit`, "STRUCTURAL");
  return {
    valueSats: requireMoney(parseRuntimeU64LeHex(raw.valueSatsLeHex, `output ${index} value`), `output ${index} value`),
    lockingBytecode,
    tokenProjection: parseProjection(raw.tokenProjection, `output ${index} token projection`),
  };
}

function parseTransactionEvidence(raw) {
  requireExactKeys(raw, ["versionLeHex", "locktimeLeHex", "inputs", "outputs"], "transaction evidence");
  const inputs = requireArray(raw.inputs, "transaction inputs").map(parseInputEvidence);
  const outputs = requireArray(raw.outputs, "transaction outputs").map(parseOutputEvidence);
  const version = parseRuntimeU64LeHex(raw.versionLeHex, "transaction version");
  const locktime = parseRuntimeU64LeHex(raw.locktimeLeHex, "transaction locktime");
  requireOk(version === 2n, "ERR_TX_VERSION", "transaction version must be 2", "STRUCTURAL");
  requireOk(locktime === 0n, "ERR_TX_LOCKTIME", "transaction locktime must be 0", "STRUCTURAL");
  for (let i = 0; i < inputs.length; i += 1) requireOk(inputs[i].sequence === 0xffffffffn, "ERR_TX_SEQUENCE", `input ${i} sequence must be 0xffffffff`, "STRUCTURAL");
  return {
    version,
    locktime,
    inputs,
    outputs,
  };
}

function expectedRoleLock(manifest, roleClass, ordinal) {
  const role = encodeRoleFromManifest(roleClass, ordinal);
  const redeem = compileStructuralRedeemV3(manifest.core, role);
  return { role, redeem, lock: compileStructuralLockV3(redeem) };
}

function checkRoleLocalConsumptions(consumptions, manifest) {
  requireArray(consumptions, "verifierRoleConsumptions");
  requireOk(consumptions.length === manifest.carrierCount + 1, "ERR_ROLE_LOCAL", "must supply state and every carrier local role consumption", "STRUCTURAL");
  const observed = new Set();
  for (let j = 0; j < consumptions.length; j += 1) {
    const item = consumptions[j];
    requireExactKeys(item, ["roleTagHex", "ordinalLeHex", "observedInputIndexLeHex"], `verifierRoleConsumptions[${j}]`);
    const tag = hexToBytes(item.roleTagHex, `verifier role ${j} tag`, 1)[0];
    const ordinal = parseU32Runtime(item.ordinalLeHex, `verifier role ${j} ordinal`);
    const observedInputIndex = parseU32Runtime(item.observedInputIndexLeHex, `verifier role ${j} active input index`);
    const roleClass = roleClassFromTag(tag);
    const expectedOrdinal = roleClass === "STATE" ? 0 : ordinal;
    const expectedIndex = roleClass === "STATE" ? 0 : ordinal + 1;
    requireOk(observedInputIndex === expectedIndex, "ERR_ROLE_LOCAL", `role ${roleClass}/${ordinal} active input index`, "STRUCTURAL");
    if (roleClass === "STATE") requireOk(ordinal === 0, "ERR_ROLE_LOCAL", "state ordinal", "STRUCTURAL");
    else requireOk(ordinal < manifest.carrierCount, "ERR_ROLE_LOCAL", "carrier ordinal out of range", "STRUCTURAL");
    const identity = `${tag}:${expectedOrdinal}`;
    requireOk(!observed.has(identity), "ERR_ROLE_LOCAL", "duplicate verifier role consumption", "STRUCTURAL");
    observed.add(identity);
  }
  requireOk(observed.size === manifest.carrierCount + 1 && observed.has("0:0"), "ERR_ROLE_LOCAL", "missing state local consumption", "STRUCTURAL");
  for (let i = 0; i < manifest.carrierCount; i += 1) requireOk(observed.has(`1:${i}`), "ERR_ROLE_LOCAL", `missing carrier ${i} local consumption`, "STRUCTURAL");
}

function checkRoleLocalByteConsumptionV3(consumptions, manifest, transaction, stateRedeem, carrierParses) {
  const expectedState = expectedRoleLock(manifest, "STATE", 0);
  for (let j = 0; j < consumptions.length; j += 1) {
    const item = consumptions[j];
    const tag = hexToBytes(item.roleTagHex, `verifier role ${j} tag`, 1)[0];
    const ordinal = parseU32Runtime(item.ordinalLeHex, `verifier role ${j} ordinal`);
    if (tag === 0) {
      equalBytes(stateRedeem.role.bytes, expectedState.role, "ERR_ROLE_LOCAL", "state local role instance", "STRUCTURAL");
      equalBytes(transaction.inputs[0].sourceLockingBytecode, expectedState.lock, "ERR_ROLE_LOCAL", "state local source lock", "STRUCTURAL");
      continue;
    }
    const expectedCarrier = expectedRoleLock(manifest, "CARRIER", ordinal);
    const parsedCarrier = carrierParses[ordinal];
    requireOk(parsedCarrier !== undefined, "ERR_ROLE_LOCAL", `carrier ${ordinal} local session entry`, "STRUCTURAL");
    equalBytes(parsedCarrier.redeem.role.bytes, expectedCarrier.role, "ERR_ROLE_LOCAL", `carrier ${ordinal} local role instance`, "STRUCTURAL");
    equalBytes(parsedCarrier.redeem.bytes, expectedCarrier.redeem, "ERR_ROLE_LOCAL", `carrier ${ordinal} local final redeem`, "STRUCTURAL");
    equalBytes(transaction.inputs[ordinal + 1].sourceLockingBytecode, expectedCarrier.lock, "ERR_ROLE_LOCAL", `carrier ${ordinal} local source lock`, "STRUCTURAL");
  }
}

function actionFromStateValues(source, successor) {
  const delta = successor - source;
  if (delta === TICKET_SATS) return { action: "DEPOSIT", actionTag: 0, reserveDirection: 0 };
  if (delta === -TICKET_SATS) return { action: "WITHDRAWAL", actionTag: 1, reserveDirection: 1 };
  fail("ERR_ACTION_DELTA", "state value delta is not plus or minus one ticket", "STRUCTURAL");
}

function inputRole(action, index, n) {
  if (index === 0) return { tag: 0x00, ordinal: 0, disposition: 0x00, tokenRole: "STATE_SOURCE" };
  if (index <= n) return { tag: 0x01, ordinal: index - 1, disposition: 0x01, tokenRole: "CARRIER" };
  return { tag: action === "DEPOSIT" ? 0x02 : 0x03, ordinal: 0, disposition: 0x02, tokenRole: action === "DEPOSIT" ? "DEPOSIT_FUNDING" : "FEE_FUNDING" };
}

function outputRole(action, index, n, hasChange) {
  if (index === 0) return { tag: 0x10, ordinal: 0, tokenRole: "STATE_SUCCESSOR" };
  if (index <= n) return { tag: 0x11, ordinal: index - 1, tokenRole: "CARRIER_SUCCESSOR" };
  if (action === "WITHDRAWAL" && index === n + 1) return { tag: 0x12, ordinal: 0, tokenRole: "PAYOUT" };
  requireOk(hasChange && index === (action === "DEPOSIT" ? n + 1 : n + 2), "ERR_TOPOLOGY", "unexpected output index", "STRUCTURAL");
  return { tag: 0x13, ordinal: 0, tokenRole: "TRANSPARENT_CHANGE" };
}

function sumMoney(items, accessor, name) {
  let total = 0n;
  for (let i = 0; i < items.length; i += 1) total = checkedMoneyAdd(total, accessor(items[i]), `${name}[${i}]`);
  return total;
}

function deriveAndCheckTransaction(manifest, transaction, stateRedeem, carrierUnlockingBytecodes) {
  const n = manifest.carrierCount;
  requireOk(transaction.inputs.length === n + 2, "ERR_TOPOLOGY", "input count must equal N + 2", "STRUCTURAL");
  requireOk(transaction.outputs.length >= n + 1 && transaction.outputs.length <= n + 3, "ERR_TOPOLOGY", "output count outside fixed action bounds", "STRUCTURAL");
  const sourceState = transaction.inputs[0];
  const successorState = transaction.outputs[0];
  const expectedState = expectedRoleLock(manifest, "STATE", 0);
  equalBytes(stateRedeem.bytes, expectedState.redeem, "ERR_REDEEM", "state active redeem", "STRUCTURAL");
  equalBytes(sourceState.sourceLockingBytecode, expectedState.lock, "ERR_LOCK", "state source lock", "STRUCTURAL");
  equalBytes(successorState.lockingBytecode, expectedState.lock, "ERR_LOCK", "state successor lock", "STRUCTURAL");
  requireOk(sourceState.outpointIndex === 0n, "ERR_LINEAGE", "state source outpoint index", "STRUCTURAL");
  const stateToken = encodeTokenObservationV3(sourceState.tokenProjection, "STATE_SOURCE", manifest.stateCategoryWire);
  const successorToken = encodeTokenObservationV3(successorState.tokenProjection, "STATE_SUCCESSOR", manifest.stateCategoryWire);
  const oldState = parseStateCodec(hexToBytes(sourceState.tokenProjection.commitmentHex, "state source commitment", 128), manifest.poolInstanceId, "state source");
  const newState = parseStateCodec(hexToBytes(successorState.tokenProjection.commitmentHex, "state successor commitment", 128), manifest.poolInstanceId, "state successor");
  checkStateInvariants(oldState, sourceState.sourceValueSats, manifest, "state source");
  checkStateInvariants(newState, successorState.valueSats, manifest, "state successor");
  const { action, actionTag, reserveDirection } = actionFromStateValues(sourceState.sourceValueSats, successorState.valueSats);
  checkStateTransition(oldState, newState, action, manifest);
  const expectedOutputCountWithoutChange = action === "DEPOSIT" ? n + 1 : n + 2;
  requireOk(transaction.outputs.length === expectedOutputCountWithoutChange || transaction.outputs.length === expectedOutputCountWithoutChange + 1, "ERR_TOPOLOGY", `${action} output count`, "STRUCTURAL");
  const hasChange = transaction.outputs.length === expectedOutputCountWithoutChange + 1;
  const carrierParses = [];
  const predecessorHash = sourceState.outpointTxHashOpcodeOrder;
  requireOk(carrierUnlockingBytecodes.length === n, "ERR_CARRIER_SESSION", "carrier unlocking count", "STRUCTURAL");
  for (let i = 0; i < n; i += 1) {
    const source = transaction.inputs[i + 1];
    const successor = transaction.outputs[i + 1];
    const expected = expectedRoleLock(manifest, "CARRIER", i);
    equalBytes(source.outpointTxHashOpcodeOrder, predecessorHash, "ERR_LINEAGE", `carrier ${i} predecessor hash`, "STRUCTURAL");
    requireOk(source.outpointIndex === BigInt(i + 1), "ERR_LINEAGE", `carrier ${i} source outpoint index`, "STRUCTURAL");
    equalBytes(source.sourceLockingBytecode, expected.lock, "ERR_LOCK", `carrier ${i} source lock`, "STRUCTURAL");
    equalBytes(successor.lockingBytecode, expected.lock, "ERR_LOCK", `carrier ${i} successor lock`, "STRUCTURAL");
    requireOk(source.sourceValueSats === manifest.carrierLayout[i].expectedValueSats && successor.valueSats === manifest.carrierLayout[i].expectedValueSats, "ERR_CARRIER_VALUE", `carrier ${i} configured value continuity`, "STRUCTURAL");
    encodeTokenObservationV3(source.tokenProjection, "CARRIER", manifest.stateCategoryWire);
    encodeTokenObservationV3(successor.tokenProjection, "CARRIER_SUCCESSOR", manifest.stateCategoryWire);
    const parsed = parseCarrierUnlockingBytecodeV3(carrierUnlockingBytecodes[i]);
    requireOk(parsed.frame.ordinal === i && parsed.frame.inputIndex === i + 1, "ERR_FRAME_ORDER", `carrier ${i} frame ordinal/index`, "STRUCTURAL");
    equalBytes(parsed.redeem.bytes, expected.redeem, "ERR_REDEEM", `carrier ${i} final redeem`, "STRUCTURAL");
    equalBytes(parsed.redeem.manifest.core, manifest.core, "ERR_MANIFEST_LOCK_SELECTION", `carrier ${i} manifest prefix`, "STRUCTURAL");
    carrierParses.push(parsed);
  }
  const external = transaction.inputs[n + 1];
  encodeTokenObservationV3(external.tokenProjection, action === "DEPOSIT" ? "DEPOSIT_FUNDING" : "FEE_FUNDING", manifest.stateCategoryWire);
  let payoutPresent = 0; let payoutOutputIndex = 0; let changePresent = 0; let changeOutputIndex = 0;
  if (action === "WITHDRAWAL") {
    const payout = transaction.outputs[n + 1];
    requireOk(payout.valueSats === TICKET_SATS, "ERR_PAYOUT", "withdrawal payout must equal ticket", "STRUCTURAL");
    encodeTokenObservationV3(payout.tokenProjection, "PAYOUT", manifest.stateCategoryWire);
    payoutPresent = 1; payoutOutputIndex = n + 1;
  }
  if (hasChange) {
    changeOutputIndex = action === "DEPOSIT" ? n + 1 : n + 2;
    encodeTokenObservationV3(transaction.outputs[changeOutputIndex].tokenProjection, "TRANSPARENT_CHANGE", manifest.stateCategoryWire);
    changePresent = 1;
  }
  const totalInputs = sumMoney(transaction.inputs, (item) => item.sourceValueSats, "input sum");
  const totalOutputs = sumMoney(transaction.outputs, (item) => item.valueSats, "output sum");
  const fee = totalInputs - totalOutputs;
  requireOk(fee >= 0n, "ERR_FEE", "negative transaction fee", "STRUCTURAL");
  requireOk(fee <= manifest.feePolicyMaxSats, "ERR_FEE", "fee exceeds locked fee policy", "STRUCTURAL");
  const changeValue = hasChange ? transaction.outputs[changeOutputIndex].valueSats : 0n;
  if (action === "DEPOSIT") requireOk(external.sourceValueSats === checkedMoneyAdd(TICKET_SATS, checkedMoneyAdd(changeValue, fee, "deposit change plus fee"), "deposit funding"), "ERR_ECONOMICS", "deposit external funding equation", "STRUCTURAL");
  else requireOk(external.sourceValueSats === checkedMoneyAdd(changeValue, fee, "withdrawal fee funding"), "ERR_ECONOMICS", "withdrawal external funding equation", "STRUCTURAL");
  return { action, actionTag, reserveDirection, hasChange, payoutPresent, payoutOutputIndex, changePresent, changeOutputIndex, fee, stateToken, successorToken, oldState, newState, carrierParses };
}

function encodeTxViewV3(manifest, transaction, details) {
  const n = manifest.carrierCount;
  const inputParts = [];
  for (let i = 0; i < transaction.inputs.length; i += 1) {
    const record = transaction.inputs[i];
    const role = inputRole(details.action, i, n);
    const token = encodeTokenObservationV3(record.tokenProjection, role.tokenRole, manifest.stateCategoryWire);
    inputParts.push(
      u32be(i), u8(role.tag), u32be(role.ordinal), record.outpointTxHashOpcodeOrder,
      u64le(record.outpointIndex), u64le(record.sequence), u64le(record.sourceValueSats),
      lp(record.sourceLockingBytecode), token, u8(role.disposition),
    );
  }
  const outputParts = [];
  for (let i = 0; i < transaction.outputs.length; i += 1) {
    const record = transaction.outputs[i];
    const role = outputRole(details.action, i, n, details.hasChange);
    const token = encodeTokenObservationV3(record.tokenProjection, role.tokenRole, manifest.stateCategoryWire);
    outputParts.push(u32be(i), u8(role.tag), u32be(role.ordinal), u64le(record.valueSats), lp(record.lockingBytecode), token);
  }
  const economics = Buffer.concat([
    u64le(TICKET_SATS), u8(details.reserveDirection), u64le(details.fee), u64le(manifest.feePolicyMaxSats),
    u8(details.payoutPresent), u32be(details.payoutOutputIndex), u8(details.changePresent), u32be(details.changeOutputIndex),
  ]);
  return Buffer.concat([
    Buffer.from("P3TV"), u16be(3), u8(details.actionTag), u8(0), u64le(transaction.version), u64le(transaction.locktime),
    u32be(n), u32be(transaction.inputs.length), ...inputParts, u32be(transaction.outputs.length), ...outputParts, economics,
  ]);
}

function parseTokenObservationV3(bytes, cursor, role, stateCategoryWire, name) {
  let tag; [tag, cursor] = readBytes(bytes, cursor, 1, `${name} token tag`);
  let categoryLength; [categoryLength, cursor] = readU16be(bytes, cursor, `${name} category length`);
  let category; [category, cursor] = readBytes(bytes, cursor, categoryLength, `${name} category`);
  let commitmentLength; [commitmentLength, cursor] = readU16be(bytes, cursor, `${name} commitment length`);
  let commitment; [commitment, cursor] = readBytes(bytes, cursor, commitmentLength, `${name} commitment`);
  let amount; [amount, cursor] = readBytes(bytes, cursor, 8, `${name} amount`);
  requireOk(parseExactRuntimeBytes(amount, `${name} amount`) === 0n, "ERR_TOKEN_AMOUNT", `${name} token amount`, "PARSER");
  if (role === "STATE_SOURCE" || role === "STATE_SUCCESSOR") {
    requireOk(tag[0] === 1 && categoryLength === 33 && commitmentLength === 128 && category.subarray(32).equals(Buffer.from([1])), "ERR_TOKEN_LANGUAGE", `${name} state token form`, "PARSER");
    equalBytes(category.subarray(0, 32), stateCategoryWire, "ERR_TOKEN_CATEGORY", `${name} state category`, "PARSER");
  } else {
    requireOk(tag[0] === 0 && categoryLength === 0 && commitmentLength === 0, "ERR_TOKEN_LANGUAGE", `${name} NONE token form`, "PARSER");
  }
  return [{ categoryWireHex: bytesToHex(category), commitmentHex: bytesToHex(commitment), amountLeHex: bytesToHex(amount) }, cursor];
}

export function parseTxViewV3(input, manifestInput) {
  const bytes = Buffer.from(input);
  const manifest = Buffer.isBuffer(manifestInput) ? parseDeploymentManifestV3Core(manifestInput) : manifestInput;
  requireOk(manifest && manifest.core && manifest.carrierCount >= 1, "ERR_TXVIEW", "parsed manifest required for TxView", "PARSER");
  let cursor = 0;
  let magic; [magic, cursor] = readBytes(bytes, cursor, 4, "TxView magic");
  equalBytes(magic, Buffer.from("P3TV"), "ERR_TXVIEW", "TxView magic", "PARSER");
  let version; [version, cursor] = readU16be(bytes, cursor, "TxView version");
  requireOk(version === 3, "ERR_TXVIEW", "TxView version", "PARSER");
  let actionTag; [actionTag, cursor] = readBytes(bytes, cursor, 1, "TxView action tag");
  requireOk(actionTag[0] === 0 || actionTag[0] === 1, "ERR_TXVIEW", "TxView action tag", "PARSER");
  const action = actionTag[0] === 0 ? "DEPOSIT" : "WITHDRAWAL";
  let reserved; [reserved, cursor] = readBytes(bytes, cursor, 1, "TxView reserved");
  requireOk(reserved[0] === 0, "ERR_RESERVED", "TxView reserved", "PARSER");
  let versionBytes; let locktimeBytes;
  [versionBytes, cursor] = readBytes(bytes, cursor, 8, "TxView transaction version");
  [locktimeBytes, cursor] = readBytes(bytes, cursor, 8, "TxView locktime");
  requireOk(parseExactRuntimeBytes(versionBytes, "TxView transaction version") === 2n, "ERR_TX_VERSION", "TxView transaction version", "PARSER");
  requireOk(parseExactRuntimeBytes(locktimeBytes, "TxView locktime") === 0n, "ERR_TX_LOCKTIME", "TxView locktime", "PARSER");
  let carrierCount; [carrierCount, cursor] = readU32be(bytes, cursor, "TxView carrier count");
  requireOk(carrierCount === manifest.carrierCount, "ERR_TXVIEW", "TxView carrier count", "PARSER");
  let inputCount; [inputCount, cursor] = readU32be(bytes, cursor, "TxView input count");
  requireOk(inputCount === carrierCount + 2, "ERR_TOPOLOGY", "TxView input count", "PARSER");
  const inputs = [];
  for (let i = 0; i < inputCount; i += 1) {
    let wireIndex; let roleTag; let roleOrdinal; let hash; let outpoint; let sequence; let value; let lock; let disposition;
    [wireIndex, cursor] = readU32be(bytes, cursor, `TxView input ${i} wire index`);
    [roleTag, cursor] = readBytes(bytes, cursor, 1, `TxView input ${i} role tag`);
    [roleOrdinal, cursor] = readU32be(bytes, cursor, `TxView input ${i} role ordinal`);
    [hash, cursor] = readBytes(bytes, cursor, 32, `TxView input ${i} outpoint hash`);
    [outpoint, cursor] = readBytes(bytes, cursor, 8, `TxView input ${i} outpoint index`);
    [sequence, cursor] = readBytes(bytes, cursor, 8, `TxView input ${i} sequence`);
    [value, cursor] = readBytes(bytes, cursor, 8, `TxView input ${i} value`);
    [lock, cursor] = readLp(bytes, cursor, `TxView input ${i} lock`);
    const expectedRole = inputRole(action, i, carrierCount);
    requireOk(wireIndex === i && roleTag[0] === expectedRole.tag && roleOrdinal === expectedRole.ordinal, "ERR_TX_ROLE_ORDINAL", `TxView input ${i} role mapping`, "PARSER");
    const [tokenProjection, next] = parseTokenObservationV3(bytes, cursor, expectedRole.tokenRole, manifest.stateCategoryWire, `TxView input ${i}`);
    cursor = next;
    [disposition, cursor] = readBytes(bytes, cursor, 1, `TxView input ${i} disposition`);
    requireOk(disposition[0] === expectedRole.disposition, "ERR_TXVIEW", `TxView input ${i} disposition`, "PARSER");
    requireOk(parseExactRuntimeBytes(sequence, `TxView input ${i} sequence`) === 0xffffffffn, "ERR_TX_SEQUENCE", `TxView input ${i} sequence`, "PARSER");
    requireMoney(parseExactRuntimeBytes(value, `TxView input ${i} value`), `TxView input ${i} value`);
    requireOk(lock.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", `TxView input ${i} lock`, "PARSER");
    inputs.push({ outpointTxHashOpcodeOrder: Buffer.from(hash), outpointIndex: parseExactRuntimeBytes(outpoint, `TxView input ${i} outpoint index`), sequence: parseExactRuntimeBytes(sequence, `TxView input ${i} sequence`), sourceValueSats: parseExactRuntimeBytes(value, `TxView input ${i} value`), sourceLockingBytecode: Buffer.from(lock), tokenProjection });
  }
  let outputCount; [outputCount, cursor] = readU32be(bytes, cursor, "TxView output count");
  const baselineOutputs = action === "DEPOSIT" ? carrierCount + 1 : carrierCount + 2;
  requireOk(outputCount === baselineOutputs || outputCount === baselineOutputs + 1, "ERR_TOPOLOGY", "TxView output count", "PARSER");
  const hasChange = outputCount === baselineOutputs + 1;
  const outputs = [];
  for (let i = 0; i < outputCount; i += 1) {
    let wireIndex; let roleTag; let roleOrdinal; let value; let lock;
    [wireIndex, cursor] = readU32be(bytes, cursor, `TxView output ${i} wire index`);
    [roleTag, cursor] = readBytes(bytes, cursor, 1, `TxView output ${i} role tag`);
    [roleOrdinal, cursor] = readU32be(bytes, cursor, `TxView output ${i} role ordinal`);
    [value, cursor] = readBytes(bytes, cursor, 8, `TxView output ${i} value`);
    [lock, cursor] = readLp(bytes, cursor, `TxView output ${i} lock`);
    const expectedRole = outputRole(action, i, carrierCount, hasChange);
    requireOk(wireIndex === i && roleTag[0] === expectedRole.tag && roleOrdinal === expectedRole.ordinal, "ERR_TX_ROLE_ORDINAL", `TxView output ${i} role mapping`, "PARSER");
    const [tokenProjection, next] = parseTokenObservationV3(bytes, cursor, expectedRole.tokenRole, manifest.stateCategoryWire, `TxView output ${i}`);
    cursor = next;
    requireMoney(parseExactRuntimeBytes(value, `TxView output ${i} value`), `TxView output ${i} value`);
    requireOk(lock.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", `TxView output ${i} lock`, "PARSER");
    outputs.push({ valueSats: parseExactRuntimeBytes(value, `TxView output ${i} value`), lockingBytecode: Buffer.from(lock), tokenProjection });
  }
  let ticket; let direction; let fee; let cap; let payoutPresent; let payoutIndex; let changePresent; let changeIndex;
  [ticket, cursor] = readBytes(bytes, cursor, 8, "TxView economics ticket");
  [direction, cursor] = readBytes(bytes, cursor, 1, "TxView economics direction");
  [fee, cursor] = readBytes(bytes, cursor, 8, "TxView economics fee");
  [cap, cursor] = readBytes(bytes, cursor, 8, "TxView economics fee cap");
  [payoutPresent, cursor] = readBytes(bytes, cursor, 1, "TxView economics payout present");
  [payoutIndex, cursor] = readU32be(bytes, cursor, "TxView economics payout index");
  [changePresent, cursor] = readBytes(bytes, cursor, 1, "TxView economics change present");
  [changeIndex, cursor] = readU32be(bytes, cursor, "TxView economics change index");
  requireNoTrailing(bytes, cursor, "TxView");
  const actualFee = sumMoney(inputs, (item) => item.sourceValueSats, "TxView input sum") - sumMoney(outputs, (item) => item.valueSats, "TxView output sum");
  requireOk(actualFee >= 0n && actualFee <= manifest.feePolicyMaxSats, "ERR_FEE", "TxView fee is outside locked policy", "PARSER");
  const expectedDirection = action === "DEPOSIT" ? 0 : 1;
  const expectedPayoutPresent = action === "WITHDRAWAL" ? 1 : 0;
  const expectedPayoutIndex = action === "WITHDRAWAL" ? carrierCount + 1 : 0;
  const expectedChangePresent = hasChange ? 1 : 0;
  const expectedChangeIndex = hasChange ? (action === "DEPOSIT" ? carrierCount + 1 : carrierCount + 2) : 0;
  requireOk(parseExactRuntimeBytes(ticket, "TxView economics ticket") === TICKET_SATS && direction[0] === expectedDirection && parseExactRuntimeBytes(fee, "TxView economics fee") === actualFee && parseExactRuntimeBytes(cap, "TxView economics fee cap") === manifest.feePolicyMaxSats && payoutPresent[0] === expectedPayoutPresent && payoutIndex === expectedPayoutIndex && changePresent[0] === expectedChangePresent && changeIndex === expectedChangeIndex, "ERR_TXVIEW", "TxView economics", "PARSER");

  // A TxView action tag is derived evidence, never an independent selector.
  // Re-run every state/topology/economics check from the fully parsed bytes so
  // a caller cannot turn a syntactically valid alternate view into authority.
  const expectedState = expectedRoleLock(manifest, "STATE", 0);
  equalBytes(inputs[0].sourceLockingBytecode, expectedState.lock, "ERR_LOCK", "TxView state source lock", "PARSER");
  equalBytes(outputs[0].lockingBytecode, expectedState.lock, "ERR_LOCK", "TxView state successor lock", "PARSER");
  requireOk(inputs[0].outpointIndex === 0n, "ERR_LINEAGE", "TxView state source outpoint index", "PARSER");
  const oldState = parseStateCodec(hexToBytes(inputs[0].tokenProjection.commitmentHex, "TxView state source commitment", 128), manifest.poolInstanceId, "TxView state source");
  const newState = parseStateCodec(hexToBytes(outputs[0].tokenProjection.commitmentHex, "TxView state successor commitment", 128), manifest.poolInstanceId, "TxView state successor");
  checkStateInvariants(oldState, inputs[0].sourceValueSats, manifest, "TxView state source");
  checkStateInvariants(newState, outputs[0].valueSats, manifest, "TxView state successor");
  const derived = actionFromStateValues(inputs[0].sourceValueSats, outputs[0].valueSats);
  requireOk(derived.action === action && derived.reserveDirection === direction[0], "ERR_ACTION_DELTA", "TxView action tag is not derived from state value delta", "PARSER");
  checkStateTransition(oldState, newState, derived.action, manifest);
  const predecessorHash = inputs[0].outpointTxHashOpcodeOrder;
  for (let i = 0; i < carrierCount; i += 1) {
    const expectedCarrier = expectedRoleLock(manifest, "CARRIER", i);
    const source = inputs[i + 1];
    const successor = outputs[i + 1];
    equalBytes(source.outpointTxHashOpcodeOrder, predecessorHash, "ERR_LINEAGE", `TxView carrier ${i} predecessor hash`, "PARSER");
    requireOk(source.outpointIndex === BigInt(i + 1), "ERR_LINEAGE", `TxView carrier ${i} source outpoint index`, "PARSER");
    equalBytes(source.sourceLockingBytecode, expectedCarrier.lock, "ERR_LOCK", `TxView carrier ${i} source lock`, "PARSER");
    equalBytes(successor.lockingBytecode, expectedCarrier.lock, "ERR_LOCK", `TxView carrier ${i} successor lock`, "PARSER");
    requireOk(source.sourceValueSats === manifest.carrierLayout[i].expectedValueSats && successor.valueSats === manifest.carrierLayout[i].expectedValueSats, "ERR_CARRIER_VALUE", `TxView carrier ${i} configured value continuity`, "PARSER");
  }
  const external = inputs[carrierCount + 1];
  const changeValue = hasChange ? outputs[expectedChangeIndex].valueSats : 0n;
  if (derived.action === "WITHDRAWAL") requireOk(outputs[carrierCount + 1].valueSats === TICKET_SATS, "ERR_PAYOUT", "TxView withdrawal payout", "PARSER");
  if (derived.action === "DEPOSIT") requireOk(external.sourceValueSats === checkedMoneyAdd(TICKET_SATS, checkedMoneyAdd(changeValue, actualFee, "TxView deposit change plus fee"), "TxView deposit funding"), "ERR_ECONOMICS", "TxView deposit funding equation", "PARSER");
  else requireOk(external.sourceValueSats === checkedMoneyAdd(changeValue, actualFee, "TxView withdrawal fee funding"), "ERR_ECONOMICS", "TxView withdrawal fee funding equation", "PARSER");
  return { bytes, action, inputs, outputs, fee: actualFee, hasChange };
}

function makeCarrierSession(parsedCarriers) {
  const entries = [u32be(parsedCarriers.length)];
  const schedule = [u32be(parsedCarriers.length)];
  const payloads = [];
  let offset = 0;
  for (let i = 0; i < parsedCarriers.length; i += 1) {
    const carrier = parsedCarriers[i];
    requireOk(carrier.bytes.length <= MAX_SCRIPT_BYTES && carrier.bytes.length + 4 <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", `carrier ${i} full script or LP exceeds structural limit`, "STRUCTURAL");
    requireOk(carrier.frame.payload.length <= MAX_SCRIPT_BYTES - SEGMENT_FRAME_HEADER_BYTES && offset <= MAX_SCRIPT_BYTES && carrier.frame.payload.length <= MAX_SCRIPT_BYTES - offset, "ERR_SCRIPT_SIZE", `carrier ${i} payload/schedule offset exceeds structural limit`, "STRUCTURAL");
    entries.push(u32be(i), u32be(i + 1), lp(carrier.bytes));
    schedule.push(u32be(i), u32be(i + 1), u32be(offset), u32be(carrier.frame.payload.length));
    payloads.push(carrier.frame.payload);
    offset += carrier.frame.payload.length;
  }
  const carrierSessionBytes = Buffer.concat(entries);
  const envelopeBytes = Buffer.concat(payloads);
  const scheduleBytes = Buffer.concat(schedule);
  requireOk(envelopeBytes.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "reconstructed envelope exceeds structural limit", "STRUCTURAL");
  requireOk(scheduleBytes.length <= MAX_SCRIPT_BYTES, "ERR_SCRIPT_SIZE", "schedule exceeds structural limit", "STRUCTURAL");
  return {
    carrierSessionBytes,
    reconstructedEnvelopeBytes: envelopeBytes,
    scheduleBytes,
    carrierSessionRoot: domainHash("PoolActionFv2/carrier-session/v3", carrierSessionBytes),
    envelopeRoot: domainHash("PoolActionFv2/envelope/v3", envelopeBytes),
  };
}

export function parseCarrierSessionV3(input, carrierCount) {
  const bytes = Buffer.from(input);
  let cursor = 0;
  let count; [count, cursor] = readU32be(bytes, cursor, "carrier session count");
  requireOk(count === carrierCount && count >= 1 && count <= MAX_CARRIER_COUNT, "ERR_CARRIER_SESSION", "carrier session count", "PARSER");
  const carriers = [];
  for (let i = 0; i < count; i += 1) {
    let ordinal; let inputIndex; let fullScript;
    [ordinal, cursor] = readU32be(bytes, cursor, `carrier session ${i} ordinal`);
    [inputIndex, cursor] = readU32be(bytes, cursor, `carrier session ${i} input index`);
    [fullScript, cursor] = readLp(bytes, cursor, `carrier session ${i} full script`);
    requireOk(ordinal === i && inputIndex === i + 1 && fullScript.length + 4 <= MAX_SCRIPT_BYTES, "ERR_CARRIER_SESSION", `carrier session ${i} order/length`, "PARSER");
    const parsed = parseCarrierUnlockingBytecodeV3(fullScript);
    requireOk(parsed.frame.ordinal === i && parsed.frame.inputIndex === i + 1, "ERR_CARRIER_SESSION", `carrier session ${i} frame`, "PARSER");
    carriers.push(parsed);
  }
  requireNoTrailing(bytes, cursor, "carrier session");
  return { bytes, carriers };
}

export function parseScheduleV3(input, carrierParses) {
  const bytes = Buffer.from(input);
  let cursor = 0;
  let count; [count, cursor] = readU32be(bytes, cursor, "schedule count");
  requireOk(count === carrierParses.length, "ERR_SCHEDULE", "schedule count", "PARSER");
  let offset = 0;
  for (let i = 0; i < count; i += 1) {
    let ordinal; let inputIndex; let encodedOffset; let length;
    [ordinal, cursor] = readU32be(bytes, cursor, `schedule ${i} ordinal`);
    [inputIndex, cursor] = readU32be(bytes, cursor, `schedule ${i} input index`);
    [encodedOffset, cursor] = readU32be(bytes, cursor, `schedule ${i} offset`);
    [length, cursor] = readU32be(bytes, cursor, `schedule ${i} length`);
    requireOk(ordinal === i && inputIndex === i + 1 && encodedOffset === offset && length === carrierParses[i].frame.payload.length && encodedOffset <= MAX_SCRIPT_BYTES && length <= MAX_SCRIPT_BYTES - encodedOffset, "ERR_SCHEDULE", `schedule ${i} entry`, "PARSER");
    offset += length;
  }
  requireNoTrailing(bytes, cursor, "schedule");
  return { bytes, envelopeLength: offset };
}

export function deriveRelationV3(input) {
  requireExactKeys(input, ["schema", "relationId", "relationVersion", "abiVersion", "transaction", "stateActiveRedeemHex", "carrierUnlockingBytecodesHex", "verifierRoleConsumptions"], "relation input");
  requireOk(input.schema === "shieldkit-labs/poolaction-fv2/relation-input/v3", "ERR_SCHEMA_ID", "relation input schema", "SCHEMA");
  requireOk(input.relationId === RELATION_ID && input.relationVersion === RELATION_VERSION && input.abiVersion === ABI_VERSION, "ERR_IDENTITY", "relation identity", "SCHEMA");
  const stateRedeem = parseStructuralRedeemV3(hexToBytes(input.stateActiveRedeemHex, "stateActiveRedeemHex"));
  const manifest = stateRedeem.manifest;
  requireOk(manifest.proofSuiteStatusByte === 0, "ERR_PROOF_SUITE_UNSUPPORTED", "selected proof suites are outside this structural package", "STRUCTURAL");
  const carrierUnlockingBytecodes = requireArray(input.carrierUnlockingBytecodesHex, "carrierUnlockingBytecodesHex").map((item, i) => hexToBytes(item, `carrierUnlockingBytecodesHex[${i}]`));
  const transaction = parseTransactionEvidence(input.transaction);
  checkRoleLocalConsumptions(input.verifierRoleConsumptions, manifest);
  const details = deriveAndCheckTransaction(manifest, transaction, stateRedeem, carrierUnlockingBytecodes);
  checkRoleLocalByteConsumptionV3(input.verifierRoleConsumptions, manifest, transaction, stateRedeem, details.carrierParses);
  const txViewBytes = encodeTxViewV3(manifest, transaction, details);
  const parsedTxView = parseTxViewV3(txViewBytes, manifest);
  requireOk(parsedTxView.action === details.action && parsedTxView.fee === details.fee, "ERR_TXVIEW", "self-parsed TxView disagreement", "CODEC");
  const session = makeCarrierSession(details.carrierParses);
  const parsedCarrierSession = parseCarrierSessionV3(session.carrierSessionBytes, manifest.carrierCount);
  const parsedSchedule = parseScheduleV3(session.scheduleBytes, parsedCarrierSession.carriers);
  requireOk(parsedSchedule.envelopeLength === session.reconstructedEnvelopeBytes.length, "ERR_SCHEDULE", "self-parsed schedule envelope length", "CODEC");
  const contextDigest = domainHash("PoolActionFv2/context/v3", manifest.deploymentCommitment, txViewBytes);
  const sessionDigest = domainHash(
    "PoolActionFv2/session/v3",
    contextDigest,
    session.carrierSessionRoot,
    session.envelopeRoot,
    session.scheduleBytes,
    manifest.proofSuiteManifestDigest,
  );
  return {
    relationId: RELATION_ID,
    relationVersion: RELATION_VERSION,
    abiVersion: ABI_VERSION,
    action: details.action,
    actionTagHex: details.actionTag.toString(16).padStart(2, "0"),
    deploymentManifestCoreHex: bytesToHex(manifest.core),
    poolIdentityConfigHex: bytesToHex(manifest.poolIdentityConfig),
    poolInstanceIdHex: bytesToHex(manifest.poolInstanceId),
    deploymentCommitmentHex: bytesToHex(manifest.deploymentCommitment),
    roleArtifacts: [{ roleClass: "STATE", ordinal: 0, roleInstanceHex: bytesToHex(expectedRoleLock(manifest, "STATE", 0).role), redeemHex: bytesToHex(expectedRoleLock(manifest, "STATE", 0).redeem), lockHex: bytesToHex(expectedRoleLock(manifest, "STATE", 0).lock) }, ...Array.from({ length: manifest.carrierCount }, (_, ordinal) => {
      const role = expectedRoleLock(manifest, "CARRIER", ordinal);
      return { roleClass: "CARRIER", ordinal, roleInstanceHex: bytesToHex(role.role), redeemHex: bytesToHex(role.redeem), lockHex: bytesToHex(role.lock) };
    })],
    txViewBytesHex: bytesToHex(txViewBytes),
    carrierSessionBytesHex: bytesToHex(session.carrierSessionBytes),
    reconstructedEnvelopeBytesHex: bytesToHex(session.reconstructedEnvelopeBytes),
    scheduleBytesHex: bytesToHex(session.scheduleBytes),
    carrierSessionRootHex: bytesToHex(session.carrierSessionRoot),
    envelopeRootHex: bytesToHex(session.envelopeRoot),
    contextDigestHex: bytesToHex(contextDigest),
    sessionDigestHex: bytesToHex(sessionDigest),
    proofSuiteStatus: "UNSELECTED",
    proofAccepted: false,
    verdict: UNSELECTED_PROOF_VERDICT,
    structuralOnly: true,
  };
}

const CANONICAL_DEPENDENCY_NODES = Object.freeze([
  "lockSelectedManifest", "introspectedTransaction", "deploymentCommitment", "txViewBytes", "contextDigest",
  "proofPublicInput", "carrierPayloads", "carrierSessionBytes", "reconstructedEnvelopeBytes", "scheduleBytes",
  "carrierSessionRoot", "envelopeRoot", "sessionDigest",
]);
const CANONICAL_DEPENDENCY_EDGES = Object.freeze([
  ["lockSelectedManifest", "deploymentCommitment"],
  ["lockSelectedManifest", "txViewBytes"],
  ["introspectedTransaction", "txViewBytes"],
  ["deploymentCommitment", "contextDigest"],
  ["txViewBytes", "contextDigest"],
  ["contextDigest", "proofPublicInput"],
  ["proofPublicInput", "carrierPayloads"],
  ["carrierPayloads", "carrierSessionBytes"],
  ["carrierPayloads", "reconstructedEnvelopeBytes"],
  ["carrierPayloads", "scheduleBytes"],
  ["carrierSessionBytes", "carrierSessionRoot"],
  ["reconstructedEnvelopeBytes", "envelopeRoot"],
  ["contextDigest", "sessionDigest"],
  ["carrierSessionRoot", "sessionDigest"],
  ["envelopeRoot", "sessionDigest"],
  ["scheduleBytes", "sessionDigest"],
]);

export function canonicalDependencyGraphV3() {
  return {
    schema: "shieldkit-labs/poolaction-fv2/dependency-graph/v3",
    relationId: RELATION_ID,
    relationVersion: RELATION_VERSION,
    abiVersion: ABI_VERSION,
    nodes: [...CANONICAL_DEPENDENCY_NODES],
    edges: CANONICAL_DEPENDENCY_EDGES.map(([from, to]) => ({ from, to })),
  };
}

function exactStringSet(actual, expected, code, name) {
  requireOk(JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort()), code, `${name} exact-set mismatch`, "COVERAGE");
}

export function validateDependencyGraphV3(graph) {
  requireExactKeys(graph, ["schema", "relationId", "relationVersion", "abiVersion", "nodes", "edges"], "dependency graph");
  requireOk(graph.schema === "shieldkit-labs/poolaction-fv2/dependency-graph/v3" && graph.relationId === RELATION_ID && graph.relationVersion === RELATION_VERSION && graph.abiVersion === ABI_VERSION, "ERR_DEPENDENCY_IDENTITY", "dependency graph identity", "DEPENDENCY");
  requireArray(graph.nodes, "dependency graph nodes");
  exactStringSet(graph.nodes, CANONICAL_DEPENDENCY_NODES, "ERR_DEPENDENCY_NODES", "dependency graph nodes");
  requireOk(new Set(graph.nodes).size === graph.nodes.length, "ERR_DEPENDENCY_NODES", "duplicate dependency node", "DEPENDENCY");
  requireArray(graph.edges, "dependency graph edges");
  const actualEdges = [];
  for (let i = 0; i < graph.edges.length; i += 1) {
    const edge = graph.edges[i];
    requireExactKeys(edge, ["from", "to"], `dependency edge ${i}`);
    requireOk(graph.nodes.includes(edge.from) && graph.nodes.includes(edge.to) && edge.from !== edge.to, "ERR_DEPENDENCY_EDGE", `invalid dependency edge ${i}`, "DEPENDENCY");
    actualEdges.push(`${edge.from}>${edge.to}`);
  }
  requireOk(new Set(actualEdges).size === actualEdges.length, "ERR_DEPENDENCY_EDGE", "duplicate dependency edge", "DEPENDENCY");
  exactStringSet(actualEdges, CANONICAL_DEPENDENCY_EDGES.map(([from, to]) => `${from}>${to}`), "ERR_DEPENDENCY_EDGE", "dependency graph edges");
  const adjacency = new Map(graph.nodes.map((node) => [node, []]));
  for (const edge of graph.edges) adjacency.get(edge.from).push(edge.to);
  const visiting = new Set(); const seen = new Set();
  const visit = (node) => {
    requireOk(!visiting.has(node), "ERR_DEPENDENCY_CYCLE", `dependency cycle at ${node}`, "DEPENDENCY");
    if (seen.has(node)) return;
    visiting.add(node);
    for (const target of adjacency.get(node)) visit(target);
    visiting.delete(node); seen.add(node);
  };
  for (const node of graph.nodes) visit(node);
  return true;
}

function dependencyNodesForLeaf(leafId, sourceClass) {
  if (sourceClass !== "DERIVED_AND_CHECKED") return [];
  if (leafId === "deployment.commitment") return ["lockSelectedManifest"];
  if (leafId === "poolIdentityConfig.recomputedPoolInstanceId") return ["lockSelectedManifest"];
  if (leafId.startsWith("roleInstance.")) return ["lockSelectedManifest", "introspectedTransaction"];
  if (leafId.startsWith("poolState.") || leafId.startsWith("txView.")) return ["lockSelectedManifest", "introspectedTransaction"];
  if (leafId.startsWith("carrier[")) return ["carrierPayloads"];
  if (leafId === "roots.carrierSessionBytes" || leafId === "roots.reconstructedEnvelopeBytes" || leafId === "roots.scheduleBytes") return ["carrierPayloads"];
  if (leafId === "roots.carrierSessionRoot") return ["carrierSessionBytes"];
  if (leafId === "roots.envelopeRoot") return ["reconstructedEnvelopeBytes"];
  if (leafId === "roots.contextDigest") return ["deploymentCommitment", "txViewBytes"];
  if (leafId === "roots.sessionDigest") return ["contextDigest", "carrierSessionRoot", "envelopeRoot", "scheduleBytes"];
  fail("ERR_COVERAGE_DEPENDENCY", `no declared dependency nodes for ${leafId}`, "COVERAGE");
}

function addLeaf(list, leafId, sourceClass) {
  list.push({ leafId, sourceClass, dependencyNodes: dependencyNodesForLeaf(leafId, sourceClass) });
}
function listFields(prefix, fields, sourceClass, output) { for (const field of fields) addLeaf(output, `${prefix}.${field}`, sourceClass); }

export function buildCodecLeafEntriesV3(carrierCount, inputCount = carrierCount + 2, outputCount = carrierCount + 1) {
  requireOk(Number.isInteger(carrierCount) && carrierCount >= 1 && carrierCount <= MAX_CARRIER_COUNT, "ERR_COVERAGE", "carrier count", "COVERAGE");
  requireOk(inputCount === carrierCount + 2 && outputCount >= carrierCount + 1 && outputCount <= carrierCount + 3, "ERR_COVERAGE", "topology counts", "COVERAGE");
  const leaves = [];
  listFields("manifest", ["magic", "abiVersion", "reserved", "ticketSats", "noUpgrade"], "CODEC_CONSTANT", leaves);
  listFields("manifest", ["networkTag", "protocolTemplateDigest", "poolInstanceId", "preExistingAnchorDigest", "genesisAncestryDigest", "stateCategoryWire", "stateCarrierBaseSats", "maxLifetimeDeposits", "feePolicyMaxSats", "proofSuiteStatus", "proofSuiteManifestDigest", "carrierCount"], "LOCK_SELECTED_EMBEDDED", leaves);
  listFields("poolIdentityConfig", ["magic", "abiVersion", "reserved", "ticketSats", "noUpgrade"], "CODEC_CONSTANT", leaves);
  listFields("poolIdentityConfig", ["networkTag", "protocolTemplateDigest", "preExistingAnchorDigest", "stateCategoryWire", "stateCarrierBaseSats", "maxLifetimeDeposits", "feePolicyMaxSats", "proofSuiteStatus", "proofSuiteManifestDigest", "carrierCount"], "LOCK_SELECTED_EMBEDDED", leaves);
  addLeaf(leaves, "poolIdentityConfig.recomputedPoolInstanceId", "DERIVED_AND_CHECKED");
  for (let i = 0; i < carrierCount; i += 1) {
    listFields(`manifest.carrierLayout[${i}]`, ["ordinal", "inputIndex", "outputIndex", "expectedValueSats"], "LOCK_SELECTED_EMBEDDED", leaves);
    listFields(`poolIdentityConfig.carrierLayout[${i}]`, ["ordinal", "inputIndex", "outputIndex", "expectedValueSats"], "LOCK_SELECTED_EMBEDDED", leaves);
  }
  for (const map of ["depositRoleMap", "withdrawalRoleMap"]) {
    listFields(`manifest.${map}`, ["stateInputIndex", "externalInputIndex", "stateOutputIndex", "payoutPresent", "payoutOutputIndex", "changeOptional", "changeOutputIndex"], "LOCK_SELECTED_EMBEDDED", leaves);
    listFields(`poolIdentityConfig.${map}`, ["stateInputIndex", "externalInputIndex", "stateOutputIndex", "payoutPresent", "payoutOutputIndex", "changeOptional", "changeOutputIndex"], "LOCK_SELECTED_EMBEDDED", leaves);
  }
  listFields("deployment", ["domain"], "CODEC_CONSTANT", leaves);
  addLeaf(leaves, "deployment.commitment", "DERIVED_AND_CHECKED");
  for (const role of ["state", ...Array.from({ length: carrierCount }, (_, i) => `carrier[${i}]`)]) {
    listFields(`roleInstance.${role}`, ["magic", "abiVersion", "roleTag", "redeemDrop1", "redeemDrop2", "redeemFalse", "lockHash160Opcode", "lockPush20", "lockEqualOpcode"], "CODEC_CONSTANT", leaves);
    listFields(`roleInstance.${role}`, ["ordinal", "fixedInputIndex", "fixedOutputIndex", "redeemMinimalManifestPush", "redeemMinimalRolePush", "finalRedeem"], "LOCK_SELECTED_EMBEDDED", leaves);
    addLeaf(leaves, `roleInstance.${role}.lockRedeemHash160`, "DERIVED_AND_CHECKED");
    addLeaf(leaves, `roleInstance.${role}.localObservedInputIndex`, "INTROSPECTED");
    addLeaf(leaves, `roleInstance.${role}.localFixedIndexCheck`, "DERIVED_AND_CHECKED");
  }
  listFields("txView", ["magic", "abiVersion", "reserved", "ticketSats"], "CODEC_CONSTANT", leaves);
  listFields("txView", ["derivedActionTag", "carrierCount", "inputCount", "outputCount", "reserveDirection", "feeSats", "payoutPresent", "payoutOutputIndex", "changePresent", "changeOutputIndex"], "DERIVED_AND_CHECKED", leaves);
  addLeaf(leaves, "txView.transactionVersion", "INTROSPECTED");
  addLeaf(leaves, "txView.locktime", "INTROSPECTED");
  addLeaf(leaves, "txView.feePolicyMaxSats", "LOCK_SELECTED_EMBEDDED");
  for (let i = 0; i < inputCount; i += 1) {
    listFields(`txView.input[${i}]`, ["wireIndex", "derivedRoleTag", "derivedRoleOrdinal", "sourceLockingBytecodeLength", "tokenTag", "tokenCategoryLength", "tokenCommitmentLength", "unlockingDisposition"], "DERIVED_AND_CHECKED", leaves);
    listFields(`txView.input[${i}]`, ["outpointTxHashOpcodeOrder", "outpointIndex", "sequence", "sourceValueSats", "sourceLockingBytecode", "tokenCategory", "tokenCommitment", "tokenAmount"], "INTROSPECTED", leaves);
  }
  for (let i = 0; i < outputCount; i += 1) {
    listFields(`txView.output[${i}]`, ["wireIndex", "derivedRoleTag", "derivedRoleOrdinal", "lockingBytecodeLength", "tokenTag", "tokenCategoryLength", "tokenCommitmentLength"], "DERIVED_AND_CHECKED", leaves);
    listFields(`txView.output[${i}]`, ["valueSats", "lockingBytecode", "tokenCategory", "tokenCommitment", "tokenAmount"], "INTROSPECTED", leaves);
  }
  for (const state of ["source", "successor"]) {
    listFields(`poolState.${state}`, ["magic", "stateCodecVersion", "reserved"], "CODEC_CONSTANT", leaves);
    listFields(`poolState.${state}`, ["sequence", "depositCount", "withdrawalCount", "poolInstanceId", "noteRoot", "nullifierRoot"], "INTROSPECTED", leaves);
    addLeaf(leaves, `poolState.${state}.poolInstanceIdMatchesLockSelectedPool`, "DERIVED_AND_CHECKED");
    addLeaf(leaves, `poolState.${state}.valueInvariant`, "DERIVED_AND_CHECKED");
  }
  listFields("poolState.transition", ["actionFromValueDelta", "sequenceNonWrappingIncrement", "depositCountTransition", "withdrawalCountTransition", "activeRootTransition"], "DERIVED_AND_CHECKED", leaves);
  for (let i = 0; i < carrierCount; i += 1) {
    listFields(`carrier[${i}]`, ["fullUnlockingBytecode", "finalRedeemPush", "framePayload"], "INTROSPECTED", leaves);
    listFields(`carrier[${i}]`, ["frameMagic", "frameAbiVersion"], "CODEC_CONSTANT", leaves);
    listFields(`carrier[${i}]`, ["frameOrdinal", "frameInputIndex", "framePayloadLength", "finalRedeem", "sessionOrdinal", "sessionInputIndex", "sessionFullBytecodeLength", "scheduleOrdinal", "scheduleInputIndex", "scheduleOffset", "scheduleLength"], "DERIVED_AND_CHECKED", leaves);
  }
  listFields("roots", ["carrierSessionDomain", "envelopeDomain", "contextDomain", "sessionDomain"], "CODEC_CONSTANT", leaves);
  listFields("roots", ["carrierSessionBytes", "reconstructedEnvelopeBytes", "scheduleBytes", "carrierSessionRoot", "envelopeRoot", "contextDigest", "sessionDigest"], "DERIVED_AND_CHECKED", leaves);
  return leaves;
}

export function buildCodecLeafRosterV3(carrierCount, inputCount = carrierCount + 2, outputCount = carrierCount + 1) {
  return buildCodecLeafEntriesV3(carrierCount, inputCount, outputCount).map((entry) => entry.leafId);
}

export function buildFieldSourceTableV3(carrierCount, inputCount = carrierCount + 2, outputCount = carrierCount + 1) {
  return buildCodecLeafEntriesV3(carrierCount, inputCount, outputCount).map(({ leafId, sourceClass, dependencyNodes }) => ({ leafId, sourceClass, dependencyNodes }));
}

export function validateFieldSourceCoverageV3(roster, table) {
  requireArray(roster, "codec leaf roster");
  requireArray(table, "field source table");
  const validLeaf = (leaf) => typeof leaf === "string" && leaf.length > 0 && !/[＊*]/.test(leaf) && !/(?:\[\]|\ball\b|\bany\b)/i.test(leaf);
  requireOk(roster.every(validLeaf), "ERR_COVERAGE_WILDCARD", "roster has wildcard or grouped leaf", "COVERAGE");
  requireOk(new Set(roster).size === roster.length, "ERR_COVERAGE_DUPLICATE", "roster has duplicate leaf", "COVERAGE");
  const ids = [];
  for (let i = 0; i < table.length; i += 1) {
    const row = table[i];
    requireExactKeys(row, ["leafId", "sourceClass", "dependencyNodes"], `source table row ${i}`);
    requireOk(validLeaf(row.leafId), "ERR_COVERAGE_WILDCARD", `source table leaf ${i}`, "COVERAGE");
    requireOk(ALLOWED_SOURCE_CLASSES.has(row.sourceClass), "ERR_COVERAGE_CLASS", `source table class ${i}`, "COVERAGE");
    requireArray(row.dependencyNodes, `source table dependency nodes ${i}`);
    requireOk(new Set(row.dependencyNodes).size === row.dependencyNodes.length, "ERR_COVERAGE_DEPENDENCY", `source table dependency nodes ${i} duplicate`, "COVERAGE");
    for (const node of row.dependencyNodes) requireOk(CANONICAL_DEPENDENCY_NODES.includes(node), "ERR_COVERAGE_DEPENDENCY", `source table dependency node ${node}`, "COVERAGE");
    if (row.sourceClass === "DERIVED_AND_CHECKED") requireOk(row.dependencyNodes.length > 0, "ERR_COVERAGE_DEPENDENCY", `derived leaf ${row.leafId} has no dependency declaration`, "COVERAGE");
    else requireOk(row.dependencyNodes.length === 0, "ERR_COVERAGE_DEPENDENCY", `non-derived leaf ${row.leafId} declares dependencies`, "COVERAGE");
    ids.push(row.leafId);
  }
  requireOk(new Set(ids).size === ids.length, "ERR_COVERAGE_DUPLICATE", "source table has duplicate leaf", "COVERAGE");
  exactStringSet(ids, roster, "ERR_COVERAGE_SET", "field source table");
  return true;
}

export function validateNoV2Namespace(value, name = "ABI3 value") {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const prohibited = ["/v2", "P2DM", "P2RI", "P2TV", "P2SG", "P2RT", "P2TS", "P2GR", "P2PE"];
  for (const token of prohibited) requireOk(!text.includes(token), "ERR_V2_NAMESPACE", `${name} contains ${token}`, "SCHEMA");
  return true;
}
