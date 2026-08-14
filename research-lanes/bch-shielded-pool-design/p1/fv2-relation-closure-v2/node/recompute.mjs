#!/usr/bin/env node
/*
 * PoolActionFv2 v2 structural reference recomputer.
 *
 * This module deliberately shares no correctness-critical codec with Fv1. It
 * consumes raw binary manifest/template/anchor/transaction/source-output and
 * carrier-unlocking inputs, recomputes every displayed result, and always
 * stops at REJECT_UNSELECTED_PROOF_SUITE. The structural compiler below is the
 * charter's always-false P2SH20 compiler: it is not BCH VM, standardness, or
 * complete-transaction acceptance evidence.
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const ASCII = (text) => Buffer.from(text, "ascii");
const ZERO32 = Buffer.alloc(32);
const TICKET = 10_000_000n;
const NETWORKS = ["mainnet", "chipnet", "regtest"];

export class RecomputeError extends Error {
  constructor(code, message) { super(`${code}: ${message}`); this.code = code; }
}
const fail = (code, message) => { throw new RecomputeError(code, message); };
const requireThat = (condition, code, message) => { if (!condition) fail(code, message); };
const sha256 = (bytes) => createHash("sha256").update(bytes).digest();
const hash160 = (bytes) => createHash("ripemd160").update(sha256(bytes)).digest();
const u16be = (n) => { requireThat(Number.isInteger(n) && n >= 0 && n <= 0xffff, "ERR_U16", "u16 out of range"); const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32be = (n) => { requireThat(Number.isInteger(n) && n >= 0 && n <= 0xffffffff, "ERR_U32", "u32 out of range"); const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const U64_RUNTIME_MAX = 0x7fff_ffff_ffff_ffffn;
const u64le = (n) => { const x = BigInt(n); requireThat(x >= 0n && x <= U64_RUNTIME_MAX, "ERR_U64", "u64 is outside the nonnegative runtime VM range"); const b = Buffer.alloc(8); b.writeBigUInt64LE(x); return b; };
const lp = (bytes) => { const b = Buffer.from(bytes); requireThat(b.length <= 0xffffffff, "ERR_LENGTH", "LP length exceeds u32"); return Buffer.concat([u32be(b.length), b]); };
const outerHash = (domain, ...parts) => sha256(Buffer.concat([ASCII(domain), Buffer.of(0), ...parts.map(lp)]));
const hexBytes = (value, label) => {
  requireThat(typeof value === "string" && /^[0-9a-f]*$/.test(value) && value.length % 2 === 0, "ERR_HEX", `${label} must be lowercase even-length hex`);
  return Buffer.from(value, "hex");
};
const hex32 = (value, label) => { const b = hexBytes(value, label); requireThat(b.length === 32, "ERR_BYTES32", `${label} must be bytes32`); return b; };
const exactly = (actual, expected, code, label) => requireThat(Buffer.from(actual).equals(Buffer.from(expected)), code, `${label} differs`);
const canonicalObject = (value, keys, label) => {
  requireThat(value !== null && typeof value === "object" && !Array.isArray(value), "ERR_OBJECT", `${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  requireThat(actual.length === expected.length && actual.every((key, i) => key === expected[i]), "ERR_KEYS", `${label} keys are not canonical`);
};

class Reader {
  constructor(bytes, label) { this.bytes = Buffer.from(bytes); this.label = label; this.offset = 0; }
  remaining() { return this.bytes.length - this.offset; }
  take(length, field) {
    requireThat(Number.isSafeInteger(length) && length >= 0 && length <= this.remaining(), "ERR_TRUNCATED", `${this.label}.${field} is truncated`);
    const result = this.bytes.subarray(this.offset, this.offset + length); this.offset += length; return result;
  }
  u8(field) { return this.take(1, field)[0]; }
  u16be(field) { return this.take(2, field).readUInt16BE(); }
  u32be(field) { return this.take(4, field).readUInt32BE(); }
  u32le(field) { return this.take(4, field).readUInt32LE(); }
  u64le(field) { return this.take(8, field).readBigUInt64LE(); }
  lp(field) { return this.take(this.u32be(`${field}.length`), field); }
  compact(field) {
    const tag = this.u8(field);
    if (tag < 253) return BigInt(tag);
    if (tag === 253) { const n = BigInt(this.take(2, field).readUInt16LE()); requireThat(n >= 253n, "ERR_COMPACT", `${this.label}.${field} is noncanonical`); return n; }
    if (tag === 254) { const n = BigInt(this.take(4, field).readUInt32LE()); requireThat(n > 0xffffn, "ERR_COMPACT", `${this.label}.${field} is noncanonical`); return n; }
    const n = this.take(8, field).readBigUInt64LE(); requireThat(n > 0xffffffffn, "ERR_COMPACT", `${this.label}.${field} is noncanonical`); return n;
  }
  compactLength(field, maximum = 100000) {
    const n = this.compact(field); requireThat(n <= BigInt(maximum), "ERR_LENGTH", `${this.label}.${field} exceeds structural bound`); return Number(n);
  }
  done() { requireThat(this.remaining() === 0, "ERR_TRAILING", `${this.label} has trailing bytes`); }
}

function parseTemplateSet(raw) {
  const r = new Reader(raw, "TemplateSetV2Bytes");
  exactly(r.take(4, "magic"), ASCII("P2TS"), "ERR_TEMPLATE_MAGIC", "template magic");
  requireThat(r.u16be("version") === 2, "ERR_TEMPLATE_VERSION", "template version must be 2");
  const toolchainBytes = r.lp("toolchainId");
  const toolchainId = toolchainBytes.toString("utf8");
  requireThat(toolchainBytes.length > 0 && !toolchainBytes.includes(0) && Buffer.from(toolchainId, "utf8").equals(toolchainBytes), "ERR_TOOLCHAIN", "toolchainId is not canonical non-NUL UTF-8");
  const stateTemplate = r.lp("normalizedStateTemplateBytes");
  const carrierTemplate = r.lp("normalizedCarrierTemplateBytes");
  requireThat(stateTemplate.length > 0 && carrierTemplate.length > 0 && !stateTemplate.equals(carrierTemplate), "ERR_TEMPLATE", "templates must be nonempty and distinct");
  r.done();
  return { raw: Buffer.from(raw), toolchainId, toolchainBytes, stateTemplate, carrierTemplate };
}

function parseManifest(raw) {
  const r = new Reader(raw, "DeploymentManifestV2CoreBytes");
  exactly(r.take(4, "magic"), ASCII("P2DM"), "ERR_MANIFEST_MAGIC", "manifest magic");
  requireThat(r.u16be("version") === 2, "ERR_MANIFEST_VERSION", "manifest version must be 2");
  const networkTag = r.u8("networkTag"); requireThat(networkTag < NETWORKS.length, "ERR_NETWORK", "network tag is reserved");
  requireThat(r.u8("reserved") === 0, "ERR_MANIFEST_RESERVED", "manifest reserved byte must be zero");
  const protocolTemplateDigest = r.take(32, "protocolTemplateDigest");
  const poolInstanceId = r.take(32, "poolInstanceId");
  const preExistingAnchorDigest = r.take(32, "preExistingAnchorDigest");
  const genesisAncestryDigest = r.take(32, "genesisAncestryDigest");
  const stateCategoryWire = r.take(32, "stateCategoryWire");
  const ticketSats = r.u64le("ticketSats"); requireThat(ticketSats === TICKET, "ERR_TICKET", "manifest ticket must be 10000000");
  const feePolicyMaxSats = r.u64le("feePolicyMaxSats");
  const proofSuiteStatus = r.u8("proofSuiteStatus");
  const proofSuiteManifestDigest = r.take(32, "proofSuiteManifestDigest");
  requireThat(proofSuiteStatus === 0 && proofSuiteManifestDigest.equals(ZERO32), "ERR_PROOF_SUITE", "only UNSELECTED with zero digest is admitted");
  const carrierCount = r.u32be("carrierCount"); requireThat(carrierCount >= 1, "ERR_CARRIER_COUNT", "carrier count must be at least one");
  const carrierLayout = [];
  for (let ordinal = 0; ordinal < carrierCount; ordinal += 1) {
    const actualOrdinal = r.u32be(`carrierLayout[${ordinal}].ordinal`);
    const inputIndex = r.u32be(`carrierLayout[${ordinal}].inputIndex`);
    const outputIndex = r.u32be(`carrierLayout[${ordinal}].outputIndex`);
    const expectedValueSats = r.u64le(`carrierLayout[${ordinal}].expectedValueSats`);
    requireThat(actualOrdinal === ordinal && inputIndex === ordinal + 1 && outputIndex === ordinal + 1, "ERR_CARRIER_LAYOUT", `carrier layout ${ordinal} is not canonical`);
    carrierLayout.push({ ordinal, inputIndex, outputIndex, expectedValueSats });
  }
  const readRoleMap = (kind) => ({
    stateInputIndex: r.u32be(`${kind}.stateInputIndex`), externalInputIndex: r.u32be(`${kind}.externalInputIndex`),
    stateOutputIndex: r.u32be(`${kind}.stateOutputIndex`), payoutPresent: r.u8(`${kind}.payoutPresent`),
    payoutOutputIndex: r.u32be(`${kind}.payoutOutputIndex`), changeOptional: r.u8(`${kind}.changeOptional`),
    changeOutputIndex: r.u32be(`${kind}.changeOutputIndex`),
  });
  const depositRoleMap = readRoleMap("depositRoleMap"); const withdrawalRoleMap = readRoleMap("withdrawalRoleMap"); r.done();
  const checkMap = (map, withdrawal) => {
    requireThat(map.stateInputIndex === 0 && map.externalInputIndex === carrierCount + 1 && map.stateOutputIndex === 0 && map.changeOptional === 1, "ERR_ROLE_MAP", "role map fixed indexes differ");
    requireThat(map.payoutPresent === (withdrawal ? 1 : 0) && map.payoutOutputIndex === (withdrawal ? carrierCount + 1 : 0) && map.changeOutputIndex === carrierCount + (withdrawal ? 2 : 1), "ERR_ROLE_MAP", "role map payout/change differs");
  };
  checkMap(depositRoleMap, false); checkMap(withdrawalRoleMap, true);
  return { raw: Buffer.from(raw), networkTag, networkId: NETWORKS[networkTag], protocolTemplateDigest, poolInstanceId, preExistingAnchorDigest, genesisAncestryDigest, stateCategoryWire, ticketSats, feePolicyMaxSats, proofSuiteStatus, proofSuiteManifestDigest, carrierCount, carrierLayout, depositRoleMap, withdrawalRoleMap };
}

function parseAnchor(raw) {
  requireThat(raw.length === 36, "ERR_ANCHOR", "pre-existing anchor must be bytes32||u32be");
  return { raw: Buffer.from(raw), txHash: raw.subarray(0, 32), outputIndex: raw.readUInt32BE(32), outputIndexBytes: raw.subarray(32, 36) };
}

function parseNativeToken(r, label) {
  if (r.remaining() === 0 || r.bytes[r.offset] !== 0xef) return { kind: "none" };
  r.u8(`${label}.prefix`); const category = r.take(32, `${label}.category`); const bitfield = r.u8(`${label}.bitfield`);
  const hasCommitment = (bitfield & 0x40) !== 0; const hasAmount = (bitfield & 0x10) !== 0;
  let commitment = Buffer.alloc(0); let amount = 0n;
  if (hasCommitment) commitment = r.take(r.compactLength(`${label}.commitmentLength`, 10000), `${label}.commitment`);
  if (hasAmount) amount = r.compact(`${label}.amount`);
  return { kind: "token", category, bitfield, commitment, amount };
}
function parseBchOutput(raw, label) {
  const r = new Reader(raw, label); const token = parseNativeToken(r, label); const value = r.u64le("valueSats"); requireThat(value <= U64_RUNTIME_MAX, "ERR_U64", `${label}.valueSats is outside the nonnegative runtime VM range`); const lockingBytecode = r.take(r.compactLength("lockingBytecodeLength", 10000), "lockingBytecode"); requireThat(lockingBytecode.length > 0, "ERR_LOCK", `${label}.lockingBytecode must be nonempty`); r.done(); return { raw: Buffer.from(raw), token, value, lockingBytecode };
}
function parseTransaction(raw) {
  requireThat(raw.length <= 100000, "ERR_TX_SIZE", "structural transaction exceeds 100000 bytes");
  const r = new Reader(raw, "transaction"); const version = r.u32le("version"); const inputCount = r.compactLength("inputCount", 100000); const inputs = [];
  for (let i = 0; i < inputCount; i += 1) {
    const outpointTxHash = r.take(32, `inputs[${i}].outpointTxHashOpcodeOrder`); const outpointIndex = r.u32le(`inputs[${i}].outpointIndex`);
    const unlockingBytecode = r.take(r.compactLength(`inputs[${i}].unlockingBytecodeLength`, 10000), `inputs[${i}].unlockingBytecode`); const sequence = r.u32le(`inputs[${i}].sequence`);
    inputs.push({ outpointTxHash, outpointIndex, unlockingBytecode, sequence });
  }
  const outputCount = r.compactLength("outputCount", 100000); const outputs = [];
  for (let i = 0; i < outputCount; i += 1) {
    const start = r.offset; const token = parseNativeToken(r, `outputs[${i}]`); const value = r.u64le(`outputs[${i}].valueSats`); requireThat(value <= U64_RUNTIME_MAX, "ERR_U64", `outputs[${i}].valueSats is outside the nonnegative runtime VM range`); const lockingBytecode = r.take(r.compactLength(`outputs[${i}].lockingBytecodeLength`, 10000), `outputs[${i}].lockingBytecode`); requireThat(lockingBytecode.length > 0, "ERR_LOCK", `outputs[${i}].lockingBytecode must be nonempty`); outputs.push({ raw: r.bytes.subarray(start, r.offset), token, value, lockingBytecode });
  }
  const locktime = r.u32le("locktime"); r.done(); return { raw: Buffer.from(raw), version, locktime, inputs, outputs };
}

function tokenObservation(token, expected, label) {
  if (expected === "NONE") {
    requireThat(token.kind === "none", "ERR_TOKEN_NONE", `${label} must have NONE observation`);
    return Buffer.concat([Buffer.of(0), u16be(0), u16be(0), u64le(0)]);
  }
  requireThat(token.kind === "token" && token.bitfield === 0x61 && token.commitment.length === 128 && token.amount === 0n, "ERR_TOKEN_STATE", `${label} must be canonical mutable-NFT-zero`);
  return Buffer.concat([Buffer.of(1), u16be(33), token.category, Buffer.of(1), u16be(128), token.commitment, u64le(0)]);
}
function parseCanonicalPush(bytes, offset, label) {
  requireThat(offset < bytes.length, "ERR_PUSH", `${label} has no push opcode`); const opcode = bytes[offset]; let header = 1; let length;
  if (opcode >= 1 && opcode <= 75) length = opcode;
  else if (opcode === 0x4c) { requireThat(offset + 2 <= bytes.length, "ERR_PUSH", `${label} PUSHDATA1 truncated`); length = bytes[offset + 1]; header = 2; requireThat(length >= 76, "ERR_PUSH_CANONICAL", `${label} uses nonminimal PUSHDATA1`); }
  else if (opcode === 0x4d) { requireThat(offset + 3 <= bytes.length, "ERR_PUSH", `${label} PUSHDATA2 truncated`); length = bytes.readUInt16LE(offset + 1); header = 3; requireThat(length > 0xff, "ERR_PUSH_CANONICAL", `${label} uses nonminimal PUSHDATA2`); }
  else fail("ERR_PUSH", `${label} opcode is not a data push`);
  requireThat(length > 0 && offset + header + length <= bytes.length, "ERR_PUSH", `${label} payload is truncated or empty`);
  return { data: bytes.subarray(offset + header, offset + header + length), next: offset + header + length };
}
function parseCarrierScript(script, ordinal, inputIndex, carrierRedeem) {
  requireThat(script.length <= 10000, "ERR_CARRIER_SIZE", `carrier ${ordinal} unlocking bytecode exceeds 10000`);
  const framePush = parseCanonicalPush(script, 0, `carrier ${ordinal} frame`); const redeemPush = parseCanonicalPush(script, framePush.next, `carrier ${ordinal} redeem`);
  requireThat(redeemPush.next === script.length && redeemPush.data.equals(carrierRedeem), "ERR_CARRIER_SCRIPT", `carrier ${ordinal} script framing/redeem differs`);
  const r = new Reader(framePush.data, `carrier ${ordinal} SegmentFrameV2`);
  exactly(r.take(4, "magic"), ASCII("P2SG"), "ERR_SEGMENT_MAGIC", `carrier ${ordinal} frame magic`); requireThat(r.u16be("version") === 2, "ERR_SEGMENT_VERSION", `carrier ${ordinal} frame version`);
  requireThat(r.u32be("ordinal") === ordinal && r.u32be("inputIndex") === inputIndex, "ERR_SEGMENT_ROLE", `carrier ${ordinal} frame role differs`);
  const payload = r.take(r.u32be("payloadLength"), "payload"); requireThat(payload.length > 0, "ERR_SEGMENT_EMPTY", `carrier ${ordinal} payload is empty`); r.done();
  return { payload: Buffer.from(payload), fullUnlockingBytecode: Buffer.from(script) };
}
function parseStateScript(script, stateRedeem) {
  const pushed = parseCanonicalPush(script, 0, "state redeem"); requireThat(pushed.next === script.length && pushed.data.equals(stateRedeem), "ERR_STATE_SCRIPT", "state unlocking script must exactly push structural redeem");
}

function deriveDeployment(template, manifest, anchor) {
  const protocolTemplateDigest = outerHash("PoolActionFv2/protocol-template/v2", template.raw);
  const preExistingAnchorDigest = outerHash("PoolActionFv2/pre-existing-anchor/v2", anchor.txHash, anchor.outputIndexBytes);
  const poolInstanceId = outerHash("PoolActionFv2/pool-instance/v2", protocolTemplateDigest, Buffer.of(manifest.networkTag), preExistingAnchorDigest, anchor.txHash, u64le(TICKET));
  const genesisAncestryDigest = outerHash("PoolActionFv2/genesis-ancestry/v2", preExistingAnchorDigest, poolInstanceId, anchor.txHash);
  exactly(manifest.protocolTemplateDigest, protocolTemplateDigest, "ERR_TEMPLATE_DIGEST", "manifest protocol template digest");
  exactly(manifest.preExistingAnchorDigest, preExistingAnchorDigest, "ERR_ANCHOR_DIGEST", "manifest anchor digest");
  exactly(manifest.poolInstanceId, poolInstanceId, "ERR_POOL_INSTANCE", "manifest pool instance id");
  exactly(manifest.genesisAncestryDigest, genesisAncestryDigest, "ERR_ANCESTRY", "manifest genesis ancestry digest");
  exactly(manifest.stateCategoryWire, anchor.txHash, "ERR_STATE_CATEGORY", "manifest state category");
  const deploymentCommitment = outerHash("PoolActionFv2/deployment/v2", manifest.raw);
  const stateRoleTemplateDigest = outerHash("PoolActionFv2/role-template/v2", protocolTemplateDigest, Buffer.of(0), template.stateTemplate);
  const carrierRoleTemplateDigest = outerHash("PoolActionFv2/role-template/v2", protocolTemplateDigest, Buffer.of(1), template.carrierTemplate);
  const stateRoleBindingDigest = outerHash("PoolActionFv2/structural-role/v2", deploymentCommitment, Buffer.of(0), stateRoleTemplateDigest);
  const carrierRoleBindingDigest = outerHash("PoolActionFv2/structural-role/v2", deploymentCommitment, Buffer.of(1), carrierRoleTemplateDigest);
  const structuralRedeem = (binding) => Buffer.concat([Buffer.of(0x20), binding, Buffer.of(0x75, 0x00)]);
  const structuralLock = (redeem) => Buffer.concat([Buffer.of(0xa9, 0x14), hash160(redeem), Buffer.of(0x87)]);
  const stateStructuralRedeem = structuralRedeem(stateRoleBindingDigest); const carrierStructuralRedeem = structuralRedeem(carrierRoleBindingDigest);
  return { protocolTemplateDigest, preExistingAnchorDigest, poolInstanceId, genesisAncestryDigest, deploymentCommitment, stateRoleTemplateDigest, carrierRoleTemplateDigest, stateRoleBindingDigest, carrierRoleBindingDigest, stateStructuralRedeem, carrierStructuralRedeem, stateStructuralLock: structuralLock(stateStructuralRedeem), carrierStructuralLock: structuralLock(carrierStructuralRedeem) };
}

function makeGenesisEvidence(template, manifest, anchor, d, initialStateValueSats) {
  const chunks = [ASCII("P2GR"), u16be(2), anchor.txHash, anchor.outputIndexBytes, d.deploymentCommitment, manifest.stateCategoryWire, lp(d.stateStructuralRedeem), lp(d.stateStructuralLock), u32be(manifest.carrierCount)];
  for (const carrier of manifest.carrierLayout) chunks.push(u32be(carrier.ordinal), u64le(carrier.expectedValueSats), lp(d.carrierStructuralRedeem), lp(d.carrierStructuralLock));
  chunks.push(u64le(initialStateValueSats)); const genesisRecipeBytes = Buffer.concat(chunks); const genesisRecipeDigest = outerHash("PoolActionFv2/genesis-recipe/v2", genesisRecipeBytes);
  const provenanceEvidenceBytes = Buffer.concat([ASCII("P2PE"), u16be(2), lp(template.raw), lp(manifest.raw), lp(genesisRecipeBytes), genesisRecipeDigest]);
  const provenanceEvidenceRoot = outerHash("PoolActionFv2/provenance-evidence/v2", provenanceEvidenceBytes);
  return { genesisRecipeBytes, genesisRecipeDigest, provenanceEvidenceBytes, provenanceEvidenceRoot };
}

function byteOrigins(stateRedeem, stateLock, carrierRedeem, carrierLock) {
  const intervals = [
    { role: "STATE", artifact: "STRUCTURAL_REDEEM", start: 0, endExclusive: 1, origin: "FIXED_COMPILER_OPCODE" },
    { role: "STATE", artifact: "STRUCTURAL_REDEEM", start: 1, endExclusive: 33, origin: "ROLE_BINDING_DIGEST" },
    { role: "STATE", artifact: "STRUCTURAL_REDEEM", start: 33, endExclusive: 35, origin: "FIXED_COMPILER_OPCODE" },
    { role: "STATE", artifact: "STRUCTURAL_LOCK", start: 0, endExclusive: 2, origin: "FIXED_COMPILER_OPCODE" },
    { role: "STATE", artifact: "STRUCTURAL_LOCK", start: 2, endExclusive: 22, origin: "HASH160_OUTPUT" },
    { role: "STATE", artifact: "STRUCTURAL_LOCK", start: 22, endExclusive: 23, origin: "FIXED_COMPILER_OPCODE" },
    { role: "VERIFIER_CARRIER", artifact: "STRUCTURAL_REDEEM", start: 0, endExclusive: 1, origin: "FIXED_COMPILER_OPCODE" },
    { role: "VERIFIER_CARRIER", artifact: "STRUCTURAL_REDEEM", start: 1, endExclusive: 33, origin: "ROLE_BINDING_DIGEST" },
    { role: "VERIFIER_CARRIER", artifact: "STRUCTURAL_REDEEM", start: 33, endExclusive: 35, origin: "FIXED_COMPILER_OPCODE" },
    { role: "VERIFIER_CARRIER", artifact: "STRUCTURAL_LOCK", start: 0, endExclusive: 2, origin: "FIXED_COMPILER_OPCODE" },
    { role: "VERIFIER_CARRIER", artifact: "STRUCTURAL_LOCK", start: 2, endExclusive: 22, origin: "HASH160_OUTPUT" },
    { role: "VERIFIER_CARRIER", artifact: "STRUCTURAL_LOCK", start: 22, endExclusive: 23, origin: "FIXED_COMPILER_OPCODE" },
  ];
  const validate = (role, artifact, length) => { const items = intervals.filter((item) => item.role === role && item.artifact === artifact); let at = 0; for (const item of items) { requireThat(item.start === at && item.endExclusive > item.start && item.endExclusive <= length, "ERR_ORIGIN_MAP", `${role} ${artifact} byte-origin map is partial`); at = item.endExclusive; } requireThat(at === length, "ERR_ORIGIN_MAP", `${role} ${artifact} byte-origin map does not cover all bytes`); };
  validate("STATE", "STRUCTURAL_REDEEM", stateRedeem.length); validate("STATE", "STRUCTURAL_LOCK", stateLock.length); validate("VERIFIER_CARRIER", "STRUCTURAL_REDEEM", carrierRedeem.length); validate("VERIFIER_CARRIER", "STRUCTURAL_LOCK", carrierLock.length);
  return intervals;
}

function inputRecord(index, roleTag, roleOrdinal, txInput, source, observation, disposition) {
  return Buffer.concat([u32be(index), Buffer.of(roleTag), u32be(roleOrdinal), txInput.outpointTxHash, u64le(txInput.outpointIndex), u64le(txInput.sequence), u64le(source.value), lp(source.lockingBytecode), observation, Buffer.of(disposition)]);
}
function outputRecord(index, roleTag, roleOrdinal, output, observation) {
  return Buffer.concat([u32be(index), Buffer.of(roleTag), u32be(roleOrdinal), u64le(output.value), lp(output.lockingBytecode), observation]);
}
function deriveTransactionAndSession(fixture, manifest, d) {
  const tx = parseTransaction(hexBytes(fixture.transactionHex, "transactionHex"));
  const n = manifest.carrierCount; const actionTag = Number.parseInt(fixture.actionTagHex, 16); const withdrawal = actionTag === 1;
  requireThat(/^(00|01)$/.test(fixture.actionTagHex), "ERR_ACTION", "actionTagHex must be 00 or 01");
  requireThat(tx.inputs.length === n + 2, "ERR_INPUT_COUNT", "transaction input count differs from manifest topology");
  const sourceOutputs = fixture.sourceOutputs.map((entry, index) => {
    canonicalObject(entry, ["sourceOutpointHex", "serializedOutputHex"], `sourceOutputs[${index}]`);
    const sourceOutpoint = hexBytes(entry.sourceOutpointHex, `sourceOutputs[${index}].sourceOutpointHex`); requireThat(sourceOutpoint.length === 36, "ERR_SOURCE_OUTPOINT", `source output ${index} outpoint must be bytes32||u32be`);
    const input = tx.inputs[index]; exactly(sourceOutpoint.subarray(0, 32), input.outpointTxHash, "ERR_SOURCE_OUTPOINT", `source output ${index} hash`); requireThat(sourceOutpoint.readUInt32BE(32) === input.outpointIndex, "ERR_SOURCE_OUTPOINT", `source output ${index} index`);
    return parseBchOutput(hexBytes(entry.serializedOutputHex, `sourceOutputs[${index}].serializedOutputHex`), `sourceOutputs[${index}]`);
  });
  requireThat(sourceOutputs.length === tx.inputs.length, "ERR_SOURCE_COUNT", "source output count differs from transaction inputs");
  const stateInput = tx.inputs[0]; const stateSource = sourceOutputs[0]; const stateSourceObs = tokenObservation(stateSource.token, "STATE", "state source");
  requireThat(stateInput.outpointIndex === 0, "ERR_STATE_PREDECESSOR", "state source outpoint index must be zero"); exactly(stateSource.token.category, manifest.stateCategoryWire, "ERR_STATE_CATEGORY", "state source category"); exactly(stateSource.lockingBytecode, d.stateStructuralLock, "ERR_STATE_LOCK", "state source lock");
  const carrierFrames = []; const inputChunks = [inputRecord(0, 0x00, 0, stateInput, stateSource, stateSourceObs, 0x00)];
  for (const carrier of manifest.carrierLayout) {
    const index = carrier.inputIndex; const input = tx.inputs[index]; const source = sourceOutputs[index];
    exactly(input.outpointTxHash, stateInput.outpointTxHash, "ERR_CARRIER_PREDECESSOR", `carrier ${carrier.ordinal} predecessor hash`); requireThat(input.outpointIndex === carrier.ordinal + 1, "ERR_CARRIER_PREDECESSOR", `carrier ${carrier.ordinal} predecessor index`);
    const obs = tokenObservation(source.token, "NONE", `carrier ${carrier.ordinal} source`); requireThat(source.value === carrier.expectedValueSats, "ERR_CARRIER_VALUE", `carrier ${carrier.ordinal} source value`); exactly(source.lockingBytecode, d.carrierStructuralLock, "ERR_CARRIER_LOCK", `carrier ${carrier.ordinal} source lock`);
    const listed = hexBytes(fixture.carrierUnlockingBytecodesHex[carrier.ordinal], `carrierUnlockingBytecodesHex[${carrier.ordinal}]`); exactly(listed, input.unlockingBytecode, "ERR_CARRIER_SCRIPT", `carrier ${carrier.ordinal} listed full unlocking bytecode`);
    carrierFrames.push(parseCarrierScript(input.unlockingBytecode, carrier.ordinal, index, d.carrierStructuralRedeem)); inputChunks.push(inputRecord(index, 0x01, carrier.ordinal, input, source, obs, 0x01));
  }
  const externalIndex = n + 1; const externalInput = tx.inputs[externalIndex]; const externalSource = sourceOutputs[externalIndex]; const externalObs = tokenObservation(externalSource.token, "NONE", "external funding source"); inputChunks.push(inputRecord(externalIndex, withdrawal ? 0x03 : 0x02, 0, externalInput, externalSource, externalObs, 0x02));
  const minimumOutputs = withdrawal ? n + 2 : n + 1; const maximumOutputs = minimumOutputs + 1; requireThat(tx.outputs.length === minimumOutputs || tx.outputs.length === maximumOutputs, "ERR_OUTPUT_COUNT", "transaction output count differs from canonical topology");
  const stateOutput = tx.outputs[0]; const stateOutputObs = tokenObservation(stateOutput.token, "STATE", "state successor"); exactly(stateOutput.token.category, manifest.stateCategoryWire, "ERR_STATE_CATEGORY", "state successor category"); exactly(stateOutput.lockingBytecode, d.stateStructuralLock, "ERR_STATE_LOCK", "state successor lock");
  const reserveDelta = stateOutput.value - stateSource.value; requireThat(reserveDelta === (withdrawal ? -TICKET : TICKET), "ERR_RESERVE", "state reserve delta is not fixed ticket direction");
  const outputChunks = [outputRecord(0, 0x10, 0, stateOutput, stateOutputObs)];
  for (const carrier of manifest.carrierLayout) {
    const output = tx.outputs[carrier.outputIndex]; const source = sourceOutputs[carrier.inputIndex]; const obs = tokenObservation(output.token, "NONE", `carrier ${carrier.ordinal} successor`);
    requireThat(output.value === carrier.expectedValueSats && output.value === source.value, "ERR_CARRIER_VALUE", `carrier ${carrier.ordinal} successor value`); exactly(output.lockingBytecode, source.lockingBytecode, "ERR_CARRIER_LOCK", `carrier ${carrier.ordinal} successor lock`); outputChunks.push(outputRecord(carrier.outputIndex, 0x11, carrier.ordinal, output, obs));
  }
  let payoutPresent = 0; let payoutOutputIndex = 0; let changePresent = 0; let changeOutputIndex = 0;
  if (withdrawal) {
    payoutPresent = 1; payoutOutputIndex = n + 1; const payout = tx.outputs[payoutOutputIndex]; requireThat(payout.value === TICKET, "ERR_PAYOUT", "withdrawal payout must be fixed ticket"); const obs = tokenObservation(payout.token, "NONE", "withdrawal payout"); outputChunks.push(outputRecord(payoutOutputIndex, 0x12, 0, payout, obs));
    if (tx.outputs.length === maximumOutputs) { changePresent = 1; changeOutputIndex = n + 2; const change = tx.outputs[changeOutputIndex]; outputChunks.push(outputRecord(changeOutputIndex, 0x13, 0, change, tokenObservation(change.token, "NONE", "withdrawal change"))); }
  } else if (tx.outputs.length === maximumOutputs) { changePresent = 1; changeOutputIndex = n + 1; const change = tx.outputs[changeOutputIndex]; outputChunks.push(outputRecord(changeOutputIndex, 0x13, 0, change, tokenObservation(change.token, "NONE", "deposit change"))); }
  const sourceTotal = sourceOutputs.reduce((sum, output) => sum + output.value, 0n); const outputTotal = tx.outputs.reduce((sum, output) => sum + output.value, 0n); requireThat(sourceTotal >= outputTotal, "ERR_FEE", "transaction has negative fee"); const feeSats = sourceTotal - outputTotal; requireThat(feeSats <= manifest.feePolicyMaxSats, "ERR_FEE", "fee exceeds manifest policy");
  const economics = Buffer.concat([u64le(TICKET), Buffer.of(withdrawal ? 1 : 0), u64le(feeSats), u64le(manifest.feePolicyMaxSats), Buffer.of(payoutPresent), u32be(payoutOutputIndex), Buffer.of(changePresent), u32be(changeOutputIndex)]);
  const txViewBytes = Buffer.concat([ASCII("P2TV"), u16be(2), Buffer.of(actionTag, 0), u64le(tx.version), u64le(tx.locktime), u32be(n), u32be(tx.inputs.length), ...inputChunks, u32be(tx.outputs.length), ...outputChunks, economics]);
  const carrierSessionChunks = [u32be(n)]; const scheduleChunks = [u32be(n)]; const envelopeChunks = []; let offset = 0;
  for (let i = 0; i < carrierFrames.length; i += 1) { const carrier = manifest.carrierLayout[i]; const frame = carrierFrames[i]; carrierSessionChunks.push(u32be(carrier.ordinal), u32be(carrier.inputIndex), lp(frame.fullUnlockingBytecode)); scheduleChunks.push(u32be(carrier.ordinal), u32be(carrier.inputIndex), u32be(offset), u32be(frame.payload.length)); envelopeChunks.push(frame.payload); offset += frame.payload.length; requireThat(offset <= 0xffffffff, "ERR_SCHEDULE", "reconstructed envelope exceeds u32"); }
  const carrierSessionBytes = Buffer.concat(carrierSessionChunks); const scheduleBytes = Buffer.concat(scheduleChunks); const reconstructedEnvelopeBytes = Buffer.concat(envelopeChunks);
  const carrierSessionRoot = outerHash("PoolActionFv2/carrier-session/v2", carrierSessionBytes); const envelopeRoot = outerHash("PoolActionFv2/envelope/v2", reconstructedEnvelopeBytes);
  const localRoleChecks = [{ role: "STATE", expectedActiveInputIndex: 0, fixtureWireIndex: 0, checked: true }];
  for (const carrier of manifest.carrierLayout) localRoleChecks.push({ role: "CARRIER", ordinal: carrier.ordinal, expectedActiveInputIndex: carrier.inputIndex, fixtureWireIndex: carrier.inputIndex, checked: carrier.inputIndex === carrier.ordinal + 1 });
  requireThat(localRoleChecks.every((x) => x.checked), "ERR_LOCAL_ROLE", "fixed local active-input role check failed");
  return { tx, txViewBytes, carrierSessionBytes, carrierSessionRoot, scheduleBytes, reconstructedEnvelopeBytes, envelopeRoot, feeSats, payoutPresent, payoutOutputIndex, changePresent, changeOutputIndex, localRoleChecks };
}

function validateFixture(fixture) {
  canonicalObject(fixture, ["fixtureFormat", "actionTagHex", "templateSetHex", "deploymentManifestCoreHex", "preExistingAnchorHex", "initialStateValueSatsU64leHex", "transactionHex", "sourceOutputs", "carrierUnlockingBytecodesHex"], "fixture");
  requireThat(fixture.fixtureFormat === "PoolActionFv2StructuralRawFixtureV2", "ERR_FIXTURE_FORMAT", "fixture format is not v2 structural raw input");
  requireThat(typeof fixture.actionTagHex === "string" && /^(00|01)$/.test(fixture.actionTagHex), "ERR_ACTION", "actionTagHex must be 00 or 01");
  requireThat(Array.isArray(fixture.sourceOutputs) && Array.isArray(fixture.carrierUnlockingBytecodesHex), "ERR_FIXTURE_ARRAY", "source outputs and carrier scripts must be arrays");
}

export function recomputeStructuralFixture(fixture) {
  validateFixture(fixture);
  const template = parseTemplateSet(hexBytes(fixture.templateSetHex, "templateSetHex")); const manifest = parseManifest(hexBytes(fixture.deploymentManifestCoreHex, "deploymentManifestCoreHex")); const anchor = parseAnchor(hexBytes(fixture.preExistingAnchorHex, "preExistingAnchorHex"));
  const initialStateRaw = hexBytes(fixture.initialStateValueSatsU64leHex, "initialStateValueSatsU64leHex"); requireThat(initialStateRaw.length === 8, "ERR_INITIAL_STATE", "initial state value must be u64le bytes"); const initialStateValueSats = initialStateRaw.readBigUInt64LE();
  requireThat(fixture.sourceOutputs.length === manifest.carrierCount + 2 && fixture.carrierUnlockingBytecodesHex.length === manifest.carrierCount, "ERR_FIXTURE_COUNT", "fixture source/carrier arrays differ from manifest count");
  if (fixture.actionTagHex === "01") requireThat(initialStateValueSats >= TICKET, "ERR_INITIAL_STATE", "withdrawal initial state is insufficient for ticket");
  const deployment = deriveDeployment(template, manifest, anchor); const evidence = makeGenesisEvidence(template, manifest, anchor, deployment, initialStateValueSats); const tx = deriveTransactionAndSession(fixture, manifest, deployment);
  const contextDigest = outerHash("PoolActionFv2/context/v2", deployment.deploymentCommitment, tx.txViewBytes);
  const sessionDigest = outerHash("PoolActionFv2/session/v2", contextDigest, tx.carrierSessionRoot, tx.envelopeRoot, tx.scheduleBytes, manifest.proofSuiteManifestDigest);
  const origins = byteOrigins(deployment.stateStructuralRedeem, deployment.stateStructuralLock, deployment.carrierStructuralRedeem, deployment.carrierStructuralLock);
  return {
    abiVersion: 2,
    proofBoundaryResult: "REJECT_UNSELECTED_PROOF_SUITE",
    proofAccepted: false,
    structuralClassification: "NON_DEPLOYABLE_ALWAYS_FALSE_STRUCTURAL_FIXTURE_NOT_BCH_VM_OR_COMPLETE_TRANSACTION_EVIDENCE",
    transactionByteCount: tx.tx.raw.length,
    carrierCount: manifest.carrierCount,
    templateSetBytesHex: template.raw.toString("hex"),
    protocolTemplateDigestHex: deployment.protocolTemplateDigest.toString("hex"),
    preExistingAnchorDigestHex: deployment.preExistingAnchorDigest.toString("hex"),
    poolInstanceIdHex: deployment.poolInstanceId.toString("hex"),
    genesisAncestryDigestHex: deployment.genesisAncestryDigest.toString("hex"),
    deploymentManifestCoreBytesHex: manifest.raw.toString("hex"),
    deploymentCommitmentHex: deployment.deploymentCommitment.toString("hex"),
    stateRoleTemplateDigestHex: deployment.stateRoleTemplateDigest.toString("hex"),
    carrierRoleTemplateDigestHex: deployment.carrierRoleTemplateDigest.toString("hex"),
    stateStructuralRedeemHex: deployment.stateStructuralRedeem.toString("hex"),
    stateStructuralLockHex: deployment.stateStructuralLock.toString("hex"),
    carrierStructuralRedeemHex: deployment.carrierStructuralRedeem.toString("hex"),
    carrierStructuralLockHex: deployment.carrierStructuralLock.toString("hex"),
    structuralByteOriginIntervals: origins,
    genesisRecipeBytesHex: evidence.genesisRecipeBytes.toString("hex"),
    genesisRecipeDigestHex: evidence.genesisRecipeDigest.toString("hex"),
    provenanceEvidenceBytesHex: evidence.provenanceEvidenceBytes.toString("hex"),
    provenanceEvidenceRootHex: evidence.provenanceEvidenceRoot.toString("hex"),
    txViewV2BytesHex: tx.txViewBytes.toString("hex"),
    carrierSessionBytesHex: tx.carrierSessionBytes.toString("hex"),
    carrierSessionRootHex: tx.carrierSessionRoot.toString("hex"),
    reconstructedEnvelopeBytesHex: tx.reconstructedEnvelopeBytes.toString("hex"),
    envelopeByteCount: tx.reconstructedEnvelopeBytes.length,
    scheduleBytesHex: tx.scheduleBytes.toString("hex"),
    envelopeRootHex: tx.envelopeRoot.toString("hex"),
    contextDigestHex: contextDigest.toString("hex"),
    sessionDigestHex: sessionDigest.toString("hex"),
    feeSats: tx.feeSats.toString(),
    payoutPresent: tx.payoutPresent === 1,
    payoutOutputIndex: tx.payoutOutputIndex,
    changePresent: tx.changePresent === 1,
    changeOutputIndex: tx.changeOutputIndex,
    localRoleChecks: tx.localRoleChecks,
  };
}

async function main() {
  const fixturePath = process.argv[2]; requireThat(fixturePath, "ERR_USAGE", "usage: recompute.mjs fixture.raw.json");
  const fixture = JSON.parse(await readFile(fixturePath, "utf8")); process.stdout.write(`${JSON.stringify(recomputeStructuralFixture(fixture), null, 2)}\n`);
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch((error) => { process.stderr.write(`REJECT: ${error.message}\n`); process.exitCode = 1; });
