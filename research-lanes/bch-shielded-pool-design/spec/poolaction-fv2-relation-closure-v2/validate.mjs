import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const here = new URL(".", import.meta.url);
const readJson = (relative) => JSON.parse(readFileSync(new URL(relative, here), "utf8"));
const schemaFiles = [
  "schemas/deployment-manifest-v2.schema.json",
  "schemas/tx-view-v2.schema.json",
  "schemas/carrier-session-v2.schema.json",
  "schemas/relation-input-v2.schema.json",
  "schemas/provenance-evidence-v2.schema.json",
  "schemas/verifier-role-consumption-v2.schema.json",
];
const ajv = new Ajv2020({ allErrors: true, strict: true });
for (const name of schemaFiles) ajv.addSchema(readJson(name));
const relationSchema = ajv.getSchema("https://shieldkit-labs.local/poolaction-fv2/v2/relation-input");
const provenanceSchema = ajv.getSchema("https://shieldkit-labs.local/poolaction-fv2/v2/provenance-evidence");
const roleMatrixSchema = ajv.getSchema("https://shieldkit-labs.local/poolaction-fv2/v2/verifier-role-consumption");

const UTF8 = new TextEncoder();
const ZERO32 = "00".repeat(32);
const U64_RUNTIME_MAX = 0x7fff_ffff_ffff_ffffn;

export class PoolActionFv2Error extends Error {
  constructor(code, message) { super(`${code}: ${message}`); this.code = code; }
}
function fail(code, message) { throw new PoolActionFv2Error(code, message); }
function require(condition, code, message) { if (!condition) fail(code, message); }
function asBytes(hexValue, name) {
  require(typeof hexValue === "string" && /^[0-9a-f]*$/.test(hexValue) && hexValue.length % 2 === 0, "ERR_HEX", `${name} is not lowercase even-length hex`);
  return Buffer.from(hexValue, "hex");
}
function asHex(value) { return Buffer.from(value).toString("hex"); }
function u16be(value, name = "u16") { require(Number.isInteger(value) && value >= 0 && value <= 0xffff, "ERR_RANGE", `${name} is outside u16`); const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; }
function u32be(value, name = "u32") { require(Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff, "ERR_RANGE", `${name} is outside u32`); const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; }
function u64le(value, name = "u64") {
  require(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), "ERR_RANGE", `${name} is not canonical nonnegative decimal`);
  const integer = BigInt(value); require(integer <= U64_RUNTIME_MAX, "ERR_RANGE", `${name} exceeds runtime VM nonnegative range`);
  const out = Buffer.alloc(8); out.writeBigUInt64LE(integer); return out;
}
function lp(value, name = "LP") { const bytes = Buffer.from(value); require(bytes.length <= 0xffff_ffff, "ERR_LENGTH", `${name} length overflows u32`); return Buffer.concat([u32be(bytes.length, `${name}.length`), bytes]); }
function domainHash(domain, parts) { return createHash("sha256").update(Buffer.concat([UTF8.encode(domain), Buffer.of(0), ...parts.map((part) => lp(part, domain))])).digest(); }
function hash160(value) { const sha = createHash("sha256").update(value).digest(); return createHash("ripemd160").update(sha).digest(); }
function taggedHashHex(domain, parts) { return asHex(domainHash(domain, parts)); }
function networkTag(networkId) { const tags = { mainnet: 0, chipnet: 1, regtest: 2 }; require(Object.hasOwn(tags, networkId), "ERR_NETWORK", "network is outside exact deployment enum"); return tags[networkId]; }
function roleTag(role, table, name) { require(Object.hasOwn(table, role), "ERR_ROLE", `${name}: unknown role ${role}`); return table[role]; }
const INPUT_ROLE_TAG = Object.freeze({ STATE: 0, VERIFIER_CARRIER: 1, DEPOSIT_FUNDING: 2, FEE_FUNDING: 3 });
const OUTPUT_ROLE_TAG = Object.freeze({ STATE_SUCCESSOR: 0x10, VERIFIER_CARRIER_SUCCESSOR: 0x11, PAYOUT: 0x12, TRANSPARENT_CHANGE: 0x13 });
const DISPOSITION_TAG = Object.freeze({ LOCAL_STATE: 0, CARRIER_SESSION: 1, EXTERNAL_AUTH: 2 });

function requireSchema(validator, value, name) { require(validator(value), "ERR_SCHEMA", `${name}: ${ajv.errorsText(validator.errors)}`); }
function exact(a, b) { return Buffer.from(a).equals(Buffer.from(b)); }
function sumSats(items, key) { return items.reduce((total, item) => total + BigInt(item[key]), 0n); }

export function encodeTokenObservation(observation, expectedKind, expectedCategoryWireHex) {
  require(observation.kind === expectedKind, "ERR_TOKEN_ROLE", `expected ${expectedKind}, got ${observation.kind}`);
  if (expectedKind === "NONE") return Buffer.concat([Buffer.of(0), u16be(0), u16be(0), u64le("0")]);
  require(observation.categoryWireHex === expectedCategoryWireHex, "ERR_TOKEN_CATEGORY", "state category differs from embedded deployment constant");
  const category = asBytes(observation.categoryWireHex, "state category");
  const commitment = asBytes(observation.commitmentHex, "state commitment");
  require(category.length === 32 && commitment.length === 128, "ERR_TOKEN_LENGTH", "state observation has wrong category or commitment length");
  return Buffer.concat([Buffer.of(1), u16be(33), category, Buffer.of(1), u16be(128), commitment, u64le("0")]);
}

function validateManifestTopology(manifest) {
  const n = manifest.carrierCount;
  require(manifest.carrierLayout.length === n, "ERR_MANIFEST_TOPOLOGY", "carrierLayout length differs from carrierCount");
  for (let i = 0; i < n; i += 1) {
    const carrier = manifest.carrierLayout[i];
    require(carrier.ordinal === i && carrier.inputIndex === i + 1 && carrier.outputIndex === i + 1, "ERR_MANIFEST_TOPOLOGY", "carrier layout is not fixed ordinal/index order");
    u64le(carrier.expectedValueSats, `carrierLayout[${i}].expectedValueSats`);
  }
  const deposit = manifest.depositRoleMap; const withdrawal = manifest.withdrawalRoleMap;
  require(deposit.externalInputIndex === n + 1 && deposit.changeOutputIndex === n + 1, "ERR_MANIFEST_TOPOLOGY", "deposit role map is not N-fixed");
  require(withdrawal.externalInputIndex === n + 1 && withdrawal.payoutOutputIndex === n + 1 && withdrawal.changeOutputIndex === n + 2, "ERR_MANIFEST_TOPOLOGY", "withdrawal role map is not N-fixed");
  require(manifest.proofSuiteStatus === "UNSELECTED" && manifest.proofSuiteManifestDigestHex === ZERO32, "ERR_PROOF_SUITE", "this package admits only an unselected all-zero suite manifest digest");
}

export function encodeDeploymentManifestCore(manifest) {
  validateManifestTopology(manifest);
  const status = manifest.proofSuiteStatus === "UNSELECTED" ? 0 : 1;
  const parts = [Buffer.from("P2DM"), u16be(2), Buffer.of(networkTag(manifest.networkId)), Buffer.of(0), asBytes(manifest.protocolTemplateDigestHex, "protocolTemplateDigest"), asBytes(manifest.poolInstanceIdHex, "poolInstanceId"), asBytes(manifest.preExistingAnchorDigestHex, "preExistingAnchorDigest"), asBytes(manifest.genesisAncestryDigestHex, "genesisAncestryDigest"), asBytes(manifest.stateCategoryWireHex, "stateCategoryWire"), u64le(manifest.ticketSats, "ticketSats"), u64le(manifest.feePolicyMaxSats, "feePolicyMaxSats"), Buffer.of(status), asBytes(manifest.proofSuiteManifestDigestHex, "proofSuiteManifestDigest"), u32be(manifest.carrierCount)];
  for (const item of manifest.carrierLayout) parts.push(u32be(item.ordinal), u32be(item.inputIndex), u32be(item.outputIndex), u64le(item.expectedValueSats));
  for (const map of [manifest.depositRoleMap, manifest.withdrawalRoleMap]) parts.push(u32be(map.stateInputIndex), u32be(map.externalInputIndex), u32be(map.stateOutputIndex), Buffer.of(map.payoutPresent ? 1 : 0), u32be(map.payoutOutputIndex), Buffer.of(map.changeOptional ? 1 : 0), u32be(map.changeOutputIndex));
  return Buffer.concat(parts);
}
export function computeDeploymentCommitment(manifest) { return taggedHashHex("PoolActionFv2/deployment/v2", [encodeDeploymentManifestCore(manifest)]); }

function expectedInputRole(action, index, n) { if (index === 0) return ["STATE", 0, "LOCAL_STATE"]; if (index <= n) return ["VERIFIER_CARRIER", index - 1, "CARRIER_SESSION"]; return [action === "DEPOSIT" ? "DEPOSIT_FUNDING" : "FEE_FUNDING", 0, "EXTERNAL_AUTH"]; }
function expectedOutputRole(action, index, n, changePresent) {
  if (index === 0) return ["STATE_SUCCESSOR", 0];
  if (index <= n) return ["VERIFIER_CARRIER_SUCCESSOR", index - 1];
  if (action === "WITHDRAWAL" && index === n + 1) return ["PAYOUT", 0];
  if (changePresent && index === (action === "DEPOSIT" ? n + 1 : n + 2)) return ["TRANSPARENT_CHANGE", 0];
  return [null, null];
}

function validateTxTopology(view, manifest) {
  const n = manifest.carrierCount;
  require(view.carrierCount === n && view.inputs.length === n + 2, "ERR_TX_TOPOLOGY", "input topology must be N carriers plus state and external input");
  const expectedOutputs = n + 1 + (view.economics.payoutPresent ? 1 : 0) + (view.economics.changePresent ? 1 : 0);
  require(view.outputs.length === expectedOutputs, "ERR_TX_TOPOLOGY", "output count differs from action topology");
  const stateInput = view.inputs[0]; const stateOutput = view.outputs[0];
  for (let index = 0; index < view.inputs.length; index += 1) {
    const item = view.inputs[index]; const [role, ordinal, disposition] = expectedInputRole(view.actionKind, index, n);
    require(item.wireIndex === index && item.role === role && item.roleOrdinal === ordinal && item.unlockingDisposition === disposition, "ERR_INPUT_ROLE", `input ${index} has wrong fixed role map`);
    const expectedToken = role === "STATE" ? "STATE_MUTABLE_NFT_ZERO" : "NONE";
    encodeTokenObservation(item.tokenObservation, expectedToken, manifest.stateCategoryWireHex);
  }
  require(stateInput.outpointIndex === "0", "ERR_STATE_LINEAGE", "state predecessor must be output zero");
  for (let ordinal = 0; ordinal < n; ordinal += 1) {
    const carrier = view.inputs[ordinal + 1]; const layout = manifest.carrierLayout[ordinal];
    require(carrier.outpointTxHashOpcodeOrderHex === stateInput.outpointTxHashOpcodeOrderHex && carrier.outpointIndex === String(ordinal + 1), "ERR_CARRIER_LINEAGE", "carrier must share state predecessor bundle");
    require(carrier.sourceValueSats === layout.expectedValueSats, "ERR_CARRIER_VALUE", "carrier source value differs from manifest");
  }
  const external = view.inputs[n + 1]; require(external.tokenObservation.kind === "NONE", "ERR_EXTERNAL_TOKEN", "external funding input must be token-free");
  for (let index = 0; index < view.outputs.length; index += 1) {
    const item = view.outputs[index]; const [role, ordinal] = expectedOutputRole(view.actionKind, index, n, view.economics.changePresent);
    require(role !== null && item.wireIndex === index && item.role === role && item.roleOrdinal === ordinal, "ERR_OUTPUT_ROLE", `output ${index} has wrong fixed role map`);
    const expectedToken = role === "STATE_SUCCESSOR" ? "STATE_MUTABLE_NFT_ZERO" : "NONE";
    encodeTokenObservation(item.tokenObservation, expectedToken, manifest.stateCategoryWireHex);
  }
  require(stateOutput.lockingBytecodeHex === stateInput.sourceLockingBytecodeHex, "ERR_STATE_LOCK", "state successor lock differs from state predecessor lock");
  for (let ordinal = 0; ordinal < n; ordinal += 1) {
    const input = view.inputs[ordinal + 1]; const output = view.outputs[ordinal + 1]; const layout = manifest.carrierLayout[ordinal];
    require(output.valueSats === layout.expectedValueSats && output.valueSats === input.sourceValueSats && output.lockingBytecodeHex === input.sourceLockingBytecodeHex, "ERR_CARRIER_CONTINUITY", "carrier successor does not preserve exact value and lock");
  }
  const economics = view.economics;
  require(economics.ticketSats === "10000000" && economics.feePolicyMaxSats === manifest.feePolicyMaxSats, "ERR_ECONOMICS", "ticket or fee cap differs from manifest");
  const delta = BigInt(stateOutput.valueSats) - BigInt(stateInput.sourceValueSats);
  if (view.actionKind === "DEPOSIT") {
    require(economics.reserveDirection === "INCREASE" && !economics.payoutPresent && economics.payoutOutputIndex === 0, "ERR_ECONOMICS", "deposit payout or reserve direction is wrong");
    require(delta === 10_000_000n, "ERR_ECONOMICS", "deposit state delta must equal one ticket");
  } else {
    require(economics.reserveDirection === "DECREASE" && economics.payoutPresent && economics.payoutOutputIndex === n + 1, "ERR_ECONOMICS", "withdrawal payout or reserve direction is wrong");
    const payout = view.outputs[n + 1]; require(payout.valueSats === "10000000" && payout.tokenObservation.kind === "NONE", "ERR_PAYOUT", "withdrawal payout must be one token-free ticket");
    require(delta === -10_000_000n, "ERR_ECONOMICS", "withdrawal state delta must equal minus one ticket");
  }
  const expectedChangeIndex = view.actionKind === "DEPOSIT" ? n + 1 : n + 2;
  if (economics.changePresent) {
    require(economics.changeOutputIndex === expectedChangeIndex, "ERR_ECONOMICS", "change output index is not action-fixed");
    require(view.outputs[expectedChangeIndex].tokenObservation.kind === "NONE", "ERR_CHANGE_TOKEN", "transparent change must be token-free");
  } else require(economics.changeOutputIndex === 0, "ERR_ECONOMICS", "absent change must have zero index");
  const fee = sumSats(view.inputs, "sourceValueSats") - sumSats(view.outputs, "valueSats");
  require(fee >= 0n && fee === BigInt(economics.feeSats) && fee <= BigInt(manifest.feePolicyMaxSats), "ERR_FEE", "derived complete-transaction fee differs from evidence or cap");
}

export function encodeTxView(view, manifest) {
  validateTxTopology(view, manifest);
  const actionTag = view.actionKind === "DEPOSIT" ? 0 : 1;
  const parts = [Buffer.from("P2TV"), u16be(2), Buffer.of(actionTag), Buffer.of(0), u64le(view.transactionVersion, "transactionVersion"), u64le(view.locktime, "locktime"), u32be(view.carrierCount), u32be(view.inputs.length)];
  for (const input of view.inputs) parts.push(u32be(input.wireIndex), Buffer.of(roleTag(input.role, INPUT_ROLE_TAG, "input")), u32be(input.roleOrdinal), asBytes(input.outpointTxHashOpcodeOrderHex, "outpointTxHash"), u64le(input.outpointIndex, "outpointIndex"), u64le(input.sequence, "sequence"), u64le(input.sourceValueSats, "sourceValueSats"), lp(asBytes(input.sourceLockingBytecodeHex, "source lock"), "source lock"), encodeTokenObservation(input.tokenObservation, input.role === "STATE" ? "STATE_MUTABLE_NFT_ZERO" : "NONE", manifest.stateCategoryWireHex), Buffer.of(roleTag(input.unlockingDisposition, DISPOSITION_TAG, "unlocking disposition")));
  parts.push(u32be(view.outputs.length));
  for (const output of view.outputs) parts.push(u32be(output.wireIndex), Buffer.of(roleTag(output.role, OUTPUT_ROLE_TAG, "output")), u32be(output.roleOrdinal), u64le(output.valueSats, "output value"), lp(asBytes(output.lockingBytecodeHex, "output lock"), "output lock"), encodeTokenObservation(output.tokenObservation, output.role === "STATE_SUCCESSOR" ? "STATE_MUTABLE_NFT_ZERO" : "NONE", manifest.stateCategoryWireHex));
  const e = view.economics;
  parts.push(u64le(e.ticketSats), Buffer.of(e.reserveDirection === "INCREASE" ? 0 : 1), u64le(e.feeSats), u64le(e.feePolicyMaxSats), Buffer.of(e.payoutPresent ? 1 : 0), u32be(e.payoutOutputIndex), Buffer.of(e.changePresent ? 1 : 0), u32be(e.changeOutputIndex));
  return Buffer.concat(parts);
}

function readCanonicalPush(script, offset) {
  require(offset < script.length, "ERR_PUSH", "truncated push opcode");
  const opcode = script[offset]; let length; let header = 1;
  if (opcode >= 1 && opcode <= 75) length = opcode;
  else if (opcode === 0x4c) { require(offset + 1 < script.length, "ERR_PUSH", "truncated PUSHDATA1"); length = script[offset + 1]; header = 2; require(length >= 76, "ERR_PUSH_NONCANONICAL", "PUSHDATA1 used for short push"); }
  else if (opcode === 0x4d) { require(offset + 2 < script.length, "ERR_PUSH", "truncated PUSHDATA2"); length = script.readUInt16LE(offset + 1); header = 3; require(length > 255, "ERR_PUSH_NONCANONICAL", "PUSHDATA2 used for short push"); }
  else fail("ERR_PUSH_NONCANONICAL", "noncanonical or zero-length BCH push");
  const end = offset + header + length; require(length > 0 && end <= script.length, "ERR_PUSH", "truncated pushed element");
  return { element: script.subarray(offset + header, end), next: end };
}
function minimalPush(element) {
  const value = Buffer.from(element); require(value.length > 0 && value.length <= 10000, "ERR_PUSH", "pushed element length outside structural bounds");
  if (value.length <= 75) return Buffer.concat([Buffer.of(value.length), value]);
  if (value.length <= 0xff) return Buffer.concat([Buffer.of(0x4c, value.length), value]);
  return Buffer.concat([Buffer.of(0x4d, value.length & 0xff, value.length >> 8), value]);
}
function parseSegmentFrame(frame) {
  require(frame.length >= 18, "ERR_SEGMENT", "carrier segment frame is truncated");
  require(frame.subarray(0, 4).equals(Buffer.from("P2SG")) && frame.readUInt16BE(4) === 2, "ERR_SEGMENT", "carrier segment magic/version mismatch");
  const ordinal = frame.readUInt32BE(6); const inputIndex = frame.readUInt32BE(10); const length = frame.readUInt32BE(14);
  require(length > 0 && length + 18 === frame.length, "ERR_SEGMENT", "carrier payload is empty, truncated, or trailing");
  return { ordinal, inputIndex, payload: frame.subarray(18), frame };
}
function p2shLockFor(redeem) { return Buffer.concat([Buffer.of(0xa9, 0x14), hash160(redeem), Buffer.of(0x87)]); }
export function encodeFullCarrierScript(frame, redeem) { return asHex(Buffer.concat([minimalPush(frame), minimalPush(redeem)])); }
export function parseCarrierSession(carrierSession, manifest, view) {
  const n = manifest.carrierCount;
  require(carrierSession.carrierSegments.length === n, "ERR_CARRIER_COUNT", "carrier session must include all N full scripts");
  const scripts = []; const payloads = []; const schedule = [u32be(n)]; const session = [u32be(n)]; let offset = 0;
  for (let i = 0; i < n; i += 1) {
    const item = carrierSession.carrierSegments[i]; const layout = manifest.carrierLayout[i];
    require(item.ordinal === i && item.inputIndex === layout.inputIndex, "ERR_CARRIER_ORDER", "carrier session ordinal/index is not manifest order");
    const script = asBytes(item.fullUnlockingBytecodeHex, `carrier script ${i}`); require(script.length <= 10000, "ERR_CARRIER_LENGTH", "full carrier unlocking bytecode exceeds 10000 bytes");
    const first = readCanonicalPush(script, 0); const second = readCanonicalPush(script, first.next); require(second.next === script.length, "ERR_CARRIER_CONSUMPTION", "carrier script has prefix, middle, or trailing bytes");
    require(first.element.length <= 10000 && second.element.length <= 10000, "ERR_CARRIER_LENGTH", "carrier pushed element exceeds 10000 bytes");
    const parsed = parseSegmentFrame(first.element); require(parsed.ordinal === i && parsed.inputIndex === layout.inputIndex, "ERR_SEGMENT_BINDING", "frame ordinal/index differs from manifest");
    const carrierInput = view.inputs[layout.inputIndex]; require(exact(p2shLockFor(second.element), asBytes(carrierInput.sourceLockingBytecodeHex, "carrier source lock")), "ERR_CARRIER_REDEEM", "full unlocking redeem script is not selected by carrier source lock");
    scripts.push(script); payloads.push(parsed.payload); session.push(u32be(i), u32be(layout.inputIndex), lp(script, "full carrier script")); schedule.push(u32be(i), u32be(layout.inputIndex), u32be(offset), u32be(parsed.payload.length)); offset += parsed.payload.length;
  }
  const carrierSessionBytes = Buffer.concat(session); const scheduleBytes = Buffer.concat(schedule); const envelopeBytes = Buffer.concat(payloads);
  return { carrierSessionBytes, carrierSessionRootHex: taggedHashHex("PoolActionFv2/carrier-session/v2", [carrierSessionBytes]), reconstructedEnvelopeBytes: envelopeBytes, scheduleBytes, envelopeRootHex: taggedHashHex("PoolActionFv2/envelope/v2", [envelopeBytes]), scripts };
}

export function validateRelationInput(input) {
  requireSchema(relationSchema, input, "relation input");
  const manifest = input.deploymentManifest; const view = input.txView;
  const manifestCoreBytes = encodeDeploymentManifestCore(manifest); const deploymentCommitmentHex = taggedHashHex("PoolActionFv2/deployment/v2", [manifestCoreBytes]);
  const txViewBytes = encodeTxView(view, manifest);
  const carrier = parseCarrierSession(input.carrierSession, manifest, view);
  const contextDigestHex = taggedHashHex("PoolActionFv2/context/v2", [asBytes(deploymentCommitmentHex, "deployment commitment"), txViewBytes]);
  const sessionDigestHex = taggedHashHex("PoolActionFv2/session/v2", [asBytes(contextDigestHex, "context digest"), asBytes(carrier.carrierSessionRootHex, "carrier session root"), asBytes(carrier.envelopeRootHex, "envelope root"), carrier.scheduleBytes, asBytes(manifest.proofSuiteManifestDigestHex, "proof suite manifest digest")]);
  return Object.freeze({ manifestCoreHex: asHex(manifestCoreBytes), deploymentCommitmentHex, txViewHex: asHex(txViewBytes), carrierSessionHex: asHex(carrier.carrierSessionBytes), carrierSessionRootHex: carrier.carrierSessionRootHex, reconstructedEnvelopeHex: asHex(carrier.reconstructedEnvelopeBytes), scheduleHex: asHex(carrier.scheduleBytes), envelopeRootHex: carrier.envelopeRootHex, contextDigestHex, sessionDigestHex, proofBoundaryResult: "REJECT_UNSELECTED_PROOF_SUITE" });
}

function validateTemplateSet(templateSet) {
  require(Buffer.from(templateSet.toolchainId, "utf8").toString("utf8") === templateSet.toolchainId && !templateSet.toolchainId.includes("\0"), "ERR_TEMPLATE", "toolchainId must be canonical UTF-8 without NUL");
  const state = asBytes(templateSet.normalizedStateTemplateHex, "normalizedStateTemplate"); const carrier = asBytes(templateSet.normalizedCarrierTemplateHex, "normalizedCarrierTemplate");
  require(state.length > 0 && carrier.length > 0 && !exact(state, carrier), "ERR_TEMPLATE", "normalized templates must be nonempty and distinct");
  const bytes = Buffer.concat([Buffer.from("P2TS"), u16be(2), lp(UTF8.encode(templateSet.toolchainId), "toolchainId"), lp(state, "state template"), lp(carrier, "carrier template")]);
  return { bytes, state, carrier, protocolTemplateDigestHex: taggedHashHex("PoolActionFv2/protocol-template/v2", [bytes]) };
}
function deriveStructuralLocks(templateData, deploymentCommitmentHex) {
  const roleTemplate = (roleTagValue, template) => domainHash("PoolActionFv2/role-template/v2", [asBytes(templateData.protocolTemplateDigestHex, "protocol template digest"), Buffer.of(roleTagValue), template]);
  const structural = (roleTagValue, roleTemplateDigest) => {
    const binding = domainHash("PoolActionFv2/structural-role/v2", [asBytes(deploymentCommitmentHex, "deployment commitment"), Buffer.of(roleTagValue), roleTemplateDigest]);
    const redeem = Buffer.concat([Buffer.of(0x20), binding, Buffer.of(0x75, 0x00)]); return { roleTemplateDigestHex: asHex(roleTemplateDigest), roleBindingDigestHex: asHex(binding), redeem, lock: p2shLockFor(redeem) };
  };
  return { state: structural(0, roleTemplate(0, templateData.state)), carrier: structural(1, roleTemplate(1, templateData.carrier)) };
}
function expectedIntervals() {
  return [
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
}
function exactJson(left, right) { return JSON.stringify(left) === JSON.stringify(right); }

export function validateProvenanceEvidence(evidence) {
  requireSchema(provenanceSchema, evidence, "provenance evidence");
  const template = validateTemplateSet(evidence.templateSet); const anchorHash = asBytes(evidence.anchor.anchorTxHashOpcodeOrderHex, "anchor tx hash"); const anchorIndex = u32be(evidence.anchor.anchorOutputIndex, "anchor output index");
  const anchorDigestHex = taggedHashHex("PoolActionFv2/pre-existing-anchor/v2", [anchorHash, anchorIndex]);
  const manifest = evidence.deploymentManifest;
  const poolInstanceIdHex = taggedHashHex("PoolActionFv2/pool-instance/v2", [asBytes(template.protocolTemplateDigestHex, "protocol template digest"), Buffer.of(networkTag(manifest.networkId)), asBytes(anchorDigestHex, "anchor digest"), anchorHash, u64le("10000000", "ticket")]);
  const ancestryHex = taggedHashHex("PoolActionFv2/genesis-ancestry/v2", [asBytes(anchorDigestHex, "anchor digest"), asBytes(poolInstanceIdHex, "pool instance"), anchorHash]);
  require(manifest.protocolTemplateDigestHex === template.protocolTemplateDigestHex && manifest.preExistingAnchorDigestHex === anchorDigestHex && manifest.poolInstanceIdHex === poolInstanceIdHex && manifest.stateCategoryWireHex === asHex(anchorHash) && manifest.genesisAncestryDigestHex === ancestryHex, "ERR_PROVENANCE_CORE", "manifest core is not derived from template and pre-existing anchor");
  const manifestCoreBytes = encodeDeploymentManifestCore(manifest); const deploymentCommitmentHex = taggedHashHex("PoolActionFv2/deployment/v2", [manifestCoreBytes]); const locks = deriveStructuralLocks(template, deploymentCommitmentHex);
  require(locks.state.redeem.at(-1) === 0 && locks.carrier.redeem.at(-1) === 0, "ERR_STRUCTURAL_LOCK", "structural redeem must end OP_FALSE");
  require(exactJson(evidence.byteOriginIntervals, expectedIntervals()), "ERR_PROVENANCE_INTERVAL", "byte-origin intervals are incomplete or noncanonical");
  const genesisParts = [Buffer.from("P2GR"), u16be(2), anchorHash, anchorIndex, asBytes(deploymentCommitmentHex, "deployment commitment"), anchorHash, lp(locks.state.redeem, "state redeem"), lp(locks.state.lock, "state lock"), u32be(manifest.carrierCount)];
  for (const carrier of manifest.carrierLayout) genesisParts.push(u32be(carrier.ordinal), u64le(carrier.expectedValueSats), lp(locks.carrier.redeem, "carrier redeem"), lp(locks.carrier.lock, "carrier lock"));
  genesisParts.push(u64le(evidence.initialStateValueSats, "initial state value"));
  const genesisRecipeBytes = Buffer.concat(genesisParts); const genesisRecipeDigestHex = taggedHashHex("PoolActionFv2/genesis-recipe/v2", [genesisRecipeBytes]);
  const provenanceEvidenceBytes = Buffer.concat([Buffer.from("P2PE"), u16be(2), lp(template.bytes, "template set"), lp(manifestCoreBytes, "manifest core"), lp(genesisRecipeBytes, "genesis recipe"), asBytes(genesisRecipeDigestHex, "genesis recipe digest")]);
  const provenanceEvidenceRootHex = taggedHashHex("PoolActionFv2/provenance-evidence/v2", [provenanceEvidenceBytes]);
  return Object.freeze({ templateSetHex: asHex(template.bytes), protocolTemplateDigestHex: template.protocolTemplateDigestHex, preExistingAnchorDigestHex: anchorDigestHex, poolInstanceIdHex, genesisAncestryDigestHex: ancestryHex, deploymentCommitmentHex, stateStructuralRedeemHex: asHex(locks.state.redeem), stateStructuralLockHex: asHex(locks.state.lock), carrierStructuralRedeemHex: asHex(locks.carrier.redeem), carrierStructuralLockHex: asHex(locks.carrier.lock), genesisRecipeHex: asHex(genesisRecipeBytes), genesisRecipeDigestHex, provenanceEvidenceHex: asHex(provenanceEvidenceBytes), provenanceEvidenceRootHex });
}

function buildManifest(n, templateSet, anchor) {
  const template = validateTemplateSet(templateSet); const anchorHash = asBytes(anchor.anchorTxHashOpcodeOrderHex, "anchor tx hash"); const anchorIndex = u32be(anchor.anchorOutputIndex); const preExistingAnchorDigestHex = taggedHashHex("PoolActionFv2/pre-existing-anchor/v2", [anchorHash, anchorIndex]); const networkId = "chipnet";
  const poolInstanceIdHex = taggedHashHex("PoolActionFv2/pool-instance/v2", [asBytes(template.protocolTemplateDigestHex, "protocol template"), Buffer.of(networkTag(networkId)), asBytes(preExistingAnchorDigestHex, "anchor digest"), anchorHash, u64le("10000000")]);
  const genesisAncestryDigestHex = taggedHashHex("PoolActionFv2/genesis-ancestry/v2", [asBytes(preExistingAnchorDigestHex, "anchor digest"), asBytes(poolInstanceIdHex, "pool instance"), anchorHash]);
  return { schema: "shieldkit-labs/poolaction-fv2/deployment-manifest/v2", abiVersion: 2, networkId, protocolTemplateDigestHex: template.protocolTemplateDigestHex, poolInstanceIdHex, preExistingAnchorDigestHex, genesisAncestryDigestHex, stateCategoryWireHex: asHex(anchorHash), ticketSats: "10000000", feePolicyMaxSats: "10000", proofSuiteStatus: "UNSELECTED", proofSuiteManifestDigestHex: ZERO32, carrierCount: n, carrierLayout: Array.from({ length: n }, (_, ordinal) => ({ ordinal, inputIndex: ordinal + 1, outputIndex: ordinal + 1, expectedValueSats: "1000" })), depositRoleMap: { stateInputIndex: 0, externalInputIndex: n + 1, stateOutputIndex: 0, payoutPresent: false, payoutOutputIndex: 0, changeOptional: true, changeOutputIndex: n + 1 }, withdrawalRoleMap: { stateInputIndex: 0, externalInputIndex: n + 1, stateOutputIndex: 0, payoutPresent: true, payoutOutputIndex: n + 1, changeOptional: true, changeOutputIndex: n + 2 } };
}

/** Produces non-deployable structural fixture evidence; never a BCH transaction claim. */
export function makeStructuralFixture(actionKind = "DEPOSIT", carrierCount = 1) {
  require(["DEPOSIT", "WITHDRAWAL"].includes(actionKind) && Number.isInteger(carrierCount) && carrierCount >= 1, "ERR_FIXTURE", "bad fixture action or carrier count");
  const templateSet = { toolchainId: "structural-fixture-compiler-v2", normalizedStateTemplateHex: "51", normalizedCarrierTemplateHex: "52" }; const anchor = { anchorTxHashOpcodeOrderHex: "11".repeat(32), anchorOutputIndex: 0 }; const manifest = buildManifest(carrierCount, templateSet, anchor); const byteOriginIntervals = expectedIntervals();
  const initialStateValueSats = actionKind === "DEPOSIT" ? "10000000" : "20000000";
  const provenanceEvidence = { schema: "shieldkit-labs/poolaction-fv2/provenance-evidence/v2", evidenceVersion: 2, runtimeAuthority: "OFF_CHAIN_EVIDENCE_ONLY", templateSet, anchor, deploymentManifest: manifest, initialStateValueSats, byteOriginIntervals };
  const provenance = validateProvenanceEvidence(provenanceEvidence); const none = { kind: "NONE" }; const stateIn = { kind: "STATE_MUTABLE_NFT_ZERO", categoryWireHex: manifest.stateCategoryWireHex, commitmentHex: "22".repeat(128) }; const stateOut = { kind: "STATE_MUTABLE_NFT_ZERO", categoryWireHex: manifest.stateCategoryWireHex, commitmentHex: "33".repeat(128) };
  const stateValue = BigInt(initialStateValueSats); const finalStateValue = actionKind === "DEPOSIT" ? stateValue + 10_000_000n : stateValue - 10_000_000n; const inputs = [{ wireIndex: 0, role: "STATE", roleOrdinal: 0, outpointTxHashOpcodeOrderHex: "44".repeat(32), outpointIndex: "0", sequence: "4294967295", sourceValueSats: stateValue.toString(), sourceLockingBytecodeHex: provenance.stateStructuralLockHex, tokenObservation: stateIn, unlockingDisposition: "LOCAL_STATE" }];
  const outputs = [{ wireIndex: 0, role: "STATE_SUCCESSOR", roleOrdinal: 0, valueSats: finalStateValue.toString(), lockingBytecodeHex: provenance.stateStructuralLockHex, tokenObservation: stateOut }];
  for (let i = 0; i < carrierCount; i += 1) { inputs.push({ wireIndex: i + 1, role: "VERIFIER_CARRIER", roleOrdinal: i, outpointTxHashOpcodeOrderHex: "44".repeat(32), outpointIndex: String(i + 1), sequence: "4294967295", sourceValueSats: "1000", sourceLockingBytecodeHex: provenance.carrierStructuralLockHex, tokenObservation: none, unlockingDisposition: "CARRIER_SESSION" }); outputs.push({ wireIndex: i + 1, role: "VERIFIER_CARRIER_SUCCESSOR", roleOrdinal: i, valueSats: "1000", lockingBytecodeHex: provenance.carrierStructuralLockHex, tokenObservation: none }); }
  const externalIndex = carrierCount + 1; const fee = "10"; const externalValue = actionKind === "DEPOSIT" ? "10000010" : "10"; inputs.push({ wireIndex: externalIndex, role: actionKind === "DEPOSIT" ? "DEPOSIT_FUNDING" : "FEE_FUNDING", roleOrdinal: 0, outpointTxHashOpcodeOrderHex: "55".repeat(32), outpointIndex: "0", sequence: "4294967295", sourceValueSats: externalValue, sourceLockingBytecodeHex: "51", tokenObservation: none, unlockingDisposition: "EXTERNAL_AUTH" });
  if (actionKind === "WITHDRAWAL") outputs.push({ wireIndex: externalIndex, role: "PAYOUT", roleOrdinal: 0, valueSats: "10000000", lockingBytecodeHex: "51", tokenObservation: none });
  const txView = { schema: "shieldkit-labs/poolaction-fv2/tx-view/v2", abiVersion: 2, actionKind, transactionVersion: "2", locktime: "0", carrierCount, inputs, outputs, economics: { ticketSats: "10000000", reserveDirection: actionKind === "DEPOSIT" ? "INCREASE" : "DECREASE", feeSats: fee, feePolicyMaxSats: "10000", payoutPresent: actionKind === "WITHDRAWAL", payoutOutputIndex: actionKind === "WITHDRAWAL" ? externalIndex : 0, changePresent: false, changeOutputIndex: 0 } };
  const carrierSegments = manifest.carrierLayout.map((layout) => { const payload = Buffer.of(0xa0 + layout.ordinal); const frame = Buffer.concat([Buffer.from("P2SG"), u16be(2), u32be(layout.ordinal), u32be(layout.inputIndex), u32be(payload.length), payload]); return { ordinal: layout.ordinal, inputIndex: layout.inputIndex, fullUnlockingBytecodeHex: encodeFullCarrierScript(frame, asBytes(provenance.carrierStructuralRedeemHex, "structural carrier redeem")) }; });
  const relationInput = { relationId: "PoolActionFv2", relationVersion: 2, abiVersion: 2, deploymentManifest: manifest, txView, carrierSession: { schema: "shieldkit-labs/poolaction-fv2/carrier-session/v2", abiVersion: 2, carrierSegments } };
  const derived = validateRelationInput(relationInput); return { fixtureVersion: 2, caseId: `structural-${actionKind.toLowerCase()}-n${carrierCount}`, classification: "STRUCTURAL_PROOF_REJECTED_NOT_DEPLOYMENT_EVIDENCE", relationInput, provenanceEvidence, expectedDerived: { ...derived, provenanceEvidenceRootHex: provenance.provenanceEvidenceRootHex } };
}

export function validateFixture(fixture) {
  require(fixture !== null && typeof fixture === "object" && !Array.isArray(fixture), "ERR_FIXTURE", "fixture must be an object");
  const allowed = ["fixtureVersion", "caseId", "classification", "relationInput", "provenanceEvidence", "expectedDerived"]; require(Object.keys(fixture).length === allowed.length && allowed.every((key) => Object.hasOwn(fixture, key)), "ERR_FIXTURE", "fixture has missing or unknown keys");
  require(fixture.fixtureVersion === 2 && fixture.classification === "STRUCTURAL_PROOF_REJECTED_NOT_DEPLOYMENT_EVIDENCE", "ERR_FIXTURE", "fixture classification/version is wrong");
  const relation = validateRelationInput(fixture.relationInput); const provenance = validateProvenanceEvidence(fixture.provenanceEvidence);
  require(fixture.relationInput.deploymentManifest.schema === fixture.provenanceEvidence.deploymentManifest.schema && JSON.stringify(fixture.relationInput.deploymentManifest) === JSON.stringify(fixture.provenanceEvidence.deploymentManifest), "ERR_FIXTURE", "runtime and off-chain evidence use different manifest cores");
  const expected = { ...relation, provenanceEvidenceRootHex: provenance.provenanceEvidenceRootHex };
  require(JSON.stringify(expected) === JSON.stringify(fixture.expectedDerived), "ERR_FIXTURE_EXPECTED", "fixture derived comparison values differ from recomputation");
  return Object.freeze(expected);
}

function selfCheck() {
  const matrix = readJson("normative/verifier-role-consumption-v2.json"); requireSchema(roleMatrixSchema, matrix, "verifier role matrix");
  const deposit = makeStructuralFixture("DEPOSIT", 1); const withdrawal = makeStructuralFixture("WITHDRAWAL", 3); validateFixture(deposit); validateFixture(withdrawal);
  process.stdout.write(`${JSON.stringify({ status: "PASS_STATIC_ONLY", fixtures: [deposit.caseId, withdrawal.caseId], proofBoundaryResult: "REJECT_UNSELECTED_PROOF_SUITE" })}\n`);
}
if (process.argv[1] === fileURLToPath(import.meta.url)) { require(process.argv[2] === "--self-check", "ERR_USAGE", "usage: node validate.mjs --self-check"); selfCheck(); }
