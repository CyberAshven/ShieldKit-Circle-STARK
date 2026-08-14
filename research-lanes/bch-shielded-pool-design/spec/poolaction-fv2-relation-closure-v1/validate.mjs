import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const here = new URL(".", import.meta.url);
const schema = (name) => JSON.parse(readFileSync(new URL(`schemas/${name}`, here), "utf8"));
const schemas = [
  schema("authenticated-tx-view.v1.schema.json"),
  schema("proof-session-envelope.v1.schema.json"),
  schema("provenance-dag.v1.schema.json"),
  schema("verifier-role-consumption-matrix.v1.schema.json"),
  schema("relation-input.v1.schema.json"),
];
const ajv = new Ajv2020({ allErrors: true, strict: true });
for (const item of schemas) ajv.addSchema(item);
const validateInputSchema = ajv.getSchema("https://shieldkit-labs.local/poolaction-fv2/relation-input/v1");
const validateMatrixSchema = ajv.getSchema("https://shieldkit-labs.local/poolaction-fv2/verifier-role-consumption-matrix/v1");

const UTF8 = new TextEncoder();
const REQUIRED_INTROSPECTION_FIELDS = Object.freeze([
  "/transactionVersion", "/locktime", "/activeInputIndex", "/inputs", "/outputs",
  "/inputs/sourceValueSats", "/inputs/sourceLockingBytecodeHex", "/inputs/sourceToken",
  "/outputs/lockingBytecodeHex", "/outputs/token", "/normalizedEnvelopeSlot",
]);

function fail(code, message) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  throw error;
}
function require(condition, code, message) { if (!condition) fail(code, message); }
function bytes(hex, name) {
  require(typeof hex === "string" && /^[0-9a-f]*$/.test(hex) && hex.length % 2 === 0, "ERR_HEX", `${name} is not canonical hex`);
  return Buffer.from(hex, "hex");
}
function hex(bytesValue) { return Buffer.from(bytesValue).toString("hex"); }
function lp(bytesValue) {
  const value = Buffer.from(bytesValue);
  require(value.length <= 0xffffffff, "ERR_LENGTH", "LP length overflows u32");
  const length = Buffer.alloc(4); length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}
function hash(domain, parts) {
  return createHash("sha256").update(Buffer.concat([UTF8.encode(domain), Buffer.of(0), ...parts.map(lp)])).digest();
}

/** CanonicalJsonV1: schema-bound values only; object names sort lexicographically. */
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
export function canonicalAuthenticatedTxView(view) { return Buffer.from(canonicalJson(view), "utf8"); }
export function computeNodeDigest(node) {
  return hex(hash("PoolActionFv2/provenance-node/v1", [UTF8.encode(node.id), UTF8.encode(node.type), bytes(node.canonicalPayloadHex, "node payload")]));
}
export function computeProvenanceRoot(provenance) {
  const { provenanceRootHex: ignored, ...withoutRoot } = provenance;
  return hex(hash("PoolActionFv2/provenance/v1", [Buffer.from(canonicalJson(withoutRoot), "utf8")]));
}
export function computeContextDigest(networkId, view, provenanceRootHex) {
  return hex(hash("PoolActionFv2/context/v1", [UTF8.encode(networkId), canonicalAuthenticatedTxView(view), bytes(provenanceRootHex, "provenanceRootHex")]));
}
export function computeEnvelopeRoot(rawEnvelopeHex) {
  return hex(hash("PoolActionFv2/envelope/v1", [bytes(rawEnvelopeHex, "rawEnvelopeHex")]));
}
export function computeSessionDigest(contextDigestHex, envelopeRootHex, sectionScheduleHex, proofSuiteManifestDigestHex) {
  return hex(hash("PoolActionFv2/session/v1", [bytes(contextDigestHex, "contextDigestHex"), bytes(envelopeRootHex, "envelopeRootHex"), bytes(sectionScheduleHex, "sectionScheduleHex"), bytes(proofSuiteManifestDigestHex, "proofSuiteManifestDigestHex")]));
}

export function parseEnvelope(rawEnvelopeHex) {
  const raw = bytes(rawEnvelopeHex, "rawEnvelopeHex");
  require(raw.length >= 20, "ERR_ENVELOPE_TRUNCATED", "envelope is shorter than header and directory");
  require(raw.subarray(0, 4).equals(Buffer.from("PAF2")), "ERR_ENVELOPE_MAGIC", "expected PAF2");
  require(raw.readUInt16BE(4) === 1, "ERR_ENVELOPE_VERSION", "only envelope version 1 is defined");
  require(raw.readUInt16BE(6) === 1, "ERR_ENVELOPE_DIRECTORY", "exactly one known critical section is required");
  const type = raw.readUInt8(8); const critical = raw.readUInt8(9); const ordinal = raw.readUInt16BE(10);
  const offset = raw.readUInt32BE(12); const length = raw.readUInt32BE(16);
  require(type === 1, "ERR_ENVELOPE_SECTION_TYPE", "unknown critical section type");
  require(critical === 1, "ERR_ENVELOPE_CRITICAL", "section must be critical");
  require(ordinal === 0, "ERR_ENVELOPE_ORDER", "section ordinal must be zero");
  require(offset === 20 && length > 0, "ERR_ENVELOPE_LAYOUT", "section must begin after directory and be nonempty");
  require(offset + length === raw.length && offset + length >= offset, "ERR_ENVELOPE_CONSUMPTION", "section must fully consume raw envelope without overflow");
  return { directory: [{ type: "OPAQUE_SUITE_PAYLOAD", critical: true, ordinal, offset, length }], sectionScheduleHex: raw.subarray(8, 20).toString("hex") };
}

function uniqueIntegers(values, code, label) {
  require(new Set(values).size === values.length, code, `${label} contains duplicate indices`);
}
function indexMap(items, code, label) {
  const result = new Map();
  for (const item of items) {
    require(!result.has(item.index), code, `${label} index is duplicate`);
    result.set(item.index, item);
  }
  return result;
}
function exactJson(left, right) { return canonicalJson(left) === canonicalJson(right); }

function validateTransactionView(view, relationNetworkId) {
  require(view.networkId === relationNetworkId, "ERR_NETWORK_BINDING", "relation and transaction-view networks differ");
  const inputs = indexMap(view.inputs, "ERR_INPUT_INDEX", "input");
  const outputs = indexMap(view.outputs, "ERR_OUTPUT_INDEX", "output");
  require(inputs.size === view.inputs.length && outputs.size === view.outputs.length, "ERR_INDEX", "non-canonical index map");
  const stateInput = inputs.get(view.stateBundle.inputIndex); const stateOutput = outputs.get(view.stateBundle.outputIndex);
  require(stateInput?.role === "STATE" && stateOutput?.role === "STATE_SUCCESSOR", "ERR_STATE_ROLE", "state bundle must reference state roles");
  require(stateInput.sourceToken.kind === "CASH_TOKEN" && stateOutput.token.kind === "CASH_TOKEN", "ERR_STATE_TOKEN", "state source and successor must be CashTokens");
  require(stateInput.sourceToken.categoryHex === view.stateBundle.categoryHex && stateOutput.token.categoryHex === view.stateBundle.categoryHex, "ERR_STATE_TOKEN", "state category differs from bundle");
  require(stateInput.sourceToken.commitmentHex === view.stateBundle.sourceCommitmentHex && stateOutput.token.commitmentHex === view.stateBundle.successorCommitmentHex, "ERR_STATE_TOKEN", "state commitment differs from bundle");
  require(stateInput.sourceToken.capability === stateOutput.token.capability, "ERR_STATE_TOKEN", "state capability changes");

  const carrierInputs = view.carrierBundle.inputIndices.map((index) => inputs.get(index));
  const carrierOutputs = view.carrierBundle.successorOutputIndices.map((index) => outputs.get(index));
  uniqueIntegers(view.carrierBundle.inputIndices, "ERR_CARRIER", "carrier input bundle");
  uniqueIntegers(view.carrierBundle.successorOutputIndices, "ERR_CARRIER", "carrier output bundle");
  require(carrierInputs.length === carrierOutputs.length, "ERR_CARRIER", "carrier predecessor/successor counts differ");
  require(carrierInputs.every(Boolean) && carrierOutputs.every(Boolean), "ERR_CARRIER", "carrier bundle references missing entry");
  for (let ordinal = 0; ordinal < carrierInputs.length; ordinal += 1) {
    const input = carrierInputs[ordinal]; const output = carrierOutputs[ordinal];
    require(input.role === "VERIFIER_CARRIER" && output.role === "VERIFIER_CARRIER_SUCCESSOR", "ERR_CARRIER", "carrier role mismatch");
    require(input.roleOrdinal === ordinal && output.roleOrdinal === ordinal, "ERR_CARRIER", "carrier ordinal mismatch");
    require(input.outpoint.txidWireHex === view.carrierBundle.predecessorTxidWireHex && input.outpoint.txidWireHex === stateInput.outpoint.txidWireHex, "ERR_CARRIER", "carrier must share state predecessor transaction");
    require(input.sourceToken.kind === "NONE" && output.token.kind === "NONE", "ERR_CARRIER_TOKEN", "carrier token presence is a relation error");
    require(input.sourceValueSats === output.valueSats && input.sourceLockingBytecodeHex === output.lockingBytecodeHex, "ERR_CARRIER", "carrier successor differs from predecessor");
  }
  require(view.normalizedEnvelopeSlot.inputIndex === view.envelopeBearingInputIndex, "ERR_ENVELOPE_SLOT", "normalized slot index differs");
  require(view.carrierBundle.inputIndices.includes(view.envelopeBearingInputIndex), "ERR_ENVELOPE_SLOT", "envelope must occupy a verifier-carrier input");
  const external = inputs.get(view.feePolicy.externalInputIndex);
  require(external?.role === view.feePolicy.externalInputRole && external.sourceToken.kind === "NONE", "ERR_FEE", "external fee input must be the declared token-free role");
  const expectedInputs = new Set([view.stateBundle.inputIndex, ...view.carrierBundle.inputIndices, view.feePolicy.externalInputIndex]);
  require(expectedInputs.size === view.inputs.length && [...expectedInputs].every((index) => inputs.has(index)), "ERR_INPUT_CONSUMPTION", "an input is unclassified or duplicated");
  const expectedOutputIndexes = new Set([view.stateBundle.outputIndex, ...view.carrierBundle.successorOutputIndices]);
  if (view.action.kind === "WITHDRAWAL") {
    require(view.action.reserveDeltaSats === "-10000000" && view.action.withdrawalPayout !== null, "ERR_ACTION", "withdrawal must have fixed negative delta and payout");
    const payout = outputs.get(view.action.withdrawalPayout.outputIndex);
    require(payout?.role === "PAYOUT" && exactJson({ outputIndex: payout.index, valueSats: payout.valueSats, lockingBytecodeHex: payout.lockingBytecodeHex, token: payout.token }, view.action.withdrawalPayout), "ERR_PAYOUT", "payout is not the authenticated output");
    expectedOutputIndexes.add(view.action.withdrawalPayout.outputIndex);
  } else {
    require(view.action.reserveDeltaSats === "10000000" && view.action.withdrawalPayout === null, "ERR_ACTION", "deposit must have positive delta and no payout");
  }
  if (view.feePolicy.transparentChangeOutputIndex !== null) {
    const change = outputs.get(view.feePolicy.transparentChangeOutputIndex);
    require(change?.role === "TRANSPARENT_CHANGE" && change.token.kind === "NONE", "ERR_FEE", "change output must be token-free transparent change");
    expectedOutputIndexes.add(change.index);
  }
  require(expectedOutputIndexes.size === view.outputs.length && [...expectedOutputIndexes].every((index) => outputs.has(index)), "ERR_OUTPUT_CONSUMPTION", "an output is unclassified or duplicated");
  const sourceTotal = view.inputs.reduce((sum, input) => sum + BigInt(input.sourceValueSats), 0n);
  const outputTotal = view.outputs.reduce((sum, output) => sum + BigInt(output.valueSats), 0n);
  require(sourceTotal - outputTotal === BigInt(view.feePolicy.feeSats) && BigInt(view.feePolicy.feeSats) <= BigInt(view.feePolicy.maxFeeSats), "ERR_FEE", "fee policy does not equal complete transaction balance");
  const fields = view.currentBchIntrospection.map((item) => item.fieldPath);
  uniqueIntegers(fields.map((value, index) => fields.indexOf(value) === index ? index : -index - 1), "ERR_INTROSPECTION", "introspection fields");
  for (const field of REQUIRED_INTROSPECTION_FIELDS) require(fields.includes(field), "ERR_INTROSPECTION", `missing required authenticated field ${field}`);
}

function validateProvenance(provenance) {
  const nodes = new Map();
  for (const node of provenance.nodes) {
    require(!nodes.has(node.id), "ERR_PROVENANCE_NODE", "duplicate node id");
    require(computeNodeDigest(node) === node.digestHex, "ERR_PROVENANCE_NODE_DIGEST", `node digest mismatch for ${node.id}`);
    nodes.set(node.id, node);
  }
  const adjacency = new Map([...nodes.keys()].map((id) => [id, []]));
  for (const edge of provenance.edges) {
    require(nodes.has(edge.from) && nodes.has(edge.to) && edge.from !== edge.to, "ERR_PROVENANCE_EDGE", "edge is unknown or self-referential");
    adjacency.get(edge.from).push(edge.to);
  }
  const visiting = new Set(); const visited = new Set();
  const visit = (id) => { require(!visiting.has(id), "ERR_PROVENANCE_CYCLE", "provenance DAG contains a cycle"); if (visited.has(id)) return; visiting.add(id); for (const child of adjacency.get(id)) visit(child); visiting.delete(id); visited.add(id); };
  for (const id of nodes.keys()) visit(id);
  const paths = (from, to, seen = new Set()) => {
    if (from === to) return 1;
    if (seen.has(from)) return 0;
    const nextSeen = new Set(seen); nextSeen.add(from);
    return adjacency.get(from).reduce((total, child) => Math.min(2, total + paths(child, to, nextSeen)), 0);
  };
  const locks = [provenance.concreteLocks.state, ...provenance.concreteLocks.carriers];
  for (const lock of locks) {
    const lockNode = nodes.get(lock.nodeId);
    require(lockNode?.type === (lock === provenance.concreteLocks.state ? "CONCRETE_STATE_LOCK" : "CONCRETE_CARRIER_LOCK"), "ERR_PROVENANCE_LOCK", "concrete lock references wrong node type");
    const byteLength = bytes(lock.lockingBytecodeHex, "lockingBytecodeHex").length;
    require(lock.byteOrigins.length === byteLength, "ERR_PROVENANCE_BYTE", "every concrete byte requires one origin");
    for (let offset = 0; offset < byteLength; offset += 1) {
      const origin = lock.byteOrigins[offset];
      require(origin.byteOffset === offset && nodes.has(origin.originNodeId), "ERR_PROVENANCE_BYTE", "byte-origin map is incomplete or noncanonical");
      require(paths(origin.originNodeId, lock.nodeId) === 1, "ERR_PROVENANCE_PATH", "each concrete byte must have one provenance path");
    }
  }
  require(computeProvenanceRoot(provenance) === provenance.provenanceRootHex, "ERR_PROVENANCE_ROOT", "provenance root mismatch");
}

export function validateRelationInput(input) {
  require(validateInputSchema(input), "ERR_SCHEMA", ajv.errorsText(validateInputSchema.errors));
  validateTransactionView(input.authenticatedTxView, input.networkId);
  validateProvenance(input.provenanceDag);
  const parsed = parseEnvelope(input.proofSessionEnvelope.rawEnvelopeHex);
  const envelope = input.proofSessionEnvelope;
  require(exactJson(parsed.directory, envelope.directory) && parsed.sectionScheduleHex === envelope.sectionScheduleHex, "ERR_ENVELOPE_DIRECTORY", "supplied directory or schedule was not recomputed from raw bytes");
  require(envelope.proofSuiteManifestDigestHex === input.proofSuiteManifestDigestHex, "ERR_SUITE_BINDING", "envelope and relation suite digests differ");
  const contextDigestHex = computeContextDigest(input.networkId, input.authenticatedTxView, input.provenanceDag.provenanceRootHex);
  const envelopeRootHex = computeEnvelopeRoot(envelope.rawEnvelopeHex);
  const sessionDigestHex = computeSessionDigest(contextDigestHex, envelopeRootHex, parsed.sectionScheduleHex, input.proofSuiteManifestDigestHex);
  require(envelope.contextDigestHex === contextDigestHex, "ERR_CONTEXT_DIGEST", "caller-supplied context digest differs from recomputation");
  require(envelope.envelopeRootHex === envelopeRootHex, "ERR_ENVELOPE_ROOT", "caller-supplied envelope root differs from recomputation");
  require(envelope.sessionDigestHex === sessionDigestHex, "ERR_SESSION_DIGEST", "caller-supplied session digest differs from recomputation");
  require(envelope.proofSuiteStatus === "UNSELECTED" && envelope.proofBoundaryResult === "REJECT_UNSELECTED_PROOF_SUITE", "ERR_PROOF_BOUNDARY", "unselected suite cannot reach acceptance");
  return Object.freeze({ canonicalAuthenticatedTxViewHex: hex(canonicalAuthenticatedTxView(input.authenticatedTxView)), provenanceRootHex: input.provenanceDag.provenanceRootHex, contextDigestHex, envelopeRootHex, sectionScheduleHex: parsed.sectionScheduleHex, sessionDigestHex, proofBoundaryResult: "REJECT_UNSELECTED_PROOF_SUITE" });
}

export function makeStructuralFixture() {
  const category = "aa".repeat(32); const sourceCommitment = "bb".repeat(128); const successorCommitment = "cc".repeat(128);
  const node = (id, type, canonicalPayloadHex) => ({ id, type, canonicalPayloadHex, digestHex: "00".repeat(32) });
  const nodes = [node("template", "NORMALIZED_TEMPLATE", "00"), node("parameters", "TYPED_PARAMETERS", "01"), node("toolchain", "PINNED_TOOLCHAIN", "02"), node("protocol", "PROTOCOL_TEMPLATE_DIGEST", "03"), node("state-lock", "CONCRETE_STATE_LOCK", "51"), node("carrier-lock", "CONCRETE_CARRIER_LOCK", "52"), node("genesis", "GENESIS_RECIPE", "04")];
  for (const item of nodes) item.digestHex = computeNodeDigest(item);
  const provenanceDag = { dagVersion: 1, nodes, edges: [{ from: "template", to: "protocol", kind: "DERIVES" }, { from: "parameters", to: "protocol", kind: "CONSUMES" }, { from: "toolchain", to: "protocol", kind: "CONSUMES" }, { from: "protocol", to: "state-lock", kind: "DERIVES" }, { from: "protocol", to: "carrier-lock", kind: "DERIVES" }, { from: "state-lock", to: "genesis", kind: "CONSUMES" }, { from: "carrier-lock", to: "genesis", kind: "CONSUMES" }], provenanceRootHex: "00".repeat(32), concreteLocks: { state: { nodeId: "state-lock", lockingBytecodeHex: "51", byteOrigins: [{ byteOffset: 0, originNodeId: "protocol", originByteOffset: 0 }] }, carriers: [{ nodeId: "carrier-lock", lockingBytecodeHex: "52", byteOrigins: [{ byteOffset: 0, originNodeId: "protocol", originByteOffset: 0 }] }] }, genesisRecipe: { recipeVersion: 1, networkId: "chipnet", transactionTemplateHex: "00", stateOutputIndex: 0, carrierOutputIndices: [1], derivationNodeId: "genesis" } };
  provenanceDag.provenanceRootHex = computeProvenanceRoot(provenanceDag);
  const stateTokenIn = { kind: "CASH_TOKEN", categoryHex: category, capability: "mutable", commitmentHex: sourceCommitment, amount: "0" };
  const stateTokenOut = { kind: "CASH_TOKEN", categoryHex: category, capability: "mutable", commitmentHex: successorCommitment, amount: "0" };
  const none = { kind: "NONE", categoryHex: "", capability: "none", commitmentHex: "", amount: "0" };
  const currentBchIntrospection = REQUIRED_INTROSPECTION_FIELDS.map((fieldPath, index) => ({ fieldPath, mappingId: `REQUIRED_${String(index).padStart(2, "0")}`, status: "REQUIRED_NOT_ASSERTED_BY_THIS_ARTIFACT" }));
  const authenticatedTxView = { viewVersion: 1, networkId: "chipnet", transactionVersion: 2, locktime: 0, activeInputIndex: 1, envelopeBearingInputIndex: 1, normalizedEnvelopeSlot: { inputIndex: 1, normalization: "RAW_ENVELOPE_REPLACED_BY_EMPTY", normalizedUnlockingBytecodeHex: "" }, inputs: [{ index: 0, role: "STATE", roleOrdinal: 0, outpoint: { txidWireHex: "11".repeat(32), index: 0 }, sequence: 4294967295, sourceValueSats: "100", sourceLockingBytecodeHex: "51", sourceToken: stateTokenIn }, { index: 1, role: "VERIFIER_CARRIER", roleOrdinal: 0, outpoint: { txidWireHex: "11".repeat(32), index: 1 }, sequence: 4294967295, sourceValueSats: "50", sourceLockingBytecodeHex: "52", sourceToken: none }, { index: 2, role: "DEPOSIT_FUNDING", roleOrdinal: 0, outpoint: { txidWireHex: "22".repeat(32), index: 3 }, sequence: 4294967295, sourceValueSats: "1000", sourceLockingBytecodeHex: "53", sourceToken: none }], outputs: [{ index: 0, role: "STATE_SUCCESSOR", roleOrdinal: 0, valueSats: "100", lockingBytecodeHex: "51", token: stateTokenOut }, { index: 1, role: "VERIFIER_CARRIER_SUCCESSOR", roleOrdinal: 0, valueSats: "50", lockingBytecodeHex: "52", token: none }, { index: 2, role: "TRANSPARENT_CHANGE", roleOrdinal: 0, valueSats: "990", lockingBytecodeHex: "53", token: none }], stateBundle: { inputIndex: 0, outputIndex: 0, categoryHex: category, sourceCommitmentHex: sourceCommitment, successorCommitmentHex: successorCommitment }, carrierBundle: { predecessorTxidWireHex: "11".repeat(32), inputIndices: [1], successorOutputIndices: [1] }, action: { kind: "DEPOSIT", ticketSats: "10000000", reserveDeltaSats: "10000000", withdrawalPayout: null }, feePolicy: { externalInputIndex: 2, externalInputRole: "DEPOSIT_FUNDING", feeSats: "10", maxFeeSats: "10", transparentChangeOutputIndex: 2, poolSubsidySats: "0", externalTokens: "NONE" }, currentBchIntrospection };
  const rawEnvelopeHex = "5041463200010001010100000000001400000001ff";
  const parsed = parseEnvelope(rawEnvelopeHex); const proofSuiteManifestDigestHex = "dd".repeat(32);
  const proofSessionEnvelope = { envelopeVersion: 1, rawEnvelopeHex, directory: parsed.directory, sectionScheduleHex: parsed.sectionScheduleHex, envelopeRootHex: computeEnvelopeRoot(rawEnvelopeHex), contextDigestHex: computeContextDigest("chipnet", authenticatedTxView, provenanceDag.provenanceRootHex), proofSuiteManifestDigestHex, sessionDigestHex: "00".repeat(32), proofSuiteStatus: "UNSELECTED", proofBoundaryResult: "REJECT_UNSELECTED_PROOF_SUITE" };
  proofSessionEnvelope.sessionDigestHex = computeSessionDigest(proofSessionEnvelope.contextDigestHex, proofSessionEnvelope.envelopeRootHex, proofSessionEnvelope.sectionScheduleHex, proofSuiteManifestDigestHex);
  return { relationId: "PoolActionFv2", relationVersion: 2, networkId: "chipnet", proofSuiteManifestDigestHex, authenticatedTxView, provenanceDag, proofSessionEnvelope };
}

function selfCheck() {
  const matrix = JSON.parse(readFileSync(new URL("normative/verifier-role-consumption-matrix.v1.json", here), "utf8"));
  require(validateMatrixSchema(matrix), "ERR_MATRIX_SCHEMA", ajv.errorsText(validateMatrixSchema.errors));
  const result = validateRelationInput(makeStructuralFixture());
  process.stdout.write(`${JSON.stringify({ status: "PASS_STATIC_ONLY", ...result })}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] !== "--self-check") fail("ERR_USAGE", "usage: node validate.mjs --self-check");
  selfCheck();
}
