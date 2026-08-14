import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  encodeTxView,
  makeStructuralFixture,
  validateFixture,
  validateProvenanceEvidence,
  validateRelationInput,
} from "./validate.mjs";

const base = new URL(".", import.meta.url);
const fromFile = (relative) => JSON.parse(readFileSync(new URL(relative, base), "utf8"));
const clone = (value) => JSON.parse(JSON.stringify(value));
const rejects = (mutate, code) => {
  const fixture = makeStructuralFixture("DEPOSIT", 1); mutate(fixture);
  assert.throws(() => validateFixture(fixture), (error) => error.code === code, code);
};

test("materialized N=1 deposit fixture is structurally proof-rejected", () => {
  const fixture = fromFile("fixtures/structural-deposit-n1.v2.json");
  const result = validateFixture(fixture);
  assert.equal(result.proofBoundaryResult, "REJECT_UNSELECTED_PROOF_SUITE");
  assert.match(result.sessionDigestHex, /^[0-9a-f]{64}$/);
});

test("materialized N=3 withdrawal fixture is structurally proof-rejected", () => {
  const fixture = fromFile("fixtures/structural-withdrawal-n3.v2.json");
  const result = validateFixture(fixture);
  assert.equal(result.proofBoundaryResult, "REJECT_UNSELECTED_PROOF_SUITE");
  assert.equal(result.reconstructedEnvelopeHex, "a0a1a2");
});

test("exact static deployment network enum rejects aliases", () => {
  rejects((fixture) => { fixture.relationInput.deploymentManifest.networkId = "chipnet-test"; }, "ERR_SCHEMA");
});

test("shared transaction view rejects dynamic network and active input fields", () => {
  rejects((fixture) => { fixture.relationInput.txView.networkId = "chipnet"; }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.txView.activeInputIndex = 1; }, "ERR_SCHEMA");
});

test("relation input rejects caller-derived digests and provenance authority", () => {
  rejects((fixture) => { fixture.relationInput.contextDigestHex = "00".repeat(32); }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.provenanceEvidenceRootHex = "00".repeat(32); }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.provenanceEvidence = fixture.provenanceEvidence; }, "ERR_SCHEMA");
});

test("closed token observation language rejects arbitrary and role-invalid records", () => {
  rejects((fixture) => { fixture.relationInput.txView.inputs[2].tokenObservation = { kind: "IMMUTABLE_EMPTY_NFT", categoryWireHex: "11".repeat(32) }; }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.txView.inputs[0].tokenObservation = { kind: "NONE" }; }, "ERR_TOKEN_ROLE");
  rejects((fixture) => { fixture.relationInput.txView.inputs[1].tokenObservation = { kind: "NONE", amount: "0" }; }, "ERR_SCHEMA");
});

test("carrier count is plural and fixed by manifest topology", () => {
  rejects((fixture) => { fixture.relationInput.deploymentManifest.carrierCount = 0; }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.carrierSession.carrierSegments = []; }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.carrierSession.carrierSlot = fixture.relationInput.carrierSession.carrierSegments[0]; }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.txView.inputs[1].wireIndex = 2; }, "ERR_INPUT_ROLE");
});

test("all full carrier unlocking bytes are consumed and canonical", () => {
  rejects((fixture) => { fixture.relationInput.carrierSession.carrierSegments[0].fullUnlockingBytecodeHex += "00"; }, "ERR_CARRIER_CONSUMPTION");
  rejects((fixture) => {
    const original = fixture.relationInput.carrierSession.carrierSegments[0].fullUnlockingBytecodeHex;
    fixture.relationInput.carrierSession.carrierSegments[0].fullUnlockingBytecodeHex = `4c13${original.slice(2)}`;
  }, "ERR_PUSH_NONCANONICAL");
  rejects((fixture) => { fixture.relationInput.carrierSession.carrierSegments[0].inputIndex = 2; }, "ERR_CARRIER_ORDER");
});

test("same payload cannot be rebound under a different full carrier script", () => {
  rejects((fixture) => {
    const script = fixture.relationInput.carrierSession.carrierSegments[0].fullUnlockingBytecodeHex;
    fixture.relationInput.carrierSession.carrierSegments[0].fullUnlockingBytecodeHex = `${script.slice(0, -2)}01`;
  }, "ERR_CARRIER_REDEEM");
});

test("unselected suite has no acceptance representation", () => {
  rejects((fixture) => { fixture.relationInput.deploymentManifest.proofSuiteStatus = "SELECTED"; }, "ERR_SCHEMA");
  rejects((fixture) => { fixture.relationInput.proofBoundaryResult = "ACCEPT"; }, "ERR_SCHEMA");
});

test("off-chain structural provenance is deterministic and always-false", () => {
  const fixture = makeStructuralFixture("DEPOSIT", 1);
  const result = validateProvenanceEvidence(fixture.provenanceEvidence);
  assert.match(result.stateStructuralRedeemHex, /00$/);
  assert.match(result.carrierStructuralRedeemHex, /00$/);
  assert.match(result.provenanceEvidenceRootHex, /^[0-9a-f]{64}$/);
  const broken = clone(fixture.provenanceEvidence); broken.byteOriginIntervals.pop();
  assert.throws(() => validateProvenanceEvidence(broken), (error) => error.code === "ERR_PROVENANCE_INTERVAL");
});

test("JSON interchange aliases do not alter binary runtime bytes", () => {
  const fixture = makeStructuralFixture("DEPOSIT", 1); const view = fixture.relationInput.txView;
  const reordered = Object.fromEntries(Object.entries(view).reverse());
  assert.deepEqual(encodeTxView(view, fixture.relationInput.deploymentManifest), encodeTxView(reordered, fixture.relationInput.deploymentManifest));
});

test("all evidence schemas close every object against unknown keys", () => {
  const schemas = readdirSync(new URL("schemas/", base)).filter((name) => name.endsWith(".json"));
  const visit = (value, path) => {
    if (value && typeof value === "object") {
      if (value.type === "object") assert.equal(value.additionalProperties, false, `${path} must reject unknown keys`);
      for (const [key, child] of Object.entries(value)) visit(child, `${path}/${key}`);
    }
  };
  for (const schema of schemas) visit(fromFile(`schemas/${schema}`), schema);
});

test("source pins and review anchor match the current authoritative charter", () => {
  const charter = readFileSync(new URL("../poolaction-fv2-relation-closure-charter-v2.md", base));
  const hash = createHash("sha256").update(charter).digest("hex");
  const pins = fromFile("source-pins-v2.json"); const anchor = fromFile("outside-package-review-anchor-v2.json");
  assert.equal(hash, "aa1a63b17c74bc5f4f09c4c5009914a42c0942cd320cbf82fce6bad19d45191e");
  assert.equal(pins.pins[0].sha256, hash); assert.equal(anchor.sha256, hash);
});

test("field-source table has only the three allowed classes and excludes physical identity", () => {
  const table = fromFile("field-source-table-v2.json");
  const allowed = new Set(table.sourceClasses);
  assert(table.entries.length > 0);
  assert(table.entries.every((entry) => allowed.has(entry.class)));
  assert(table.explicitExclusions.some((entry) => entry.field === "networkId in TxViewV2Bytes"));
  assert(table.entries.some((entry) => entry.field === "localExecutionInputIndex" && entry.runtimeHash === false));
});
