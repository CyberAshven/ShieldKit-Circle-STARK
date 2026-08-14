import test from "node:test";
import assert from "node:assert/strict";
import { makeStructuralFixture, validateRelationInput } from "./validate.mjs";

const clone = (value) => JSON.parse(JSON.stringify(value));
const rejects = (mutation, code) => {
  const input = makeStructuralFixture(); mutation(input);
  assert.throws(() => validateRelationInput(input), (error) => error.code === code, code);
};

test("structural input recomputes all outer bindings and remains proof-rejected", () => {
  const result = validateRelationInput(makeStructuralFixture());
  assert.equal(result.proofBoundaryResult, "REJECT_UNSELECTED_PROOF_SUITE");
  assert.match(result.contextDigestHex, /^[0-9a-f]{64}$/);
});

test("exact three-network enum rejects Fv1-style aliases", () => {
  rejects((input) => { input.networkId = "chipnet-test"; }, "ERR_SCHEMA");
});

test("context digest is recomputed rather than injected", () => {
  rejects((input) => { input.proofSessionEnvelope.contextDigestHex = "00".repeat(32); }, "ERR_CONTEXT_DIGEST");
});

test("carrier token presence rejects", () => {
  rejects((input) => { input.authenticatedTxView.inputs[1].sourceToken = { kind: "CASH_TOKEN", categoryHex: "aa".repeat(32), capability: "mutable", commitmentHex: "bb".repeat(128), amount: "0" }; }, "ERR_CARRIER_TOKEN");
});

test("raw envelope controls the parsed schedule and rejects unknown sections", () => {
  rejects((input) => { input.proofSessionEnvelope.rawEnvelopeHex = input.proofSessionEnvelope.rawEnvelopeHex.slice(0, 16) + "02" + input.proofSessionEnvelope.rawEnvelopeHex.slice(18); }, "ERR_ENVELOPE_SECTION_TYPE");
});

test("schema rejects unknown relation fields and any acceptance claim", () => {
  rejects((input) => { input.injectedContextDigestHex = input.proofSessionEnvelope.contextDigestHex; }, "ERR_SCHEMA");
  rejects((input) => { input.proofSessionEnvelope.proofBoundaryResult = "ACCEPT"; }, "ERR_SCHEMA");
});

test("provenance byte coverage and roots recompute", () => {
  rejects((input) => { input.provenanceDag.concreteLocks.state.byteOrigins[0].byteOffset = 1; }, "ERR_PROVENANCE_BYTE");
  rejects((input) => { input.provenanceDag.provenanceRootHex = "00".repeat(32); }, "ERR_PROVENANCE_ROOT");
});

test("fixture mutation helper does not share state", () => {
  const left = makeStructuralFixture(); const right = clone(left);
  left.networkId = "mainnet";
  assert.equal(right.networkId, "chipnet");
});
