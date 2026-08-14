import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  validateContractValue,
  validateSourcePinsValue,
  validateStatusTransition,
} from "./validate.mjs";

const here = path.dirname(new URL(import.meta.url).pathname);
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(here, name), "utf8"));
const clone = (value) => JSON.parse(JSON.stringify(value));
const base = readJson("contract.v3.json");
const expectCode = (mutate, code) => {
  const value = clone(base);
  mutate(value);
  assert.throws(() => validateContractValue(value, { verifySources: false }), (error) => error.code === code, code);
};

test("ABI3 contract is statically complete and execution-free", () => {
  const result = validateContractValue(base);
  assert.deepEqual(result, {
    rowCount: 99,
    retained: 73,
    additive: 26,
    statusCounts: { PLANNED: 99, MATERIALIZED: 0, EXECUTED: 0, PASSED: 0 },
    materialized: 0,
    executed: 0,
    passed: 0,
  });
});

test("duplicate IDs and missing retained/additive IDs reject", () => {
  expectCode((value) => { value.rows[1].familyId = value.rows[0].familyId; }, "ERR_ROWS");
  expectCode((value) => { value.rows = value.rows.filter((row) => row.familyId !== "A3-DEPENDENCY-CYCLE-INJECTION"); value.rowCount = 98; }, "ERR_SCHEMA");
  expectCode((value) => { value.rows = value.rows.filter((row) => row.familyId !== "RF-POS-NET-MAINNET-00"); value.rowCount = 98; }, "ERR_SCHEMA");
});

test("lineage and source obligation drift reject", () => {
  expectCode((value) => { value.rows.find((row) => row.lineage === "V2_RETAINED").sourceStatus = "PLANNED"; }, "ERR_LINEAGE");
  expectCode((value) => { value.rows.find((row) => row.lineage === "ABI3_ADDITIVE").sourceFamilyId = "RF-FAKE"; }, "ERR_ADDITIVE");
  expectCode((value) => { value.rows.find((row) => row.lineage === "ABI3_ADDITIVE").mutationMetadata.requiredBeforeGate1 = false; }, "ERR_ADDITIVE");
});

test("incomplete, wildcard, and unknown mutation metadata reject", () => {
  expectCode((value) => { delete value.rows[0].mutationMetadata.targetFields; }, "ERR_SCHEMA");
  expectCode((value) => { delete value.rows[0].mutationMetadata.mutationModes; }, "ERR_SCHEMA");
  expectCode((value) => { value.rows[0].mutationMetadata.targetFields = ["*"]; }, "ERR_MUTATION_METADATA");
  expectCode((value) => { value.rows[0].mutationMetadata.extra = true; }, "ERR_SCHEMA");
});

test("execution status claims and status counts reject", () => {
  expectCode((value) => { value.rows[0].status = "MATERIALIZED"; }, "ERR_EXECUTION_CLAIM");
  expectCode((value) => { value.statusCounts.PLANNED = 98; }, "ERR_SCHEMA");
  expectCode((value) => { value.materializedVariantCount = 1; }, "ERR_SCHEMA");
});

test("v2 namespace, magic, domain, and ABI reuse reject", () => {
  expectCode((value) => { value.contractId = "PoolActionFv2/falsifier-contract/v2"; }, "ERR_SCHEMA");
  expectCode((value) => { value.namespacePolicy.runtimeMagic = "P2TV"; }, "ERR_SCHEMA");
  expectCode((value) => { value.namespacePolicy.hashDomainSuffix = "/v2"; }, "ERR_SCHEMA");
  expectCode((value) => { value.rows[0].mutationMetadata.runtimeNamespace = "PoolActionFv2/falsifier-contract/v2"; }, "ERR_SCHEMA");
  for (const token of ["P2RI", "P2RT", "P2TS", "P2PI"]) {
    expectCode((value) => { value.namespacePolicy.forbiddenV2Tokens = value.namespacePolicy.forbiddenV2Tokens.filter((entry) => entry !== token); }, "ERR_NAMESPACE");
  }
});

test("normative v3 charter is primary and section-6 manifest mutation is exhaustive", () => {
  const pins = readJson("source-pins.v3.json");
  assert.equal(pins.pins[0].id, "ABI3-NORMATIVE-CHARTER-V3");
  assert.equal(pins.pins[0].sha256, "bb89cdc724aabefbe8f2dfced3c9e4934dc4ee48fecb92856b2982523cc81b4f");
  assert.equal(pins.pins[0].role, "PRIMARY_NORMATIVE_BYTE_AUTHORITY");
  assert.match(pins.pins.find((pin) => pin.id === "ABI3-SUCCESSOR-CHECKPOINT").role, /historical.*not normative/);
  const row = base.rows.find((candidate) => candidate.familyId === "A3-MANIFEST-MUTATION-ORIGINAL-LOCKS");
  assert.equal(row.mutationMetadata.targetFields.length, 33);
  const missing = clone(base);
  missing.rows.find((candidate) => candidate.familyId === "A3-MANIFEST-MUTATION-ORIGINAL-LOCKS").mutationMetadata.targetFields = row.mutationMetadata.targetFields.slice(0, -1);
  assert.throws(() => validateContractValue(missing, { verifySources: false }), (error) => error.code === "ERR_MANIFEST_AXES");
  const roleSwap = base.rows.find((candidate) => candidate.familyId === "A3-ROLE-LOCAL-INPUTINDEX-MISMATCH");
  assert.deepEqual(roleSwap.mutationMetadata.targetFields, [
    "OP_INPUTINDEX",
    "roleInstance.fixedInputIndex",
    "TxViewV3.inputRecords[].derivedRoleTag",
    "TxViewV3.inputRecords[].wireIndex",
    "TxViewV3.outputRecords[].derivedRoleTag",
    "TxViewV3.outputRecords[].wireIndex",
  ]);
  assert.equal(roleSwap.mutationMetadata.expectedOutcome, "REJECT_ROLE_RELOCATION_OR_ROLE_TAG_WIRE_INDEX_SWAP");
  assert.ok(roleSwap.mutationMetadata.mutationModes.includes("role-tag-wire-index-swap"));
  const runtime = base.rows.find((candidate) => candidate.familyId === "A3-RUNTIME-INTEGER-BOUNDARIES");
  assert.deepEqual(runtime.mutationMetadata.targetFields, [
    "PoolStateFv1.sequence",
    "PoolStateFv1.depositCount",
    "PoolStateFv1.withdrawalCount",
    "LE8(2^63)",
    "LE8(2^63)+",
    "sequence transition 2^63-2 -> 2^63-1",
    "sequence increment from 2^63-1",
  ]);
  assert.equal(runtime.mutationMetadata.expectedOutcome, "ACCEPT_MAX_BOUNDARY_REJECT_2^63_PLUS_OR_SEQUENCE_INCREMENT_FROM_MAX");
  assert.ok(runtime.mutationMetadata.mutationModes.includes("accept-sequence-max-boundary"));
  assert.ok(runtime.mutationMetadata.mutationModes.includes("reject-increment-from-max"));
  const sequenceWrap = base.rows.find((candidate) => candidate.familyId === "A3-SEQUENCE-WRAP");
  assert.ok(sequenceWrap.mutationMetadata.targetFields.includes("LE8(2^63-1)"));
  assert.ok(sequenceWrap.mutationMetadata.mutationModes.includes("reject-increment-from-2^63-1"));
});

test("missing, duplicate, and unknown source pins reject", () => {
  const pins = readJson("source-pins.v3.json");
  const missing = clone(pins); missing.pins = missing.pins.slice(0, -1); missing.requiredPinIds = missing.requiredPinIds.slice(0, -1);
  assert.throws(() => validateSourcePinsValue(missing), (error) => error.code === "ERR_SCHEMA" || error.code === "ERR_SOURCE_PINS");
  const duplicate = clone(pins); duplicate.pins[1].id = duplicate.pins[0].id;
  assert.throws(() => validateSourcePinsValue(duplicate), (error) => error.code === "ERR_SOURCE_PINS");
  const unknown = clone(pins); unknown.pins[0].id = "ABI3-UNKNOWN";
  assert.throws(() => validateSourcePinsValue(unknown), (error) => error.code === "ERR_SOURCE_PINS");
});

test("status transition model is explicit and monotone", () => {
  assert.equal(validateStatusTransition("PLANNED", "PLANNED"), true);
  assert.equal(validateStatusTransition("PLANNED", "MATERIALIZED"), true);
  assert.equal(validateStatusTransition("MATERIALIZED", "EXECUTED"), true);
  assert.equal(validateStatusTransition("EXECUTED", "PASSED"), true);
  assert.throws(() => validateStatusTransition("PLANNED", "EXECUTED"), /ERR_STATUS_TRANSITION/);
  assert.throws(() => validateStatusTransition("PASSED", "PLANNED"), /ERR_STATUS_TRANSITION/);
});

test("all mandatory ABI3 families carry exact mutation metadata", () => {
  const mandatory = base.rows.filter((row) => row.lineage === "ABI3_ADDITIVE");
  assert.equal(mandatory.length, 26);
  for (const row of mandatory) {
    assert.equal(row.status, "PLANNED");
    assert.equal(row.mutationMetadata.requiredBeforeGate1, true);
    assert.ok(row.mutationMetadata.targetFields.length > 0);
    assert.ok(!row.mutationMetadata.targetFields.some((field) => field.includes("*")));
  }
});
