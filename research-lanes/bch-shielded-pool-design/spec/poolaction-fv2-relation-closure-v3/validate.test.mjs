// SPDX-License-Identifier: CC0-1.0
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  MAX_RUNTIME_U64,
  PoolActionFv2Abi3Error,
  buildCodecLeafRosterV3,
  buildFieldSourceTableV3,
  canonicalDependencyGraphV3,
  deriveRelationV3,
  deriveStructuralProvenanceV3,
  encodeDeploymentManifestV3Core,
  encodeMinimalPush,
  encodeSegmentFrameV3,
  parseCarrierUnlockingBytecodeV3,
  parseDeploymentManifestV3Core,
  parsePoolIdentityConfigV3,
  parseRuntimeU64LeHex,
  parseTxViewV3,
  runtimeU64LeHex,
  validateDependencyGraphV3,
  validateFieldSourceCoverageV3,
  validateStructuralProvenanceV3,
} from "./validate.mjs";
import { buildFixtureV3 } from "./fixture-builder.mjs";
import {
  ABI3_SCHEMA_FILENAMES,
  ABI3_SCHEMA_IDS,
  PoolActionFv2Abi3SchemaError,
  assertAbi3SchemaValid,
  compileAbi3SchemasV3,
} from "./schema-validation-v3.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const clone = (value) => structuredClone(value);
const rawU64LeHex = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(value); return bytes.toString("hex"); };
const fixtures = Object.fromEntries(["DEPOSIT", "WITHDRAWAL"].flatMap((action) => [1, 3].map((n) => {
  const fixture = buildFixtureV3(action, n);
  return [`${action}-N${n}`, fixture];
})));

function expectCode(fn, code) {
  assert.throws(fn, (error) => error instanceof PoolActionFv2Abi3Error && error.code === code, `expected ${code}`);
}

function expectSchemaCode(fn, code) {
  assert.throws(fn, (error) => error instanceof PoolActionFv2Abi3SchemaError && error.code === code, `expected ${code}`);
}

function mutateHexByte(hex, offset) {
  const bytes = Buffer.from(hex, "hex");
  bytes[offset] ^= 0x01;
  return bytes.toString("hex");
}

function setStateField(raw, which, value) {
  const fixture = clone(raw);
  const offset = { sequence: 8, depositCount: 16, withdrawalCount: 24 }[which];
  const mutate = (projection) => {
    const bytes = Buffer.from(projection.commitmentHex, "hex");
    Buffer.from(rawU64LeHex(value), "hex").copy(bytes, offset);
    projection.commitmentHex = bytes.toString("hex");
  };
  mutate(fixture.relationInput.transaction.inputs[0].tokenProjection);
  mutate(fixture.relationInput.transaction.outputs[0].tokenProjection);
  return fixture;
}

function rawInput(fixtureName) { return clone(fixtures[fixtureName].raw.relationInput); }

test("four N=1/N=3 structural fixtures deterministically proof-reject", () => {
  for (const [name, fixture] of Object.entries(fixtures)) {
    const derived = deriveRelationV3(fixture.raw.relationInput);
    assert.equal(derived.verdict, "REJECT_UNSELECTED_PROOF_SUITE", name);
    assert.equal(derived.proofAccepted, false, name);
    assert.equal(derived.structuralOnly, true, name);
    assert.equal(derived.action, name.startsWith("DEPOSIT") ? "DEPOSIT" : "WITHDRAWAL", name);
  }
});

test("materialized raw/KAT fixtures replay exactly from raw evidence", () => {
  const fixtureDir = path.join(HERE, "fixtures");
  for (const action of ["DEPOSIT", "WITHDRAWAL"]) {
    for (const carrierCount of [1, 3]) {
      const stem = `structural-${action.toLowerCase()}-n${carrierCount}.v3`;
      const raw = JSON.parse(fs.readFileSync(path.join(fixtureDir, `${stem}.raw.json`), "utf8"));
      const kat = JSON.parse(fs.readFileSync(path.join(fixtureDir, `${stem}.kat.json`), "utf8"));
      const built = buildFixtureV3(action, carrierCount);
      assert.deepEqual(raw, built.raw, `${stem} raw builder replay`);
      assert.deepEqual(kat, built.expected, `${stem} KAT builder replay`);
      assert.deepEqual(deriveRelationV3(raw.relationInput), kat, `${stem} raw relation replay`);
      assert.equal(validateStructuralProvenanceV3(raw.structuralProvenance), true, `${stem} provenance replay`);
    }
  }
});

test("P3DM/P3PI parser recomputes lock-selected pool identity", () => {
  const provenance = fixtures["DEPOSIT-N3"].raw.structuralProvenance;
  const manifest = parseDeploymentManifestV3Core(Buffer.from(provenance.deploymentManifestCoreHex, "hex"));
  const identity = parsePoolIdentityConfigV3(Buffer.from(provenance.poolIdentityConfigHex, "hex"));
  assert.equal(manifest.poolInstanceId.toString("hex"), provenance.poolInstanceIdHex);
  assert.equal(identity.poolInstanceId.toString("hex"), provenance.poolInstanceIdHex);
  assert.equal(manifest.core.length, 282 + (20 * 3));
  assert.equal(manifest.poolIdentityConfig.length, 218 + (20 * 3));
});

test("every fixture provenance replays exact compiler bytes and byte origins", () => {
  for (const fixture of Object.values(fixtures)) assert.equal(validateStructuralProvenanceV3(fixture.raw.structuralProvenance), true);
});

test("all ABI-v3 schemas are closed, namespace-clean, and compile together under offline Ajv2020", () => {
  const schemaDir = path.join(HERE, "schemas");
  const names = fs.readdirSync(schemaDir).filter((name) => name.endsWith(".json"));
  assert.deepEqual(names.sort(), ABI3_SCHEMA_FILENAMES);
  for (const name of names) {
    const schema = JSON.parse(fs.readFileSync(path.join(schemaDir, name), "utf8"));
    assert.equal(schema.$id.endsWith("/v3"), true, name);
    assert.equal(schema.additionalProperties, false, name);
    assert.equal(JSON.stringify(schema).includes("/v2"), false, name);
  }
  const compiled = compileAbi3SchemasV3(schemaDir);
  assert.equal(compiled.validators.size, ABI3_SCHEMA_FILENAMES.length);
});

test("all materialized raw wrappers and KATs validate under compiled ABI-v3 schemas", () => {
  const compiled = compileAbi3SchemasV3();
  const fixtureDir = path.join(HERE, "fixtures");
  for (const action of ["DEPOSIT", "WITHDRAWAL"]) {
    for (const carrierCount of [1, 3]) {
      const stem = `structural-${action.toLowerCase()}-n${carrierCount}.v3`;
      const raw = JSON.parse(fs.readFileSync(path.join(fixtureDir, `${stem}.raw.json`), "utf8"));
      const kat = JSON.parse(fs.readFileSync(path.join(fixtureDir, `${stem}.kat.json`), "utf8"));
      assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.structuralFixtureRaw, raw, `${stem}.raw`);
      assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.derivedResult, kat, `${stem}.kat`);
      assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.carrierSession, {
        schema: ABI3_SCHEMA_IDS.carrierSession,
        carrierUnlockingBytecodesHex: raw.relationInput.carrierUnlockingBytecodesHex,
      }, `${stem}.carrier-session`);
      assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.comparisonManifestCore, {
        schema: ABI3_SCHEMA_IDS.comparisonManifestCore,
        comparisonOnly: true,
        deploymentManifestCoreHex: kat.deploymentManifestCoreHex,
      }, `${stem}.comparison-manifest`);
    }
  }
  for (const [filename, schemaId] of [
    ["codec-leaf-roster-v3.json", ABI3_SCHEMA_IDS.codecLeafRoster],
    ["field-source-table-v3.json", ABI3_SCHEMA_IDS.fieldSourceTable],
    ["dependency-graph-v3.json", ABI3_SCHEMA_IDS.dependencyGraph],
  ]) {
    const artifact = JSON.parse(fs.readFileSync(path.join(HERE, filename), "utf8"));
    assertAbi3SchemaValid(compiled, schemaId, artifact, filename);
  }
});

test("compiled schemas reject missing derived bytes, nested role gaps, out-of-domain integers, and unknown fields", () => {
  const compiled = compileAbi3SchemasV3();
  const raw = clone(fixtures["DEPOSIT-N1"].raw);
  const kat = clone(fixtures["DEPOSIT-N1"].expected);
  delete kat.contextDigestHex;
  expectSchemaCode(() => assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.derivedResult, kat, "missing-derived-byte"), "ERR_SCHEMA_INVALID");
  const missingRoleIntervals = clone(raw);
  delete missingRoleIntervals.structuralProvenance.roles[0].redeemIntervals;
  expectSchemaCode(() => assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.structuralFixtureRaw, missingRoleIntervals, "missing-role-intervals"), "ERR_SCHEMA_INVALID");
  const nonRuntimeSequence = clone(raw);
  nonRuntimeSequence.relationInput.transaction.inputs[0].sequenceLeHex = "0000000000000080";
  expectSchemaCode(() => assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.structuralFixtureRaw, nonRuntimeSequence, "u64-overflow"), "ERR_SCHEMA_INVALID");
  const unknownTopLevel = clone(raw);
  unknownTopLevel.untrustedDerivedDigestHex = "00".repeat(32);
  expectSchemaCode(() => assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.structuralFixtureRaw, unknownTopLevel, "unknown-top-level"), "ERR_SCHEMA_INVALID");
  const malformedSourceRow = JSON.parse(fs.readFileSync(path.join(HERE, "field-source-table-v3.json"), "utf8"));
  delete malformedSourceRow.fixtureTables[0].rows[0].sourceClass;
  expectSchemaCode(() => assertAbi3SchemaValid(compiled, ABI3_SCHEMA_IDS.fieldSourceTable, malformedSourceRow, "missing-source-class"), "ERR_SCHEMA_INVALID");
});

test("every manifest config mutation under original state lock rejects", () => {
  const raw = rawInput("DEPOSIT-N1");
  const coreStart = 3; // PUSHDATA2 plus little-endian manifest length in the state redeem.
  const offsets = [6, 8, 40, 72, 104, 136, 168, 176, 184, 192, 200, 201, 233, 234, 238, 242, 246, 250, 258, 262, 266, 270, 274, 280, 284, 288, 292, 296];
  for (const offset of offsets) {
    const mutated = clone(raw);
    mutated.stateActiveRedeemHex = mutateHexByte(mutated.stateActiveRedeemHex, coreStart + offset);
    assert.throws(() => deriveRelationV3(mutated), PoolActionFv2Abi3Error, `manifest byte ${offset}`);
  }
});

test("coordinated manifest/state category substitution still fails original lock selection", () => {
  const raw = rawInput("DEPOSIT-N1");
  raw.stateActiveRedeemHex = mutateHexByte(raw.stateActiveRedeemHex, 3 + 136);
  const mutateCategory = (projection) => { projection.categoryWireHex = mutateHexByte(projection.categoryWireHex, 0); };
  mutateCategory(raw.transaction.inputs[0].tokenProjection);
  mutateCategory(raw.transaction.outputs[0].tokenProjection);
  expectCode(() => deriveRelationV3(raw), "ERR_POOL_IDENTITY");
});

test("distinct and generic redeems cannot replace the redeem selected by original locks", () => {
  const state = rawInput("DEPOSIT-N1");
  state.stateActiveRedeemHex = `${state.stateActiveRedeemHex.slice(0, -2)}51`;
  assert.throws(() => deriveRelationV3(state), PoolActionFv2Abi3Error);
  const carrier = rawInput("DEPOSIT-N1");
  carrier.carrierUnlockingBytecodesHex[0] = `${carrier.carrierUnlockingBytecodesHex[0].slice(0, -2)}51`;
  assert.throws(() => deriveRelationV3(carrier), PoolActionFv2Abi3Error);
});

test("N=3 ordinal lock/redeem/frame/source swaps reject", () => {
  const raw = rawInput("DEPOSIT-N3");
  [raw.transaction.inputs[1], raw.transaction.inputs[2]] = [raw.transaction.inputs[2], raw.transaction.inputs[1]];
  [raw.transaction.outputs[1], raw.transaction.outputs[2]] = [raw.transaction.outputs[2], raw.transaction.outputs[1]];
  [raw.carrierUnlockingBytecodesHex[0], raw.carrierUnlockingBytecodesHex[1]] = [raw.carrierUnlockingBytecodesHex[1], raw.carrierUnlockingBytecodesHex[0]];
  assert.throws(() => deriveRelationV3(raw), PoolActionFv2Abi3Error);
});

test("caller action labels are never an authority", () => {
  for (const value of ["DEPOSIT", "WITHDRAWAL", "", null]) {
    const raw = rawInput("DEPOSIT-N1");
    raw.actionKind = value;
    expectCode(() => deriveRelationV3(raw), "ERR_SCHEMA_KEYS");
  }
  assert.equal(deriveRelationV3(rawInput("DEPOSIT-N1")).action, "DEPOSIT");
});

test("delta/topology mutations reject against both action forms", () => {
  for (const fixtureName of ["DEPOSIT-N1", "WITHDRAWAL-N1"]) {
    for (const delta of [0n, 1n, 20000000n]) {
      const raw = rawInput(fixtureName);
      const old = Buffer.from(raw.transaction.inputs[0].sourceValueSatsLeHex, "hex").readBigUInt64LE();
      raw.transaction.outputs[0].valueSatsLeHex = runtimeU64LeHex(old + delta);
      assert.throws(() => deriveRelationV3(raw), PoolActionFv2Abi3Error, `${fixtureName}/${delta}`);
    }
  }
});

test("TxView parser re-derives action from parsed state values", () => {
  const txView = Buffer.from(fixtures["DEPOSIT-N1"].expected.txViewBytesHex, "hex");
  txView[6] = 0x01; // Change only the caller-like action label byte.
  const manifest = Buffer.from(fixtures["DEPOSIT-N1"].expected.deploymentManifestCoreHex, "hex");
  expectCode(() => parseTxViewV3(txView, manifest), "ERR_TX_ROLE_ORDINAL");
});

test("field-source exact-set checks reject every required malformed family", () => {
  const roster = buildCodecLeafRosterV3(1, 3, 3);
  const table = buildFieldSourceTableV3(1, 3, 3);
  validateFieldSourceCoverageV3(roster, table);
  for (let index = 0; index < roster.length; index += 1) {
    const missing = table.filter((_, i) => i !== index);
    expectCode(() => validateFieldSourceCoverageV3(roster, missing), "ERR_COVERAGE_SET");
    const duplicate = [...table, table[index]];
    expectCode(() => validateFieldSourceCoverageV3(roster, duplicate), "ERR_COVERAGE_DUPLICATE");
  }
  expectCode(() => validateFieldSourceCoverageV3([...roster, "carrier[*].hidden"], table), "ERR_COVERAGE_WILDCARD");
  expectCode(() => validateFieldSourceCoverageV3(roster, [...table, { leafId: "unknown.leaf", sourceClass: "INTROSPECTED", dependencyNodes: [] }]), "ERR_COVERAGE_SET");
  expectCode(() => validateFieldSourceCoverageV3(roster, table.map((row, index) => index === 0 ? { ...row, sourceClass: "CALLER" } : row)), "ERR_COVERAGE_CLASS");
  const derivedIndex = table.findIndex((row) => row.sourceClass === "DERIVED_AND_CHECKED");
  expectCode(() => validateFieldSourceCoverageV3(roster, table.map((row, index) => index === derivedIndex ? { ...row, dependencyNodes: [] } : row)), "ERR_COVERAGE_DEPENDENCY");
  expectCode(() => validateFieldSourceCoverageV3(roster, table.map((row, index) => index === derivedIndex ? { ...row, dependencyNodes: ["not-a-node"] } : row)), "ERR_COVERAGE_DEPENDENCY");
});

test("materialized N=1/N=3 leaf roster and source table are exact", () => {
  const rosterArtifact = JSON.parse(fs.readFileSync(path.join(HERE, "codec-leaf-roster-v3.json"), "utf8"));
  const tableArtifact = JSON.parse(fs.readFileSync(path.join(HERE, "field-source-table-v3.json"), "utf8"));
  assert.equal(rosterArtifact.schema, "shieldkit-labs/poolaction-fv2/codec-leaf-roster/v3");
  assert.equal(tableArtifact.schema, "shieldkit-labs/poolaction-fv2/field-source-table/v3");
  assert.equal(rosterArtifact.fixtureRosters.length, 4);
  assert.equal(tableArtifact.fixtureTables.length, 4);
  for (let index = 0; index < 4; index += 1) {
    const roster = rosterArtifact.fixtureRosters[index];
    const table = tableArtifact.fixtureTables[index];
    assert.equal(roster.fixtureId, table.fixtureId);
    assert.deepEqual(roster.leaves, buildCodecLeafRosterV3(roster.carrierCount, roster.inputCount, roster.outputCount));
    assert.deepEqual(table.rows, buildFieldSourceTableV3(table.carrierCount, table.inputCount, table.outputCount));
    assert.equal(validateFieldSourceCoverageV3(roster.leaves, table.rows), true);
  }
});

test("runtime integer and PAF1 boundary domain are exact", () => {
  assert.equal(parseRuntimeU64LeHex(runtimeU64LeHex(MAX_RUNTIME_U64)), MAX_RUNTIME_U64);
  expectCode(() => runtimeU64LeHex(0x8000000000000000n), "ERR_RUNTIME_U64");
  expectCode(() => parseRuntimeU64LeHex("0000000000000080"), "ERR_RUNTIME_U64");
  expectCode(() => parseRuntimeU64LeHex("0100000000000080"), "ERR_RUNTIME_U64");
  for (const invalid of ["-1", "1", "0001", "01", "00000000000000000", "0000000000000000ff"]) assert.throws(() => parseRuntimeU64LeHex(invalid), PoolActionFv2Abi3Error);
  const boundary = rawInput("DEPOSIT-N1");
  const set = (projection, offset, value) => { const bytes = Buffer.from(projection.commitmentHex, "hex"); Buffer.from(runtimeU64LeHex(value), "hex").copy(bytes, offset); projection.commitmentHex = bytes.toString("hex"); };
  set(boundary.transaction.inputs[0].tokenProjection, 8, MAX_RUNTIME_U64 - 1n);
  set(boundary.transaction.outputs[0].tokenProjection, 8, MAX_RUNTIME_U64);
  assert.equal(deriveRelationV3(boundary).verdict, "REJECT_UNSELECTED_PROOF_SUITE");
  const maxIncrement = clone(boundary);
  set(maxIncrement.transaction.inputs[0].tokenProjection, 8, MAX_RUNTIME_U64);
  expectCode(() => deriveRelationV3(maxIncrement), "ERR_STATE_TRANSITION");
  for (const field of ["sequence", "depositCount", "withdrawalCount"]) {
    const invalid = setStateField(fixtures["DEPOSIT-N1"].raw, field, 0x8000000000000000n);
    expectCode(() => deriveRelationV3(invalid.relationInput), "ERR_RUNTIME_U64");
    const larger = setStateField(fixtures["DEPOSIT-N1"].raw, field, 0x8000000000000001n);
    expectCode(() => deriveRelationV3(larger.relationInput), "ERR_RUNTIME_U64");
  }
});

test("dependency graph is exact and rejects an outer-root cycle", () => {
  const graph = canonicalDependencyGraphV3();
  validateDependencyGraphV3(graph);
  const cycle = clone(graph);
  cycle.edges.push({ from: "sessionDigest", to: "carrierPayloads" });
  expectCode(() => validateDependencyGraphV3(cycle), "ERR_DEPENDENCY_EDGE");
});

test("carrier framing rejects nonminimal wrappers, final redeem mutation, prefix, suffix, and length aliases", () => {
  const raw = rawInput("DEPOSIT-N1");
  const script = Buffer.from(raw.carrierUnlockingBytecodesHex[0], "hex");
  const variants = [
    Buffer.concat([Buffer.from([0x4c, script[0]]), script.subarray(1)]),
    Buffer.concat([Buffer.from([0x00]), script]),
    Buffer.concat([script, Buffer.from([0x00])]),
    Buffer.concat([script.subarray(0, -1)]),
  ];
  for (const variant of variants) assert.throws(() => parseCarrierUnlockingBytecodeV3(variant), PoolActionFv2Abi3Error);
});

test("token collision projections are rejected in every forbidden role", () => {
  const roles = [
    ["inputs", 1], ["inputs", 2], ["outputs", 1], ["outputs", 2], ["outputs", 3],
  ];
  // The native projection cannot distinguish these two forbidden token forms;
  // exercising both labels demonstrates that neither is relabelled as NONE.
  for (const _form of ["FT_ONLY", "IMMUTABLE_EMPTY_NFT_PLUS_FT"]) {
    for (const [side, index] of roles) {
      const raw = rawInput("WITHDRAWAL-N1");
      raw.transaction[side][index].tokenProjection = { categoryWireHex: "22".repeat(32), commitmentHex: "", amountLeHex: "0000000000000000" };
      expectCode(() => deriveRelationV3(raw), "ERR_TOKEN_LANGUAGE");
    }
  }
});

test("state token evidence requires the observed mutable extended category and rejects native-prefix injection", () => {
  const baseline = rawInput("DEPOSIT-N1");
  const baseCategory = baseline.transaction.inputs[0].tokenProjection.categoryWireHex.slice(0, 64);
  assert.equal(baseline.transaction.inputs[0].tokenProjection.categoryWireHex, `${baseCategory}01`);
  assert.equal(baseline.transaction.outputs[0].tokenProjection.categoryWireHex, `${baseCategory}01`);
  for (const [side, index] of [["inputs", 0], ["outputs", 0]]) {
    const missingSuffix = rawInput("DEPOSIT-N1");
    missingSuffix.transaction[side][index].tokenProjection.categoryWireHex = baseCategory;
    expectCode(() => deriveRelationV3(missingSuffix), "ERR_TOKEN_LANGUAGE");
    const immutableCollision = rawInput("DEPOSIT-N1");
    immutableCollision.transaction[side][index].tokenProjection.categoryWireHex = "22".repeat(32);
    expectCode(() => deriveRelationV3(immutableCollision), "ERR_TOKEN_LANGUAGE");
    const wrongCapability = rawInput("DEPOSIT-N1");
    wrongCapability.transaction[side][index].tokenProjection.categoryWireHex = `${baseCategory}02`;
    expectCode(() => deriveRelationV3(wrongCapability), "ERR_TOKEN_CATEGORY");
    const prefixInCategorySlot = rawInput("DEPOSIT-N1");
    prefixInCategorySlot.transaction[side][index].tokenProjection.categoryWireHex = `ef${baseCategory}6180${prefixInCategorySlot.transaction[side][index].tokenProjection.commitmentHex}`;
    expectCode(() => deriveRelationV3(prefixInCategorySlot), "ERR_TOKEN_LANGUAGE");
    const unknownPrefixField = rawInput("DEPOSIT-N1");
    unknownPrefixField.transaction[side][index].tokenProjection.nativeTokenPrefixHex = `ef${baseCategory}6180${unknownPrefixField.transaction[side][index].tokenProjection.commitmentHex}`;
    expectCode(() => deriveRelationV3(unknownPrefixField), "ERR_SCHEMA_KEYS");
  }
});

test("physical chain and shared dynamic active-index claims reject", () => {
  for (const field of ["physicalChainIdentity", "activeInputIndexLeHex"]) {
    const raw = rawInput("DEPOSIT-N1");
    raw[field] = "regtest";
    expectCode(() => deriveRelationV3(raw), "ERR_SCHEMA_KEYS");
  }
});

test("provenance/genesis mismatch and unsupported selected suite reject", () => {
  expectCode(() => deriveStructuralProvenanceV3({
    anchorTxHashOpcodeOrderHex: "33".repeat(32), anchorOutputIndexLeHex: "0000000000000000", networkId: "regtest",
    stateCarrierBaseSatsLeHex: "00e1f50500000000", maxLifetimeDepositsLeHex: "0100000000000000", feePolicyMaxSatsLeHex: "e803000000000000",
    carrierExpectedValuesSatsLeHex: ["e803000000000000"], genesisInitialStateValueSatsLeHex: "01e1f50500000000",
  }), "ERR_PROVENANCE_GENESIS");
  const provenance = fixtures["DEPOSIT-N1"].raw.structuralProvenance;
  const manifest = parseDeploymentManifestV3Core(Buffer.from(provenance.deploymentManifestCoreHex, "hex"));
  assert.equal(manifest.proofSuiteStatus, "UNSELECTED");
});

test("carrier bounds and fixed transaction constants reject", () => {
  const raw = rawInput("DEPOSIT-N1");
  raw.transaction.versionLeHex = runtimeU64LeHex(3n);
  expectCode(() => deriveRelationV3(raw), "ERR_TX_VERSION");
  const locktime = rawInput("DEPOSIT-N1"); locktime.transaction.locktimeLeHex = runtimeU64LeHex(1n);
  expectCode(() => deriveRelationV3(locktime), "ERR_TX_LOCKTIME");
  const sequence = rawInput("DEPOSIT-N1"); sequence.transaction.inputs[0].sequenceLeHex = runtimeU64LeHex(1n);
  expectCode(() => deriveRelationV3(sequence), "ERR_TX_SEQUENCE");
  expectCode(() => parseCarrierUnlockingBytecodeV3(Buffer.alloc(10001)), "ERR_SCRIPT_SIZE");
  const badCount = clone(fixtures["DEPOSIT-N1"].raw.relationInput);
  badCount.stateActiveRedeemHex = mutateHexByte(badCount.stateActiveRedeemHex, 3 + 234);
  assert.throws(() => deriveRelationV3(badCount), PoolActionFv2Abi3Error);
});

test("manifest encoder rejects status pairs and carrier count outside 1..483", () => {
  const provenance = fixtures["DEPOSIT-N1"].raw.structuralProvenance;
  const parsed = parseDeploymentManifestV3Core(Buffer.from(provenance.deploymentManifestCoreHex, "hex"));
  const spec = {
    networkId: parsed.networkId, protocolTemplateDigestHex: parsed.protocolTemplateDigest.toString("hex"), poolInstanceIdHex: parsed.poolInstanceId.toString("hex"),
    preExistingAnchorDigestHex: parsed.preExistingAnchorDigest.toString("hex"), genesisAncestryDigestHex: parsed.genesisAncestryDigest.toString("hex"), stateCategoryWireHex: parsed.stateCategoryWire.toString("hex"),
    stateCarrierBaseSatsLeHex: runtimeU64LeHex(parsed.stateCarrierBaseSats), maxLifetimeDepositsLeHex: runtimeU64LeHex(parsed.maxLifetimeDeposits), feePolicyMaxSatsLeHex: runtimeU64LeHex(parsed.feePolicyMaxSats),
    proofSuiteStatusHex: "01", proofSuiteManifestDigestHex: "00".repeat(32), carrierCountLeHex: runtimeU64LeHex(1n),
    carrierLayout: [{ ordinalLeHex: runtimeU64LeHex(0n), inputIndexLeHex: runtimeU64LeHex(1n), outputIndexLeHex: runtimeU64LeHex(1n), expectedValueSatsLeHex: runtimeU64LeHex(parsed.carrierLayout[0].expectedValueSats) }],
  };
  expectCode(() => encodeDeploymentManifestV3Core(spec), "ERR_PROOF_SUITE");
  spec.proofSuiteStatusHex = "00";
  spec.proofSuiteManifestDigestHex = "00".repeat(32);
  spec.carrierCountLeHex = runtimeU64LeHex(484n);
  expectCode(() => encodeDeploymentManifestV3Core(spec), "ERR_CARRIER_COUNT");
});

test("N=483 is the exact structural maximum and N=484 cannot encode", () => {
  const common = {
    anchorTxHashOpcodeOrderHex: "44".repeat(32), anchorOutputIndexLeHex: runtimeU64LeHex(0n), networkId: "regtest",
    stateCarrierBaseSatsLeHex: runtimeU64LeHex(100000000n), maxLifetimeDepositsLeHex: runtimeU64LeHex(10n), feePolicyMaxSatsLeHex: runtimeU64LeHex(10000n),
    genesisInitialStateValueSatsLeHex: runtimeU64LeHex(100000000n),
  };
  const atMaximum = deriveStructuralProvenanceV3({ ...common, carrierExpectedValuesSatsLeHex: Array.from({ length: 483 }, () => runtimeU64LeHex(1000n)) });
  assert.equal(atMaximum.manifestCore.length, 282 + (20 * 483));
  assert.equal(atMaximum.roles[1].redeem.length, 308 + (20 * 483));
  const frame = encodeSegmentFrameV3({ ordinal: 0, inputIndex: 1, payload: Buffer.from([0x42]) });
  const fullUnlocking = Buffer.concat([encodeMinimalPush(frame), encodeMinimalPush(atMaximum.roles[1].redeem)]);
  assert.equal(fullUnlocking.length, 331 + (20 * 483));
  assert.equal(fullUnlocking.length <= 10000, true);
  expectCode(() => deriveStructuralProvenanceV3({ ...common, carrierExpectedValuesSatsLeHex: Array.from({ length: 484 }, () => runtimeU64LeHex(1000n)) }), "ERR_CARRIER_COUNT");
});
