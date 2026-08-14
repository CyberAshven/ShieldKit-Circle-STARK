import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import Ajv from "ajv/dist/2020.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../../../..");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(HERE, name), "utf8"));
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const contractSchema = readJson("contract.v3.schema.json");
const sourcePinsSchema = readJson("source-pins.v3.schema.json");
const manifestSchema = readJson("manifest.v3.schema.json");
const v2ContractPath = path.join(ROOT, "research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v2/contract.v2.json");
const v2Contract = JSON.parse(fs.readFileSync(v2ContractPath, "utf8"));
const EXPECTED_ADDITIVE = [
  "A3-MANIFEST-MUTATION-ORIGINAL-LOCKS",
  "A3-MANIFEST-STATE-CATEGORY-COORDINATED",
  "A3-REDEEM-REPLACEMENT-UNCHANGED-LOCK",
  "A3-N3-ORDINAL-LOCK-REDEEM-FRAME-SOURCE-SWAPS",
  "A3-ACTION-DISPLAY-FLIP-REMOVAL",
  "A3-STATE-DELTA-BOUNDARIES-BOTH-TOPOLOGIES",
  "A3-SOURCE-TABLE-LEAF-COVERAGE",
  "A3-RUNTIME-INTEGER-BOUNDARIES",
  "A3-DEPENDENCY-CYCLE-INJECTION",
  "A3-DIRECT-GENESIS-PROVENANCE-MISMATCH",
  "A3-V2-NAMESPACE-MAGIC-DOMAIN-SCHEMA-REUSE",
  "A3-GENERIC-CARRIER-LOCK-SUBSTITUTION",
  "A3-CARRIER-NONMINIMAL-FINAL-REDEEM-WRAPPER-SUFFIX",
  "A3-TOKEN-AMBIGUITY-LANGUAGE-ESCAPES",
  "A3-PHYSICAL-CHAIN-IDENTITY-CLAIM",
  "A3-ROLE-LOCAL-INPUTINDEX-MISMATCH",
  "A3-STATE-POOL-ID-FOREIGN-OLD-NEW",
  "A3-PAF1-CODEC-VERSION-RESERVED",
  "A3-SEQUENCE-WRAP",
  "A3-STATE-BASE-CAPACITY-VALUE-EQUATION",
  "A3-PROOF-SUITE-STATUS-DIGEST-PAIRS",
  "A3-POOL-IDENTITY-FREE-MISCOMPUTED",
  "A3-CARRIER-COUNT-BOUNDARIES-N0-N484",
  "A3-CARRIER-SIZE-OVERLIMITS",
  "A3-TX-FIXED-VERSION-LOCKTIME-SEQUENCES",
  "A3-MONEYRANGE-AGGREGATE-OVERFLOW",
];
const EXPECTED_PINS = [
  "ABI3-NORMATIVE-CHARTER-V3",
  "ABI3-SUCCESSOR-CHECKPOINT",
  "ABI2-STATIC-REDTEAM-HOLD",
  "ABI2-FALSIFIER-CONTRACT",
  "ABI2-CHARTER",
  "ABI2-RELATION-PACKAGE-MANIFEST",
];
const STATUSES = ["PLANNED", "MATERIALIZED", "EXECUTED", "PASSED"];
const TRANSITIONS = new Set(["PLANNED->MATERIALIZED", "MATERIALIZED->EXECUTED", "EXECUTED->PASSED"]);

export class FalsifierContractV3Error extends Error {
  constructor(code, message) { super(code + ": " + message); this.code = code; }
}
function fail(code, message) { throw new FalsifierContractV3Error(code, message); }
function require(condition, code, message) { if (!condition) fail(code, message); }
function compile(schema) {
  const ajv = new Ajv({ allErrors: true, strict: true });
  return ajv.compile(schema);
}
function schemaCheck(validator, value, name) {
  require(validator(value), "ERR_SCHEMA", name + ": " + (validator.errors ? JSON.stringify(validator.errors) : "invalid"));
}
function exactSet(actual, expected, code, name) {
  const a = [...actual].sort();
  const e = [...expected].sort();
  require(JSON.stringify(a) === JSON.stringify(e), code, name + " exact-set mismatch");
}
function assertNoWildcards(row) {
  const fields = row.mutationMetadata.targetFields;
  require(fields.every((field) => field.length > 0 && !/[＊*]/.test(field) && !/^(?:all|any)$/i.test(field)), "ERR_MUTATION_METADATA", row.familyId + " has wildcard mutation metadata");
}
export function validateStatusTransition(from, to) {
  require(STATUSES.includes(from) && STATUSES.includes(to), "ERR_STATUS", "unknown status");
  if (from === to) return true;
  require(TRANSITIONS.has(from + "->" + to), "ERR_STATUS_TRANSITION", from + " -> " + to + " is not an allowed transition");
  return true;
}
function assertNamespace(contract) {
  require(contract.abiVersion === 3, "ERR_NAMESPACE", "ABI version is not 3");
  require(contract.contractId.endsWith("/v3"), "ERR_NAMESPACE", "contract namespace is not v3");
  require(contract.namespacePolicy.packageNamespace.endsWith("v3"), "ERR_NAMESPACE", "package namespace is not v3");
  require(contract.namespacePolicy.abiNamespace.endsWith("/v3"), "ERR_NAMESPACE", "ABI namespace is not v3");
  require(contract.namespacePolicy.binaryVersion === 3 && contract.namespacePolicy.runtimeMagic === "P3", "ERR_NAMESPACE", "ABI3 binary identity is wrong");
  require(contract.namespacePolicy.hashDomainSuffix === "/v3", "ERR_NAMESPACE", "hash domains are not v3");
  for (const token of ["/v2", "P2DM", "P2TV", "P2SG", "P2GR", "P2PE", "P2RI", "P2RT", "P2TS", "P2PI"]) {
    require(contract.namespacePolicy.forbiddenV2Tokens.includes(token), "ERR_NAMESPACE", "forbidden v2 token missing: " + token);
  }
  for (const token of contract.namespacePolicy.forbiddenV2Tokens) {
    require(token !== "" && token !== "/v3", "ERR_NAMESPACE", "invalid forbidden namespace token");
  }
}
export function validateSourcePinsValue(pins) {
  schemaCheck(compile(sourcePinsSchema), pins, "source pins");
  exactSet(pins.requiredPinIds, EXPECTED_PINS, "ERR_SOURCE_PINS", "required pin IDs");
  exactSet(pins.pins.map((pin) => pin.id), EXPECTED_PINS, "ERR_SOURCE_PINS", "source pin IDs");
  const primary = pins.pins.find((pin) => pin.id === "ABI3-NORMATIVE-CHARTER-V3");
  const checkpoint = pins.pins.find((pin) => pin.id === "ABI3-SUCCESSOR-CHECKPOINT");
  require(primary.role === "PRIMARY_NORMATIVE_BYTE_AUTHORITY", "ERR_SOURCE_PINS", "v3 charter is not primary normative authority");
  require(checkpoint.role.includes("historical") && checkpoint.role.includes("not normative"), "ERR_SOURCE_PINS", "successor checkpoint is incorrectly normative");
  for (const pin of pins.pins) {
    const absolute = path.join(ROOT, pin.path);
    require(fs.existsSync(absolute), "ERR_SOURCE_PINS", "missing source pin: " + pin.path);
    const actual = sha256(fs.readFileSync(absolute));
    require(actual === pin.sha256, "ERR_SOURCE_PINS", pin.id + " hash mismatch");
  }
}
function validateRows(contract) {
  const rows = contract.rows;
  require(rows.length === contract.rowCount, "ERR_ROWS", "rowCount mismatch");
  require(new Set(rows.map((row) => row.familyId)).size === rows.length, "ERR_ROWS", "duplicate familyId");
  const retained = rows.filter((row) => row.lineage === "V2_RETAINED");
  const additive = rows.filter((row) => row.lineage === "ABI3_ADDITIVE");
  require(retained.length === v2Contract.rows.length, "ERR_LINEAGE", "retained v2 row count mismatch");
  require(additive.length === EXPECTED_ADDITIVE.length, "ERR_LINEAGE", "ABI3 additive row count mismatch");
  exactSet(retained.map((row) => row.familyId), v2Contract.rows.map((row) => row.familyId), "ERR_LINEAGE", "retained family IDs");
  exactSet(additive.map((row) => row.familyId), EXPECTED_ADDITIVE, "ERR_ADDITIVE", "additive family IDs");
  const manifestRow = rows.find((row) => row.familyId === "A3-MANIFEST-MUTATION-ORIGINAL-LOCKS");
  const manifestFields = ["networkTag", "reserved", "protocolTemplateDigest", "poolInstanceId", "preExistingAnchorDigest", "genesisAncestryDigest", "stateCategoryWire", "ticketSats", "stateCarrierBaseSats", "maxLifetimeDeposits", "feePolicyMaxSats", "proofSuiteStatus", "proofSuiteManifestDigest", "noUpgrade", "carrierCount", "carrierLayout[].ordinal", "carrierLayout[].inputIndex", "carrierLayout[].outputIndex", "carrierLayout[].expectedValueSats", "depositRoleMap.stateInputIndex", "depositRoleMap.externalInputIndex", "depositRoleMap.stateOutputIndex", "depositRoleMap.payoutPresent", "depositRoleMap.payoutOutputIndex", "depositRoleMap.changeOptional", "depositRoleMap.changeOutputIndex", "withdrawalRoleMap.stateInputIndex", "withdrawalRoleMap.externalInputIndex", "withdrawalRoleMap.stateOutputIndex", "withdrawalRoleMap.payoutPresent", "withdrawalRoleMap.payoutOutputIndex", "withdrawalRoleMap.changeOptional", "withdrawalRoleMap.changeOutputIndex"];
  require(JSON.stringify(manifestRow.mutationMetadata.targetFields) === JSON.stringify(manifestFields), "ERR_MANIFEST_AXES", "section-6 manifest mutation axes are incomplete or reordered");
  for (const row of retained) {
    const source = v2Contract.rows.find((candidate) => candidate.familyId === row.familyId);
    require(row.sourceFamilyId === source.familyId, "ERR_LINEAGE", row.familyId + " sourceFamilyId mismatch");
    require(row.sourceGroup === source.group && row.sourceClassification === source.classification && row.sourceLayer === source.layer && row.sourceDependencyGate === source.dependencyGate && row.sourceMinStableVariants === source.minStableVariants && row.sourceStatus === source.status, "ERR_LINEAGE", row.familyId + " source obligation drift");
    require(row.mutationMetadata.mutationKind === "MIGRATED_V2_OBLIGATION", "ERR_MUTATION_METADATA", row.familyId + " missing migrated mutation kind");
    require(row.mutationMetadata.requiredBeforeGate1 === false, "ERR_STATUS", row.familyId + " falsely marked mandatory");
  }
  for (const row of additive) {
    require(row.sourceFamilyId === null && row.mutationMetadata.mutationKind === "ABI3_MANDATORY", "ERR_ADDITIVE", row.familyId + " additive lineage fields invalid");
    require(row.mutationMetadata.requiredBeforeGate1 === true, "ERR_ADDITIVE", row.familyId + " is not mandatory before Gate 1");
  }
  for (const row of rows) {
    require(row.status === "PLANNED", "ERR_EXECUTION_CLAIM", row.familyId + " is not initially planned");
    require(row.metaValidation === "SCHEMA_AND_CONTRACT_ONLY", "ERR_EXECUTION_CLAIM", row.familyId + " meta-validation boundary missing");
    require(row.mutationMetadata.runtimeNamespace === "PoolActionFv2/falsifier-contract/v3", "ERR_NAMESPACE", row.familyId + " runtime namespace mismatch");
    require(row.mutationMetadata.targetFields.length > 0 && row.mutationMetadata.preserve.length > 0 && row.mutationMetadata.mutationModes.length > 0, "ERR_MUTATION_METADATA", row.familyId + " incomplete mutation metadata");
    assertNoWildcards(row);
  }
  const counts = Object.fromEntries(STATUSES.map((status) => [status, rows.filter((row) => row.status === status).length]));
  require(JSON.stringify(counts) === JSON.stringify(contract.statusCounts), "ERR_STATUS", "statusCounts mismatch");
  require(contract.materializedVariantCount === 0 && contract.executedVariantCount === 0 && contract.passedVariantCount === 0, "ERR_EXECUTION_CLAIM", "contract claims relation execution");
  require(contract.lineageCounts.V2_RETAINED === retained.length && contract.lineageCounts.ABI3_ADDITIVE === additive.length, "ERR_LINEAGE", "lineageCounts mismatch");
}
export function validateContractValue(contract, options = {}) {
  schemaCheck(compile(contractSchema), contract, "contract");
  assertNamespace(contract);
  validateRows(contract);
  if (options.verifySources !== false) {
    const pins = readJson("source-pins.v3.json");
    schemaCheck(compile(sourcePinsSchema), pins, "source pins");
    validateSourcePinsValue(pins);
    const manifest = readJson("MANIFEST.json");
    schemaCheck(compile(manifestSchema), manifest, "manifest");
    require(manifest.fileCount === manifest.files.length, "ERR_MANIFEST", "manifest fileCount mismatch");
    for (const file of manifest.files) require(fs.existsSync(path.join(HERE, file)), "ERR_MANIFEST", "manifest file missing: " + file);
  }
  return { rowCount: contract.rowCount, retained: contract.retainedV2FamilyCount, additive: contract.additiveAbi3FamilyCount, statusCounts: contract.statusCounts, materialized: contract.materializedVariantCount, executed: contract.executedVariantCount, passed: contract.passedVariantCount };
}
export function validateContract() {
  return validateContractValue(readJson("contract.v3.json"));
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  require(process.argv[2] === "--self-check", "ERR_USAGE", "usage: node validate.mjs --self-check");
  console.log(JSON.stringify(validateContract()));
}
