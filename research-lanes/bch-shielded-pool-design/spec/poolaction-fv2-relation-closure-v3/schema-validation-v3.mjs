// SPDX-License-Identifier: CC0-1.0
// Offline Draft 2020-12 schema compilation and instance validation for ABI-v3.

import Ajv2020 from "ajv/dist/2020.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const ABI3_SCHEMA_FILENAMES = Object.freeze([
  "carrier-session-v3.schema.json",
  "codec-leaf-roster-v3.schema.json",
  "comparison-manifest-core-v3.schema.json",
  "dependency-graph-v3.schema.json",
  "derived-result-v3.schema.json",
  "field-source-table-v3.schema.json",
  "raw-introspected-tx-evidence-v3.schema.json",
  "relation-input-v3.schema.json",
  "structural-fixture-raw-v3.schema.json",
  "structural-provenance-v3.schema.json",
  "verifier-role-consumption-v3.schema.json",
]);

export const ABI3_SCHEMA_IDS = Object.freeze({
  carrierSession: "shieldkit-labs/poolaction-fv2/carrier-session/v3",
  codecLeafRoster: "shieldkit-labs/poolaction-fv2/codec-leaf-roster/v3",
  comparisonManifestCore: "shieldkit-labs/poolaction-fv2/comparison-manifest-core/v3",
  dependencyGraph: "shieldkit-labs/poolaction-fv2/dependency-graph/v3",
  derivedResult: "shieldkit-labs/poolaction-fv2/derived-result/v3",
  fieldSourceTable: "shieldkit-labs/poolaction-fv2/field-source-table/v3",
  rawIntrospectedTxEvidence: "shieldkit-labs/poolaction-fv2/raw-introspected-tx-evidence/v3",
  relationInput: "shieldkit-labs/poolaction-fv2/relation-input/v3",
  structuralFixtureRaw: "shieldkit-labs/poolaction-fv2/structural-fixture-raw/v3",
  structuralProvenance: "shieldkit-labs/poolaction-fv2/structural-provenance/v3",
  verifierRoleConsumption: "shieldkit-labs/poolaction-fv2/verifier-role-consumption/v3",
});

export class PoolActionFv2Abi3SchemaError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PoolActionFv2Abi3SchemaError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PoolActionFv2Abi3SchemaError(code, message);
}

function walkSchemaRequiredProperties(schema, filename, pointer = "#") {
  if (Array.isArray(schema)) {
    schema.forEach((value, index) => walkSchemaRequiredProperties(value, filename, `${pointer}/${index}`));
    return;
  }
  if (!schema || typeof schema !== "object") return;
  if (Object.hasOwn(schema, "required")) {
    if (!Array.isArray(schema.required)) fail("ERR_SCHEMA_CONTRACT", `${filename}:${pointer}: required must be an array`);
    const properties = schema.properties;
    if (!properties || typeof properties !== "object" || Array.isArray(properties)) {
      fail("ERR_SCHEMA_CONTRACT", `${filename}:${pointer}: required has no sibling properties object`);
    }
    const seen = new Set();
    for (const field of schema.required) {
      if (typeof field !== "string" || field.length === 0 || seen.has(field)) {
        fail("ERR_SCHEMA_CONTRACT", `${filename}:${pointer}: required contains an invalid or duplicate field`);
      }
      seen.add(field);
      if (!Object.hasOwn(properties, field)) {
        fail("ERR_SCHEMA_CONTRACT", `${filename}:${pointer}: required field ${field} has no sibling properties entry`);
      }
    }
  }
  for (const [key, value] of Object.entries(schema)) walkSchemaRequiredProperties(value, filename, `${pointer}/${key}`);
}

function formatAjvErrors(errors) {
  return (errors ?? []).map((error) => `${error.instancePath || "/"} ${error.keyword}: ${error.message}`).join("; ");
}

export function compileAbi3SchemasV3(schemaDirectory = path.join(HERE, "schemas")) {
  let filenames;
  try {
    filenames = fs.readdirSync(schemaDirectory).filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    fail("ERR_SCHEMA_LOAD", `cannot list ABI-v3 schema directory: ${error.message}`);
  }
  if (JSON.stringify(filenames) !== JSON.stringify(ABI3_SCHEMA_FILENAMES)) {
    fail("ERR_SCHEMA_SET", `ABI-v3 schema filename set differs: ${filenames.join(", ")}`);
  }

  const schemaById = new Map();
  const parsed = [];
  for (const filename of filenames) {
    let schema;
    try {
      schema = JSON.parse(fs.readFileSync(path.join(schemaDirectory, filename), "utf8"));
    } catch (error) {
      fail("ERR_SCHEMA_LOAD", `cannot parse ${filename}: ${error.message}`);
    }
    if (!schema || typeof schema !== "object" || Array.isArray(schema) || typeof schema.$id !== "string" || !schema.$id.endsWith("/v3")) {
      fail("ERR_SCHEMA_CONTRACT", `${filename}: missing ABI-v3 $id`);
    }
    if (schema.additionalProperties !== false) fail("ERR_SCHEMA_CONTRACT", `${filename}: root object must be closed`);
    if (JSON.stringify(schema).includes("/v2")) fail("ERR_SCHEMA_CONTRACT", `${filename}: v2 namespace is forbidden`);
    walkSchemaRequiredProperties(schema, filename);
    if (schemaById.has(schema.$id)) fail("ERR_SCHEMA_CONTRACT", `${filename}: duplicate $id ${schema.$id}`);
    schemaById.set(schema.$id, schema);
    parsed.push([filename, schema]);
  }

  const expectedIds = new Set(Object.values(ABI3_SCHEMA_IDS));
  if (schemaById.size !== expectedIds.size || [...expectedIds].some((id) => !schemaById.has(id))) {
    fail("ERR_SCHEMA_SET", "ABI-v3 schema IDs differ from the closed package set");
  }

  const ajv = new Ajv2020({ allErrors: true, strict: true });
  try {
    for (const [, schema] of parsed) ajv.addSchema(schema);
  } catch (error) {
    fail("ERR_SCHEMA_COMPILE", `Ajv2020 addSchema failed: ${error.message}`);
  }
  const validators = new Map();
  for (const [filename, schema] of parsed) {
    try {
      const validator = ajv.getSchema(schema.$id);
      if (!validator) fail("ERR_SCHEMA_COMPILE", `Ajv2020 did not return a validator for ${filename}`);
      validators.set(schema.$id, validator);
    } catch (error) {
      if (error instanceof PoolActionFv2Abi3SchemaError) throw error;
      fail("ERR_SCHEMA_COMPILE", `Ajv2020 compile failed for ${filename}: ${error.message}`);
    }
  }
  return Object.freeze({ ajv, schemaDirectory, validators });
}

export function assertAbi3SchemaValid(compiled, schemaId, instance, label = "instance") {
  if (!compiled || !(compiled.validators instanceof Map)) fail("ERR_SCHEMA_CONTRACT", "compiled ABI-v3 schemas are required");
  const validator = compiled.validators.get(schemaId);
  if (!validator) fail("ERR_SCHEMA_ID", `unknown ABI-v3 schema ID: ${schemaId}`);
  if (!validator(instance)) {
    fail("ERR_SCHEMA_INVALID", `${label} violates ${schemaId}: ${formatAjvErrors(validator.errors)}`);
  }
  return true;
}
