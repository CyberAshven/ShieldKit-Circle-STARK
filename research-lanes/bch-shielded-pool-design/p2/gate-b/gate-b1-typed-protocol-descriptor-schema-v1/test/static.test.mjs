import Ajv2020 from 'ajv/dist/2020.js';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import {
  PENDING_SURFACE_KEYS,
  SAFE_TYPED_SCHEMA_DEFINITIONS,
  TYPED_SCHEMA_URI,
  assertTypedSchemaRefReachability,
  digestPreimage,
  fileDigest
} from '../semantic-validator.mjs';
import { validateStatic } from '../validate-static.mjs';

validateStatic();
const schemas = readdirSync(new URL('../schemas/', import.meta.url)).map(name => JSON.parse(readFileSync(new URL(`../schemas/${name}`, import.meta.url))));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: true });
schemas.forEach(schema => ajv.addSchema(schema));
const descriptorSchema = ajv.getSchema(TYPED_SCHEMA_URI);
assert.ok(descriptorSchema);
const typedSchema = descriptorSchema.schema;
assert.deepEqual(assertTypedSchemaRefReachability(typedSchema), [...SAFE_TYPED_SCHEMA_DEFINITIONS].sort());
assert.deepEqual(Object.keys(typedSchema.properties).filter(key => PENDING_SURFACE_KEYS.includes(key)).sort(), [...PENDING_SURFACE_KEYS].sort());
assert.equal(ajv.getSchema(`${TYPED_SCHEMA_URI}#/$defs/air`), undefined);
assert.equal(ajv.getSchema(`${TYPED_SCHEMA_URI}#/$defs/circleFriFoldKernel`), undefined);
const kats = JSON.parse(readFileSync(new URL('./digest.kat.json', import.meta.url)));
for (const testCase of kats.fileDigest.cases) assert.equal(fileDigest(kats.fileDigest.domain, Buffer.from(testCase.bytesHex, 'hex')), testCase.expectedSha256, `file KAT ${testCase.name}`);
for (const testCase of kats.semanticDigest.cases) assert.equal(digestPreimage(kats.semanticDigest.domain, JSON.parse(testCase.inputJson)), testCase.expectedSha256, `semantic KAT ${testCase.name}`);
