import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, checkSourceSet, sha256, validatePlanEmission } from './generate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fail = (message) => { throw new Error(`source-set-v1 validation: ${message}`); };
const readJson = (path) => JSON.parse(readFileSync(resolve(here, path), 'utf8'));
const rootSchema = readJson('source-set.v1.schema.json');
const mapSchema = readJson('plan-source-map.v1.schema.json');
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateRootSchema = ajv.compile(rootSchema);
const validateMapSchema = ajv.compile(mapSchema);

const assertSchema = (validator, value, label) => {
  if (!validator(value)) fail(`${label} schema rejection: ${ajv.errorsText(validator.errors, { separator: '; ' })}`);
};

export const assertRootSchema = (root) => assertSchema(validateRootSchema, root, 'root');
export const assertMapSchema = (map) => assertSchema(validateMapSchema, map, `map ${map?.planId ?? '<unknown>'}`);
export const assertExactGeneratedRoot = (actual, expected) => {
  if (canonicalJson(actual) !== canonicalJson(expected)) fail('root semantic equality to deterministic regeneration failed');
};
export const assertExactGeneratedMap = (actual, expected) => {
  if (canonicalJson(actual) !== canonicalJson(expected)) fail(`${actual?.planId ?? '<unknown>'} map semantic equality to deterministic regeneration failed`);
};

export const validateSourceSet = () => {
  const generated = checkSourceSet();
  const rootBytes = readFileSync(resolve(here, 'source-set.v1.json'));
  const actualRoot = JSON.parse(rootBytes);
  assertRootSchema(actualRoot);
  if (sha256(rootBytes) !== sha256(Buffer.from(canonicalJson(actualRoot), 'utf8'))) fail('root is not canonical JSON bytes');
  assertExactGeneratedRoot(actualRoot, generated.root);
  for (const expected of generated.built) {
    const actualAsm = readFileSync(resolve(here, expected.paths.asmPath), 'utf8');
    const actualHex = readFileSync(resolve(here, expected.paths.hexPath), 'utf8');
    const actualMap = readJson(expected.paths.mapPath);
    assertMapSchema(actualMap);
    if (!/^[0-9a-f]+\n$/u.test(actualHex) || actualHex !== `${expected.bytecode.toString('hex')}\n`) fail(`${expected.plan.planId}: lowercase hex artifact drift`);
    validatePlanEmission({ asm: actualAsm, bytecode: expected.bytecode, map: actualMap, plan: expected.plan });
    assertExactGeneratedMap(actualMap, expected.map);
  }
  return generated;
};

if (process.argv[1] === fileURLToPath(import.meta.url)) validateSourceSet();
