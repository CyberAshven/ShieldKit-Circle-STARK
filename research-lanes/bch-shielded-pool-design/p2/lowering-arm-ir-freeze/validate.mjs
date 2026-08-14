#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';

import {
  ARTIFACT_PATH,
  REPO,
  SCHEMA_PATH,
  validatePackageSemantics
} from './generate.mjs';

export function validateLoweringArmIrPackage() {
  const schema = JSON.parse(readFileSync(resolve(REPO, SCHEMA_PATH), 'utf8'));
  const artifact = JSON.parse(readFileSync(ARTIFACT_PATH, 'utf8'));
  const validateSchema = new Ajv({ strict: true, allErrors: true }).compile(schema);
  const errors = [];
  if (!validateSchema(artifact)) errors.push(`schema: ${JSON.stringify(validateSchema.errors)}`);
  errors.push(...validatePackageSemantics(artifact));
  return { artifact, errors };
}

const isMain = process.argv[1] && (
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  || process.argv[1].replaceAll('\\', '/').endsWith('/lowering-arm-ir-freeze/validate.mjs')
  || process.argv[1].replaceAll('\\', '/') === 'research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/validate.mjs'
);
if (isMain) {
  const { artifact, errors } = validateLoweringArmIrPackage();
  if (errors.length) throw new Error(`lowering-arm IR package validation failed: ${errors.join('; ')}`);
  process.stdout.write(
    `OK schema=${SCHEMA_PATH} artifact=${artifact.artifactId} programs=${artifact.programIndex.length} modules=${artifact.moduleIndex.length} plans=${artifact.planIndex.length} content=${artifact.contentDigest.value}\n`
  );
}
