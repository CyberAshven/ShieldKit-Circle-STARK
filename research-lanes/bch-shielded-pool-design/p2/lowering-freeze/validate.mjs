#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import Ajv from 'ajv/dist/2020.js';
import { DIRECTORY, REPO, SCHEMA_PATH, validateLoweringFreezeSemantics } from './lowering-freeze.mjs';

const schema = JSON.parse(readFileSync(resolve(REPO, SCHEMA_PATH), 'utf8'));
const artifact = JSON.parse(readFileSync(resolve(DIRECTORY, 'lowering-freeze.v1.json'), 'utf8'));
const ajv = new Ajv({ strict: true, allErrors: true });
const valid = ajv.compile(schema)(artifact);
if (!valid) throw new Error(`schema validation failed: ${ajv.errorsText(ajv.errors)}`);
const errors = validateLoweringFreezeSemantics(artifact);
if (errors.length) throw new Error(`semantic validation failed: ${errors.join('; ')}`);
process.stdout.write(`OK schema=${SCHEMA_PATH} artifact=${artifact.artifactId} arms=${artifact.arms.length} relationTargets=${artifact.relationTargets.length}\n`);
