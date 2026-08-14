#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import {
  EXPECTED_CONSTRUCTIONS,
  canonicalJson,
  generateDescriptorV2Set,
  validateDescriptorV2,
} from './algebra-component-descriptor-v2.mjs';

const moduleDir = dirname(fileURLToPath(import.meta.url));
const descriptorDir = resolve(moduleDir, 'descriptors');
const manifestPath = resolve(descriptorDir, 'SHA256SUMS.v2');
const mode = process.argv[2] ?? '--check';
const schema = JSON.parse(readFileSync(resolve(moduleDir, 'algebra-component-descriptor.v2.schema.json'), 'utf8'));
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

if (!['--check', '--write'].includes(mode) || process.argv.length !== 3) {
  process.stderr.write('usage: node generate-descriptor-v2.mjs [--check|--write]\n');
  process.exitCode = 2;
} else {
  try {
    const descriptors = generateDescriptorV2Set();
    const expected = EXPECTED_CONSTRUCTIONS.map((construction, index) => ({
      fileName: construction.fileName,
      bytes: Buffer.from(canonicalJson(descriptors[index]), 'utf8'),
      descriptor: descriptors[index],
    }));
    for (const item of expected) {
      if (!validateSchema(item.descriptor)) throw new Error(item.fileName + ': schema failure: ' + JSON.stringify(validateSchema.errors));
      const errors = validateDescriptorV2(item.descriptor);
      if (errors.length > 0) throw new Error(item.fileName + ': ' + errors.join('; '));
    }
    const manifest = expected.map((item) => createHash('sha256').update(item.bytes).digest('hex') + '  ' + item.fileName).join('\n') + '\n';
    if (mode === '--write') {
      for (const item of expected) writeFileSync(resolve(descriptorDir, item.fileName), item.bytes);
      writeFileSync(manifestPath, manifest);
    } else {
      for (const item of expected) {
        const path = resolve(descriptorDir, item.fileName);
        if (!existsSync(path) || !readFileSync(path).equals(item.bytes)) throw new Error('descriptor diff: ' + item.fileName);
      }
      if (!existsSync(manifestPath) || readFileSync(manifestPath, 'utf8') !== manifest) throw new Error('descriptor v2 manifest diff');
    }
    process.stdout.write('descriptor-v2 ' + mode.slice(2) + ' OK: ' + expected.map((item) => item.fileName).join(', ') + '\n');
  } catch (error) {
    process.stderr.write('descriptor-v2 ' + mode.slice(2) + ' FAIL: ' + (error instanceof Error ? error.message : String(error)) + '\n');
    process.exitCode = 1;
  }
}
