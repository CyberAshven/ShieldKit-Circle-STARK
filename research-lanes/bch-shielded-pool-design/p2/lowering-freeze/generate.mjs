#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DIRECTORY, canonicalJson, generateLoweringFreeze, sha256, validateLoweringFreezeSemantics } from './lowering-freeze.mjs';

const artifactPath = resolve(DIRECTORY, 'lowering-freeze.v1.json');
const sumsPath = resolve(DIRECTORY, 'SHA256SUMS');
const tracked = ['README.md', 'COMMAND.txt', 'lowering-freeze.mjs', 'generate.mjs', 'validate.mjs', 'lowering-freeze.test.mjs', 'lowering-freeze.v1.schema.json', 'lowering-freeze.v1.json'];
const artifact = generateLoweringFreeze();
const bytes = Buffer.from(canonicalJson(artifact), 'utf8');
const sums = () => `${tracked.map((name) => `${sha256(name === 'lowering-freeze.v1.json' ? bytes : readFileSync(resolve(DIRECTORY, name)))}  ${name}`).join('\n')}\n`;

if (process.argv.includes('--write')) {
  writeFileSync(artifactPath, bytes);
  writeFileSync(sumsPath, sums(), 'utf8');
  process.stdout.write(`WROTE ${artifactPath}\nBYTES ${bytes.length}\nSHA256 ${sha256(bytes)}\nCONTENT_DIGEST ${artifact.contentDigest.value}\n`);
} else if (process.argv.includes('--print')) process.stdout.write(bytes);
else {
  const current = readFileSync(artifactPath);
  if (!current.equals(bytes)) throw new Error('lowering-freeze artifact differs from deterministic regeneration; run node generate.mjs --write');
  if (readFileSync(sumsPath, 'utf8') !== sums()) throw new Error('SHA256SUMS differs from frozen file set; run node generate.mjs --write');
  const parsed = JSON.parse(current.toString('utf8'));
  const errors = validateLoweringFreezeSemantics(parsed);
  if (errors.length) throw new Error(`lowering-freeze semantic validation failed: ${errors.join('; ')}`);
  process.stdout.write(`OK ${artifactPath}\nBYTES ${bytes.length}\nSHA256 ${sha256(bytes)}\nCONTENT_DIGEST ${artifact.contentDigest.value}\n`);
}
