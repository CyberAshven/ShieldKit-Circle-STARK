#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, generateScheduleFreeze, sha256, validateScheduleFreezeSemantics } from './schedule-freeze.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const artifactPath = resolve(directory, 'schedule-freeze.v1.json');
const manifestPath = resolve(directory, 'SHA256SUMS');
const tracked = [
  'README.md',
  'generate.mjs',
  'schedule-freeze.mjs',
  'schedule-freeze.test.mjs',
  'schedule-freeze.v1.json',
  'schedule-freeze.v1.schema.json'
];
const artifact = generateScheduleFreeze();
const bytes = Buffer.from(canonicalJson(artifact), 'utf8');

const sums = () => `${tracked.map((name) => {
  const body = name === 'schedule-freeze.v1.json' ? bytes : readFileSync(resolve(directory, name));
  return `${sha256(body)}  ${name}`;
}).join('\n')}\n`;

if (process.argv.includes('--write')) {
  writeFileSync(artifactPath, bytes);
  writeFileSync(manifestPath, sums(), 'utf8');
  process.stdout.write(`WROTE ${artifactPath}\nSHA256 ${sha256(bytes)}\n`);
} else if (process.argv.includes('--print')) {
  process.stdout.write(bytes);
} else {
  const current = readFileSync(artifactPath);
  if (!current.equals(bytes)) throw new Error('schedule-freeze artifact differs from deterministic regeneration; run node generate.mjs --write');
  if (readFileSync(manifestPath, 'utf8') !== sums()) throw new Error('SHA256SUMS differs from frozen file set; run node generate.mjs --write');
  const parsed = JSON.parse(current.toString('utf8'));
  const errors = validateScheduleFreezeSemantics(parsed);
  if (errors.length > 0) throw new Error(`schedule-freeze semantic validation failed: ${errors.join('; ')}`);
  process.stdout.write(`OK ${artifactPath}\nSHA256 ${sha256(bytes)}\n`);
}
