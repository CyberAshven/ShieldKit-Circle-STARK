import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { buildContract, canonicalBytes, digestRecord, omit, PACKAGE_REL, validateContract, validateManifest } from './contract.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = path.resolve(here, '../../../../..');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-execution-v3 generator: ${message}`); };
const byteSort = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const rel = file => path.relative(workspace, file).split(path.sep).join('/');
const staticNames = Object.freeze(['README.md', 'COMMAND.txt', 'contract.mjs', 'lean-aggregate.mjs', 'fixtures.mjs', 'adapters.mjs', 'generate.mjs', 'execution-contract.test.mjs', 'lean-aggregate.test.mjs', 'fixtures.test.mjs', 'execution-contract.v3.schema.json', 'evidence-shape.v3.schema.json', 'manifest.v1.schema.json', 'execution-contract.v3.json']);
const write = (file, value) => fs.writeFileSync(file, Buffer.isBuffer(value) ? value : canonicalBytes(value));
const listed = () => staticNames.map(name => {
  const file = path.join(here, name); const body = fs.readFileSync(file);
  return { path: rel(file), rawSha256: sha(body), byteLength: body.length };
}).sort((a, b) => byteSort(a.path, b.path));
export function buildManifest() {
  const manifest = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v3/manifest/v1', status: 'frozen-unexecuted', files: listed(), coverage: { listedPayloadCount: staticNames.length, selfManifestExcluded: true, checksumsExcluded: true } };
  manifest.contentDigest = digestRecord(omit(manifest), 'shieldkit-labs/p2/gate-b/cohort-execution-v3/package-manifest/root');
  return manifest;
}
export function writeStaticPackage() {
  write(path.join(here, 'execution-contract.v3.json'), buildContract());
  const manifest = buildManifest(); write(path.join(here, 'MANIFEST.json'), manifest);
  const rows = [[sha(fs.readFileSync(path.join(here, 'MANIFEST.json'))), `${PACKAGE_REL}/MANIFEST.json`], ...manifest.files.map(file => [file.rawSha256, file.path])];
  fs.writeFileSync(path.join(here, 'SHA256SUMS'), Buffer.from(`${rows.map(row => row.join('  ')).join('\n')}\n`, 'utf8'));
  return Object.freeze({ contractDigest: buildContract().contentDigest.value, manifestDigest: manifest.contentDigest.value });
}
export function checkStaticPackage() {
  validateContract(); validateManifest();
  return Object.freeze({ status: 'PASS', mode: 'read-only-check' });
}
if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length === 3 && process.argv[2] === '--write-static') console.log(JSON.stringify(writeStaticPackage()));
  else if (process.argv.length === 3 && process.argv[2] === '--check') console.log(JSON.stringify(checkStaticPackage()));
  else { assert(false, 'use exactly --check or --write-static'); }
}
