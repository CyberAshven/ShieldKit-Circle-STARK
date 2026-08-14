import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { PACKAGE_REL, canonicalBytes, digestRecord, omit, validatePackageEnvelope } from './validator.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const repo = path.resolve(here, '../../../../../');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const byteSort = (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const staticNames = Object.freeze(['README.md', 'COMMAND.txt', 'live-failure.v2.schema.json', 'checkpoint.v2.schema.json', 'checkpoint-manifest.v2.schema.json', 'manifest.v1.schema.json', 'validator.mjs', 'validator.test.mjs', 'generate.mjs', 'test-support/failure-fixture.mjs']);
const rel = file => path.relative(repo, file).split(path.sep).join('/');
const listed = () => staticNames.map(name => { const file = path.join(here, name); const bytes = fs.readFileSync(file); return { path: rel(file), rawSha256: sha(bytes), byteLength: bytes.length }; }).sort((left, right) => byteSort(left.path, right.path));
export function buildManifest() { const value = { schema: 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/package-manifest/v1', manifestId: 'manifest:cohort-live-accounting-v2-package', status: 'authority-neutral-schema-only', evidenceClassification: 'failure-recovery-grammar-not-execution-evidence', executionAllowed: false, metricsAllowed: false, ranking: null, selection: null, coverage: { packageRoot: PACKAGE_REL, listedPayloadCount: staticNames.length, selfManifestExcluded: true, checksumsExcluded: true, symlinksForbidden: true }, files: listed() }; value.contentDigest = digestRecord('shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/package-manifest/root', omit(value)); return value; }
export function writeStaticPackage() { const manifest = buildManifest(); fs.writeFileSync(path.join(here, 'MANIFEST.json'), canonicalBytes(manifest)); const rows = [[sha(fs.readFileSync(path.join(here, 'MANIFEST.json'))), `${PACKAGE_REL}/MANIFEST.json`], ...manifest.files.map(file => [file.rawSha256, file.path])]; fs.writeFileSync(path.join(here, 'SHA256SUMS'), Buffer.from(`${rows.map(row => row.join('  ')).join('\n')}\n`, 'utf8')); return Object.freeze({ manifestDigest: manifest.contentDigest.value, listedPayloadCount: manifest.files.length }); }
if (import.meta.url === `file://${process.argv[1]}`) { if (process.argv[2] === '--write-static') console.log(JSON.stringify(writeStaticPackage())); else if (process.argv[2] === '--check') { validatePackageEnvelope(); console.log(JSON.stringify({ status: 'PASS', mode: 'read-only-check' })); } else throw new Error('cohort-live-accounting-v2 generator accepts exactly --write-static or --check'); }
