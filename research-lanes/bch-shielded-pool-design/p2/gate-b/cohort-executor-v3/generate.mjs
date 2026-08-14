import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalBytes, digestRecord, omit } from '../cohort-execution-v3/contract.mjs';
import { validateStaticExecutor } from './authority.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = path.resolve(here, '../../../../..');
const packageRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3';
const sha = body => crypto.createHash('sha256').update(body).digest('hex');
const byteSort = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const rel = file => path.relative(workspace, file).split(path.sep).join('/');
const staticNames = Object.freeze(['README.md', 'COMMAND.txt', 'authority.mjs', 'commit-helper.mjs', 'durable-io.mjs', 'static-executor.mjs', 'evidence-validator.mjs', 'evidence-builder.mjs', 'materializer.mjs', 'runner-open.mjs', 'cli.mjs', 'generate.mjs', 'executor.test.mjs', 'evidence-validator.test.mjs', 'runner-open.test.mjs', 'authorization.v3.schema.json', 'execution-claim.v3.schema.json', 'evidence-manifest.v3.schema.json', 'evidence-root.v3.schema.json', 'raw-engine-observation.v3.schema.json', 'normalized-engine-result.v3.schema.json', 'cross-engine-summary.v3.schema.json', 'manifest.v1.schema.json']);
export function buildManifest() {
  const files = staticNames.map(name => { const body = fs.readFileSync(path.join(here, name)); return { path: rel(path.join(here, name)), rawSha256: sha(body), byteLength: body.length }; }).sort((a, b) => byteSort(a.path, b.path));
  const manifest = { schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v3/manifest/v1', status: 'static-unexecuted-no-authorization', files, coverage: { listedPayloadCount: files.length, selfManifestExcluded: true, checksumsExcluded: true } };
  manifest.contentDigest = digestRecord(omit(manifest), 'shieldkit-labs/p2/gate-b/cohort-executor-v3/package-manifest/root'); return manifest;
}
export function writeStaticPackage() {
  const manifest = buildManifest(); fs.writeFileSync(path.join(here, 'MANIFEST.json'), canonicalBytes(manifest));
  const rows = [[sha(fs.readFileSync(path.join(here, 'MANIFEST.json'))), `${packageRel}/MANIFEST.json`], ...manifest.files.map(file => [file.rawSha256, file.path])];
  fs.writeFileSync(path.join(here, 'SHA256SUMS'), Buffer.from(`${rows.map(row => row.join('  ')).join('\n')}\n`, 'utf8'));
  return Object.freeze({ manifestDigest: manifest.contentDigest.value });
}
export function checkStaticPackage() {
  const expected = buildManifest(); const current = JSON.parse(fs.readFileSync(path.join(here, 'MANIFEST.json'), 'utf8'));
  if (!canonicalBytes(current).equals(canonicalBytes(expected))) throw new Error('cohort-executor-v3 generator: manifest drift');
  const rows = [[sha(fs.readFileSync(path.join(here, 'MANIFEST.json'))), `${packageRel}/MANIFEST.json`], ...expected.files.map(item => [item.rawSha256, item.path])];
  const sums = Buffer.from(`${rows.map(row => row.join('  ')).join('\n')}\n`, 'utf8');
  if (!fs.readFileSync(path.join(here, 'SHA256SUMS')).equals(sums)) throw new Error('cohort-executor-v3 generator: checksum drift');
  return validateStaticExecutor();
}
if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length === 3 && process.argv[2] === '--check') console.log(JSON.stringify(checkStaticPackage()));
  else if (process.argv.length === 3 && process.argv[2] === '--write-static') console.log(JSON.stringify(writeStaticPackage()));
  else throw new Error('cohort-executor-v3 generator accepts exactly --check or --write-static');
}
