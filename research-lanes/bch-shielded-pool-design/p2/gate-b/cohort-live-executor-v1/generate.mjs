import { createHash } from 'node:crypto';
import { lstat, readdir, readFile, writeFile } from 'node:fs/promises';

const CONTENT_FILES = Object.freeze([
  'README.md', 'COMMAND.txt', 'manifest.v1.schema.json', 'generate.mjs',
  'live-policy-authorization.v1.schema.json', 'snapshot-binding.v1.schema.json', 'live-claim.v1.schema.json',
  'attempt-join.v1.schema.json', 'journal-entry.v1.schema.json', 'journal-index.v1.schema.json',
  'observation-receipt.v1.schema.json', 'terminal-publication.v1.schema.json',
  'model.mjs', 'snapshot-boundary.mjs', 'observation-boundary.mjs', 'state-machine.mjs',
  'model.test.mjs', 'snapshot-boundary.test.mjs', 'observation-boundary.test.mjs', 'state-machine.test.mjs', 'package-boundary.test.mjs',
]);
const PACKAGE_FILES = Object.freeze(['MANIFEST.json', 'SHA256SUMS', ...CONTENT_FILES]);

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalJson = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
};
const domainDigest = (domain, value) => createHash('sha256').update(`ShieldKit/live-executor-static/v1/${domain}\u0000${canonicalJson(value)}`, 'utf8').digest('hex');
const renderedJson = (value) => `${JSON.stringify(value, null, 2)}\n`;

function exactArray(actual, expected, label) {
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) throw new Error(`${label} differs from the exact static roster`);
}

async function fileRecord(path) {
  const url = new URL(path, import.meta.url);
  const [metadata, bytes] = await Promise.all([lstat(url), readFile(url)]);
  const mode = (metadata.mode & 0o7777).toString(8).padStart(4, '0');
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || mode !== '0644') throw new Error(`${path} must be a single-link regular 0644 file`);
  const record = { path, sha256: sha256(bytes), byteLength: bytes.byteLength, mode, nlink: metadata.nlink, kind: 'regular' };
  return { ...record, contentDigest: domainDigest('manifest-file-content', record) };
}

async function assertExactPackageDirectory() {
  const actual = (await readdir(new URL('./', import.meta.url))).sort();
  exactArray(actual, [...PACKAGE_FILES].sort(), 'package directory');
}

async function expectedManifest() {
  await assertExactPackageDirectory();
  const files = await Promise.all(CONTENT_FILES.map(fileRecord));
  const core = {
    schemaVersion: 'live-executor-static-manifest-v1',
    package: 'cohort-live-executor-v1',
    staticOnly: true,
    executionAllowed: false,
    files,
  };
  return { ...core, contentDigest: domainDigest('manifest-content', core) };
}

async function expectedSums(manifestBytes) {
  const rows = [`${sha256(manifestBytes)}  MANIFEST.json`];
  for (const path of CONTENT_FILES) rows.push(`${(await fileRecord(path)).sha256}  ${path}`);
  return `${rows.join('\n')}\n`;
}

async function main() {
  const mode = process.argv[2];
  if (mode !== '--check' && mode !== '--write') throw new Error('usage: node generate.mjs --check|--write');
  const manifestBytes = Buffer.from(renderedJson(await expectedManifest()), 'utf8');
  const sums = await expectedSums(manifestBytes);
  if (mode === '--write') {
    // The only writer in this package is this explicit envelope refresh mode.
    await writeFile(new URL('MANIFEST.json', import.meta.url), manifestBytes);
    await writeFile(new URL('SHA256SUMS', import.meta.url), sums, 'utf8');
    return;
  }
  const [actualManifest, actualSums] = await Promise.all([
    readFile(new URL('MANIFEST.json', import.meta.url)),
    readFile(new URL('SHA256SUMS', import.meta.url), 'utf8'),
  ]);
  if (!actualManifest.equals(manifestBytes) || actualSums !== sums) throw new Error('static package envelope is stale or violates exact closure; run node generate.mjs --write explicitly');
}

await main();
