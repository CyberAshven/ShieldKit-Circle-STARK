#!/usr/bin/env node
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, generateCertificateSet, sha256, verifyCertificateSet } from './direct-construction-cohort-v2.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const artifactName = 'direct-construction-cohort-v2.v2.json';
const reportName = 'repository-replay-report.v2.txt';
const artifactPath = resolve(directory, artifactName);
const reportPath = resolve(directory, reportName);
const manifestPath = resolve(directory, 'MANIFEST.json');
const sumsPath = resolve(directory, 'SHA256SUMS');

const { artifact, report } = generateCertificateSet();
const artifactBytes = canonicalJson(artifact);
writeFileSync(artifactPath, artifactBytes, 'utf8');
writeFileSync(reportPath, report, 'utf8');
const serializedArtifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
verifyCertificateSet(serializedArtifact);

const manifestFiles = [
  artifactName,
  reportName,
  'direct-construction-cohort-v2.v2.schema.json',
  'direct-construction-cohort-v2.mjs',
  'generate.mjs',
  'repository-replay.mjs',
  'direct-construction-cohort-v2.test.mjs',
  'README.md',
  'COMMAND.txt'
].map((name) => {
  const bytes = readFileSync(resolve(directory, name));
  return { path: name, byteCount: bytes.length, sha256: sha256(bytes) };
});
const manifest = {
  schema: 'shieldkit-labs/p2/direct-construction-cohort-v2/manifest/v1',
  manifestId: 'manifest:direct-construction-cohort-v2-v1',
  artifactId: artifact.artifactId,
  files: manifestFiles
};
const manifestBytes = canonicalJson(manifest);
writeFileSync(manifestPath, manifestBytes, 'utf8');

const sumFiles = [...manifestFiles.map(({ path }) => path), 'MANIFEST.json'];
const sums = `${sumFiles.map((name) => `${sha256(readFileSync(resolve(directory, name)))}  ${name}`).join('\n')}\n`;
writeFileSync(sumsPath, sums, 'utf8');

const parsed = JSON.parse(readFileSync(artifactPath, 'utf8'));
if (parsed.contentDigest !== artifact.contentDigest) throw new Error('artifact changed during serialization');
if (statSync(reportPath).size !== artifact.replayReportBinding.byteCount) throw new Error('replay report byte binding mismatch');
process.stdout.write(`WROTE ${artifactPath}\nWROTE ${reportPath}\nWROTE ${manifestPath}\nSHA256 artifact=${sha256(Buffer.from(artifactBytes, 'utf8'))}\n`);
