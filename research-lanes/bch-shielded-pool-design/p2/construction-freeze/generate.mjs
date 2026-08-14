#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { canonicalJson, generateConstructionFreezeBundle, sha256 } from './construction-freeze.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const artifactPath = resolve(directory, 'construction-freeze.v1.json');
const transcriptPath = resolve(directory, 'construction-freeze.normalized-transcript.v1.json');
const sumsPath = resolve(directory, 'SHA256SUMS');

const { summary, transcript, transcriptBytes } = generateConstructionFreezeBundle();
const summaryBytes = canonicalJson(summary);
writeFileSync(artifactPath, summaryBytes, 'utf8');
writeFileSync(transcriptPath, transcriptBytes, 'utf8');
writeFileSync(sumsPath, `${sha256(Buffer.from(summaryBytes, 'utf8'))}  construction-freeze.v1.json\n${sha256(Buffer.from(transcriptBytes, 'utf8'))}  construction-freeze.normalized-transcript.v1.json\n`, 'utf8');

const parsedSummary = JSON.parse(readFileSync(artifactPath, 'utf8'));
const parsedTranscript = JSON.parse(readFileSync(transcriptPath, 'utf8'));
if (parsedSummary.contentDigest !== summary.contentDigest) throw new Error('generated summary changed during serialization');
if (parsedTranscript.contentDigest !== transcript.contentDigest) throw new Error('generated transcript changed during serialization');
process.stdout.write(`WROTE ${artifactPath}\nWROTE ${transcriptPath}\nSHA256 summary=${sha256(Buffer.from(summaryBytes, 'utf8'))} transcript=${sha256(Buffer.from(transcriptBytes, 'utf8'))}\n`);
