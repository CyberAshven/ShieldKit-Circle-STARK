#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { rawReplayReportFor, verifyCertificateSet } from './direct-construction-cohort-v2.mjs';

const [artifactPath, ...extra] = process.argv.slice(2);
if (!artifactPath || extra.length !== 0) {
  process.stderr.write('usage: node repository-replay.mjs <certificate-set-path>\n');
  process.exitCode = 2;
} else {
  try {
    const artifact = JSON.parse(readFileSync(resolve(artifactPath), 'utf8'));
    verifyCertificateSet(artifact);
    const report = rawReplayReportFor(artifact);
    if (artifact.replayReportBinding.sha256 !== createHash('sha256').update(report).digest('hex')) throw new Error('replay report binding mismatch');
    process.stdout.write(report);
  } catch (error) {
    process.stderr.write(`FAIL ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
