#!/usr/bin/env node
import { validateStaticExecutor } from './authority.mjs';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--check') console.log(JSON.stringify({ ...validateStaticExecutor(), packageScope: 'full-hardened-evidence-validator-static', fullHardenedEvidenceValidator: true, durableWriter: false, captureLayer: false, processRunner: false, failurePublisher: false, authorization: false, execution: false }, null, 2));
else if (args.length === 1 && args[0] === '--execute') {
  /* The execute-only module is intentionally dynamic: default/import/check
     reach only the pure static validator closure. Its first operation is an
     exact descriptor read of the absent external authorization transport. */
  const { executeAuthorizedAttempt } = await import('./runner-open.mjs');
  await executeAuthorizedAttempt();
}
else throw new Error('cohort-executor-v3 accepts only --check');
