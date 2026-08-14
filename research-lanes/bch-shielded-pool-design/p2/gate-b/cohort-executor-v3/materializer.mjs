/* Durable staging/materialization only. This file has no child-process import. */
import fs from 'node:fs';
import path from 'node:path';
import { CLAIM_REL, OUTPUT_REL, SUCCESS_REL } from './authority.mjs';
import { successPayloadPaths, validateCompleteSuccessContainer, validateStagedSuccessContainerForCommit } from './evidence-validator.mjs';
import { assertOwnedDirectoryNoFollow, createScratchDirectory, createScratchSubdirectory, ensureExactOwnedEmptyRunBase, fsyncDirectory, requirePinnedNoReplaceDirectoryCommit, testOnlyNoReplaceDirectoryCommit, writeExclusiveFileNoFollow } from './durable-io.mjs';

const assert = (condition, message) => { if (!condition) throw new Error(`cohort-executor-v3 materializer: ${message}`); };
const workspace = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../../../..');
const exactOutput = path.resolve(workspace, OUTPUT_REL);
const exactScratch = `${exactOutput}.scratch`;
const exactScratchSuccess = path.join(exactScratch, 'success');
const successPayloads = () => successPayloadPaths().map(item => item.path);
const containerFiles = () => ['evidence-root.v3.json', 'evidence-manifest.v3.json', ...successPayloads()];
const asMap = payloads => payloads instanceof Map ? payloads : new Map(Object.entries(payloads ?? {}));

/** Create the fixed same-device, owner-only scratch root after the claim exists. */
export function createExactAttemptScratch() {
  ensureExactOwnedEmptyRunBase(path.dirname(exactOutput));
  assert(!fs.existsSync(exactOutput), 'output root already exists');
  return createScratchDirectory(exactScratch, path.dirname(exactOutput));
}

function ensureScratchSuccess(scratchRoot) {
  assert(scratchRoot === exactScratch && fs.existsSync(scratchRoot), 'exact scratch root required');
  return createScratchSubdirectory(exactScratchSuccess);
}

/**
 * Write the exact 26 success payloads. Auth and claim are copied from the
 * descriptor-read buffers; the remaining 24 bytes must be supplied by the
 * runner’s independently-derived evidence builder (including manifest/root).
 * No expected value is ever
 * substituted for an observed payload here.
 */
export function materializeExactSuccessScratch({ scratchRoot = exactScratch, payloadBytes, authorizationBytes, claimBytes }) {
  assert(Buffer.isBuffer(authorizationBytes) && Buffer.isBuffer(claimBytes), 'descriptor-read authorization and claim bytes required');
  const entries = asMap(payloadBytes); const required = containerFiles(); const payloads = successPayloads();
  const supplied = [...entries.keys()].sort(); const permitted = required.filter(item => item !== 'authorization.json' && item !== 'execution-claim.json').sort();
  assert(JSON.stringify(supplied) === JSON.stringify(permitted), 'exact 26 non-transport container bytes required');
  for (const [relative, body] of entries) assert(required.includes(relative) && Buffer.isBuffer(body), `invalid payload ${relative}`);
  const successRoot = ensureScratchSuccess(scratchRoot);
  const all = new Map(entries); all.set('authorization.json', authorizationBytes); all.set('execution-claim.json', claimBytes);
  const directories = new Set();
  for (const relative of required) {
    let cursor = successRoot;
    for (const part of relative.split('/').slice(0, -1)) { cursor = path.join(cursor, part); directories.add(cursor); }
  }
  for (const directory of [...directories].sort((left, right) => left.split(path.sep).length - right.split(path.sep).length || left.localeCompare(right))) {
    if (fs.existsSync(directory)) assertOwnedDirectoryNoFollow(directory); else createScratchSubdirectory(directory);
  }
  for (const relative of required) {
    const target = path.join(successRoot, relative); writeExclusiveFileNoFollow(target, all.get(relative));
  }
  for (const directory of [...directories, successRoot].sort((left, right) => right.split(path.sep).length - left.split(path.sep).length || right.localeCompare(left))) fsyncDirectory(directory);
  return Object.freeze({ scratchRoot, successRoot, payloads: payloads.length, containerFiles: required.length, authorizationByteLength: authorizationBytes.length, claimByteLength: claimBytes.length });
}

/** Full semantic success validation on the exact fixed scratch path. */
export function validateScratchBeforeAtomicCommit({ scratchRoot = exactScratch, authorizationBytes, claimBytes }) {
  assert(scratchRoot === exactScratch && fs.existsSync(exactScratchSuccess), 'fixed sibling scratch layout');
  return validateStagedSuccessContainerForCommit({ successRoot: exactScratchSuccess, authorizationBytes, claimBytes });
}

/**
 * Commit is intentionally gated on a real Linux no-replace primitive. Native
 * Node rename is not used because it can replace an empty target directory.
 */
export function commitValidatedAttemptNoReplace({ scratchRoot = exactScratch }) {
  assert(scratchRoot === exactScratch && fs.existsSync(exactScratchSuccess), 'validated exact scratch required');
  return requirePinnedNoReplaceDirectoryCommit({ scratchRoot, destinationRoot: exactOutput });
}
/** Test-only seam; production execution never accepts an arbitrary callback. */
export function testOnlyCommitValidatedAttemptNoReplace({ scratchRoot, destinationRoot, nativeCommit }) { return testOnlyNoReplaceDirectoryCommit({ scratchRoot, destinationRoot, nativeCommit }); }

/** Final canonical-path validation must run after a successful native commit. */
export function revalidateCommittedSuccess() { return validateCompleteSuccessContainer(); }

export const MATERIALIZATION_BOUNDARY = Object.freeze({ outputRoot: OUTPUT_REL, successRoot: SUCCESS_REL, claimPath: CLAIM_REL, payloads: 26, containerFiles: 28, noReplaceCommit: 'requires-pinned-native-renameat2-or-equivalent', noPartialReuse: true });
