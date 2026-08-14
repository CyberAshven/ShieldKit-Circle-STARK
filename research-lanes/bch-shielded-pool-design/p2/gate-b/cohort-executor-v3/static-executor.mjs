import path from 'node:path';
import { CLAIM_REL, FAILURE_REL, OUTPUT_REL, SUCCESS_REL, validateSealedV3Authority } from './authority.mjs';

const assert = (condition, message) => { if (!condition) throw new Error(`cohort-executor-v3 static plan: ${message}`); };

/**
 * This is a static commit protocol, not an execution implementation. A later
 * explicitly authorized process runner must satisfy this plan before it can
 * write any attempt bytes.
 */
export function buildAtomicAttemptPlan(authorization) {
  assert(authorization?.attempt?.outputRoot === OUTPUT_REL && authorization.attempt.successRoot === SUCCESS_REL && authorization.attempt.failureRoot === FAILURE_REL && authorization.attempt.claimPath === CLAIM_REL, 'fixed output roots');
  return Object.freeze({
    attemptIndex: 1,
    scratchRoot: `${OUTPUT_REL}.scratch`,
    outputRoot: OUTPUT_REL,
    terminalChildren: Object.freeze(['success', 'failure']),
    successPayloadCount: 26,
    successContainerFileCount: 28,
    claim: Object.freeze({ path: CLAIM_REL, creation: 'exclusive-no-follow-mode-0600-fsync-file-and-parent-before-any-engine', binds: Object.freeze(['authorization-raw-and-content', 'contract-raw-and-content', 'attempt-index', 'output-root', 'runtime', 'nonreuse-policy']) }),
    atomicity: Object.freeze(['create-empty-sibling-scratch', 'capture-only-under-scratch', 'full-semantic-validation-before-commit', 'exactly-one-terminal-child', 'same-filesystem-no-replace-whole-directory-commit', 'revalidate-final-container']),
    partialReuse: false,
    ranking: null,
    selection: null,
  });
}
/** Read-only future-entry preflight; no process runner is imported by this module. */
export function validateFutureFailureOnly({ authorizationPath, failureRoot }) {
  const checked = validateSealedV3Authority({ authorizationPath, failureRoot });
  assert(path.resolve(failureRoot).endsWith(path.join('attempt-001', 'failure')), 'failure root suffix');
  return Object.freeze({ status: 'PASS', plan: buildAtomicAttemptPlan({ attempt: { outputRoot: OUTPUT_REL, successRoot: SUCCESS_REL, failureRoot: FAILURE_REL, claimPath: CLAIM_REL } }), authorizationDigest: checked.authorizationDigest });
}
