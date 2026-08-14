import { fail, requireExactKeys, requireIdentifier, requireUint32 } from './strict.mjs';

const CLOSED_PRIVATE_SEGMENT = /^[a-z0-9](?:[a-z0-9_-]|\.(?=[a-z0-9])){0,62}$/;
const CLOSED_ARTIFACT_SEGMENT = /^[A-Za-z0-9](?:[A-Za-z0-9_-]|\.(?=[A-Za-z0-9])){0,126}$/;

function requireSegment(value, label, grammar) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('%') || value.includes('\\') || value.includes('/') || !grammar.test(value)) {
    fail('K_LOCATOR', `${label} is not one closed normalized segment`);
  }
  return value;
}

export function requireClosedLocator(value, label) {
  return requireSegment(value, label, CLOSED_PRIVATE_SEGMENT);
}

export function requireArtifactLocator(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 191 || value.startsWith('/') || value.includes('\\') || value.includes('%')) {
    fail('K_LOCATOR', `${label} is outside the closed artifact grammar`);
  }
  const segments = value.split('/');
  if (segments.length === 0 || segments.some((segment) => segment.length === 0)) {
    fail('K_LOCATOR', `${label} has an empty artifact segment`);
  }
  for (const segment of segments) requireSegment(segment, `${label} segment`, CLOSED_ARTIFACT_SEGMENT);
  return value;
}

export function requireDisjointLocators(values) {
  if (!Array.isArray(values) || values.length === 0) fail('K_LOCATOR_SET', 'locator set is empty');
  const seen = new Set();
  for (const value of values) {
    requireClosedLocator(value, 'locator');
    if (seen.has(value)) fail('K_LOCATOR_SET', 'locator collision');
    seen.add(value);
  }
  return Object.freeze([...values]);
}

export function privateStorageContract() {
  return Object.freeze({
    executionAllowed: false,
    privateDirectoryMode: '0700',
    captureDirectoryMode: '0700',
    createdFileMode: '0600',
    openFlags: Object.freeze(['O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_CLOEXEC']),
    objectRequirements: Object.freeze({ kind: 'regular', linkCount: 1 }),
    terminalProtocol: Object.freeze({ primitive: 'renameat2', flag: 'RENAME_NOREPLACE', fallback: 'fail-closed' })
  });
}

export function exclusiveClaimStorageContract() {
  const storage = privateStorageContract();
  return Object.freeze({
    executionAllowed: false,
    primitive: 'openat',
    creation: Object.freeze({
      createdFileMode: storage.createdFileMode,
      openFlags: storage.openFlags,
      noFollow: true,
      noReplace: true
    }),
    terminal: storage.terminalProtocol
  });
}

export function requireStorageInspection(value) {
  requireExactKeys(value, ['locator', 'kind', 'linkCount', 'mode', 'noFollow', 'noReplace'], 'storage inspection');
  requireClosedLocator(value.locator, 'storage locator');
  if (value.kind !== 'regular' || value.linkCount !== 1 || value.mode !== '0600' || value.noFollow !== true || value.noReplace !== true) {
    fail('K_STORAGE', 'storage inspection violates the static contract');
  }
  return Object.freeze({ ...value });
}

export function requireClaimDescriptor(value) {
  requireExactKeys(value, ['claimKey', 'ordinal'], 'exclusive claim descriptor');
  requireIdentifier(value.claimKey, 'claim key');
  requireUint32(value.ordinal, 'claim ordinal');
  return Object.freeze({ ...value });
}
