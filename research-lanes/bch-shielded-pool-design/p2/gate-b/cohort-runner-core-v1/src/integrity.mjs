import { canonicalJson, domainHash, fail, requireExactKeys, requireRoot } from './strict.mjs';
import { requireArtifactLocator } from './file-contracts.mjs';

const OMITTED = new Set(['MANIFEST.json', 'SHA256SUMS']);
const RUNTIME_CLOSURE_LOCATOR = 'runtime-core.v1.json';
const BUILD_TIME_ONLY_LOCATORS = Object.freeze(['generate.mjs', 'src/integrity.mjs', 'validate.mjs']);

export function requireArtifactRecords(records) {
  if (!Array.isArray(records) || records.length === 0) fail('K_MANIFEST', 'artifact record set is empty');
  const names = new Set();
  let previousLocator = '';
  const copied = records.map((record) => {
    requireExactKeys(record, ['locator', 'sha256', 'bytes'], 'artifact record');
    requireArtifactLocator(record.locator, 'artifact locator');
    if (OMITTED.has(record.locator) || names.has(record.locator)) fail('K_MANIFEST', 'artifact closure has a self member or duplicate');
    if (previousLocator !== '' && record.locator <= previousLocator) fail('K_MANIFEST', 'artifact closure order is not strict');
    previousLocator = record.locator;
    names.add(record.locator);
    requireRoot(record.sha256, 'artifact SHA-256');
    if (!Number.isSafeInteger(record.bytes) || record.bytes < 0) fail('K_MANIFEST', 'artifact byte count is invalid');
    return Object.freeze({ ...record });
  });
  return Object.freeze(copied);
}

function runtimeCoreClassification(entries) {
  const closure = entries.find((entry) => entry.locator === RUNTIME_CLOSURE_LOCATOR);
  if (!closure) fail('K_MANIFEST', 'runtime closure manifest is absent');
  if (!entries.some((entry) => entry.locator === 'src/contracts.mjs')) fail('K_MANIFEST', 'runtime entrypoint is absent');
  for (const locator of BUILD_TIME_ONLY_LOCATORS) {
    if (!entries.some((entry) => entry.locator === locator)) fail('K_MANIFEST', 'declared build tooling is absent');
  }
  return Object.freeze({
    closureLocator: RUNTIME_CLOSURE_LOCATOR,
    closureSha256: closure.sha256,
    runtimeEntrypoint: 'src/contracts.mjs',
    buildTimeOnlyLocators: BUILD_TIME_ONLY_LOCATORS
  });
}

export function deriveManifest(records) {
  const entries = requireArtifactRecords(records);
  const entriesRoot = domainHash('K/ENTRIES', entries);
  const runtimeCore = runtimeCoreClassification(entries);
  const body = Object.freeze({
    format: 'K/manifest/1',
    executionAllowed: false,
    runtimeBinding: null,
    policy: null,
    authorization: null,
    claim: null,
    run: null,
    evidence: null,
    metrics: null,
    ranking: null,
    selection: null,
    journal: null,
    terminal: null,
    capture: null,
    concreteLocations: null,
    runtimeCore,
    entryCount: entries.length,
    entries,
    entriesRoot
  });
  const manifestRoot = domainHash('K/MANIFEST', body);
  const packageRoot = domainHash('K/PACKAGE', { manifestRoot, entriesRoot, executionAllowed: false });
  return Object.freeze({ ...body, manifestRoot, packageRoot });
}

export function serializeManifest(manifest) {
  return `${canonicalJson(manifest)}\n`;
}

export function verifyManifest(value, records) {
  requireExactKeys(value, [
    'format', 'executionAllowed', 'runtimeBinding', 'policy', 'authorization', 'claim', 'run', 'evidence',
    'metrics', 'ranking', 'selection', 'journal', 'terminal', 'capture', 'concreteLocations', 'runtimeCore', 'entryCount', 'entries',
    'entriesRoot', 'manifestRoot', 'packageRoot'
  ], 'manifest');
  const derived = deriveManifest(records);
  if (canonicalJson(value) !== canonicalJson(derived)) fail('K_MANIFEST', 'manifest does not bind the closed artifact set');
  return true;
}
