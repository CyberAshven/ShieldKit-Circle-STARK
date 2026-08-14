import { createHash } from 'node:crypto';

export const SCHEMA_VERSION = 'live-executor-static-v1';
export const ENDPOINTS = Object.freeze([
  Object.freeze({ ordinal: 0, id: 'native-primary', label: 'Native primary', role: 'primary' }),
  Object.freeze({ ordinal: 1, id: 'libauth-primary', label: 'Libauth primary', role: 'primary' }),
  Object.freeze({ ordinal: 2, id: 'bchn-primary', label: 'BCHN primary', role: 'primary' }),
  Object.freeze({ ordinal: 3, id: 'lean-primary', label: 'Lean primary', role: 'primary' }),
  Object.freeze({ ordinal: 4, id: 'lean-secondary', label: 'Lean secondary', role: 'secondary' }),
]);
// Snapshot-v1 closes all catalog and source descriptors before this static
// boundary. The only retained recovery projection is the runtime executable;
// it is descriptive only until a future private snapshot adapter exists.
export const RUNTIME_EXECUTABLE = Object.freeze({
  id: '/proc/self/exe',
  role: 'runtime-executable',
});
export const EXTERNAL_B_JOIN_STATUS = 'PENDING_NONAUTHORIZING';
export const EXTERNAL_A0_BINDING_VERSION = 'external-a0-digest-binding-v1';
export const JOURNAL_EVENTS = Object.freeze([
  'endpoint-input-durable',
  'endpoint-started',
  'stdout-durable',
  'stderr-durable',
  'endpoint-close-observed',
  'endpoint-sealed',
]);
export const GENESIS_DIGEST = 'GENESIS';

const DIGEST = /^[a-f0-9]{64}$/;
const RELATIVE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]*$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MODE = /^[0-7]{3,4}$/;

export function invariant(condition, message) {
  if (!condition) throw new TypeError(message);
}

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    invariant(Number.isFinite(value), 'canonical JSON forbids non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  invariant(isPlainObject(value), 'canonical JSON accepts plain objects only');
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function domainDigest(domain, value) {
  invariant(typeof domain === 'string' && domain.length > 0, 'digest domain is required');
  return createHash('sha256').update(`ShieldKit/live-executor-static/v1/${domain}\u0000${canonicalJson(value)}`, 'utf8').digest('hex');
}

export function identity(kind, value) {
  return domainDigest(`identity/${kind}`, value);
}

export function assertExactKeys(value, keys, label) {
  invariant(isPlainObject(value), `${label} must be a plain object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  invariant(actual.length === expected.length && actual.every((key, index) => key === expected[index]), `${label} has unexpected keys`);
}

export function assertDigest(value, label) {
  invariant(typeof value === 'string' && DIGEST.test(value), `${label} must be a lowercase SHA-256 digest`);
}

export function assertRelativePath(value, label) {
  invariant(typeof value === 'string' && RELATIVE_PATH.test(value), `${label} must be a normalized relative path`);
}

function assertStatScalars(stat, numericKeys, label) {
  for (const key of numericKeys) {
    invariant(typeof stat[key] === 'string' && DECIMAL.test(stat[key]), `${label}.${key} must be an unsigned decimal string`);
  }
  invariant(typeof stat.mode === 'string' && MODE.test(stat.mode), `${label}.mode must be an octal mode string`);
  invariant(stat.nlink === '1', `${label}.nlink must be the decimal string 1`);
}

export function assertSnapshotStat(stat, label = 'snapshot stat') {
  assertExactKeys(stat, ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size'], label);
  assertStatScalars(stat, ['dev', 'ino', 'uid', 'gid', 'nlink', 'size'], label);
}

export function assertStreamStat(stat, label = 'stream stat') {
  assertExactKeys(stat, ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs'], label);
  assertStatScalars(stat, ['dev', 'ino', 'uid', 'gid', 'nlink', 'size', 'mtimeNs'], label);
}

export function assertStdinBinding(binding, label = 'stdin binding') {
  assertExactKeys(binding, ['ordinal', 'id', 'role', 'codec', 'readyRows', 'sha256', 'byteLength'], label);
  const endpoint = ENDPOINTS[binding.ordinal];
  invariant(endpoint && binding.id === endpoint.id && binding.role === endpoint.role, `${label} endpoint identity mismatch`);
  invariant(typeof binding.codec === 'string' && binding.codec.length > 0, `${label}.codec is required`);
  invariant(binding.readyRows === 4608, `${label}.readyRows must be 4608`);
  assertDigest(binding.sha256, `${label}.sha256`);
  invariant(Number.isSafeInteger(binding.byteLength) && binding.byteLength >= 0, `${label}.byteLength must be a non-negative safe integer`);
}

export function stdinBindingDigest(binding) {
  assertStdinBinding(binding);
  return domainDigest('stdin-binding', binding);
}

export function stdinBindingRootDigest(bindings) {
  invariant(Array.isArray(bindings) && bindings.length === ENDPOINTS.length, 'stdin binding root requires exactly five bindings');
  bindings.forEach((binding, ordinal) => {
    assertStdinBinding(binding, `stdin root binding ${ordinal}`);
    invariant(binding.ordinal === ordinal, 'stdin binding root order mismatch');
  });
  return domainDigest('stdin-binding-root', bindings);
}

export function endpointScheduleDigest(endpoints) {
  assertEndpointSchedule(endpoints);
  return domainDigest('endpoint-schedule', endpoints);
}

function assertNoRuntimeAuthority(value, label = 'static policy') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRuntimeAuthority(item, `${label}[${index}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, nested] of Object.entries(value)) {
    invariant(!/(fd|snapshot|runtime|descriptor)/i.test(key), `${label} may not bind dynamic ${key}`);
    assertNoRuntimeAuthority(nested, `${label}.${key}`);
  }
}

function assertEndpointSchedule(endpoints) {
  invariant(Array.isArray(endpoints) && endpoints.length === ENDPOINTS.length, 'policy endpoint schedule must contain exactly five endpoints');
  endpoints.forEach((entry, ordinal) => {
    assertExactKeys(entry, ['ordinal', 'id', 'role'], `policy endpoint ${ordinal}`);
    const expected = ENDPOINTS[ordinal];
    invariant(entry.ordinal === expected.ordinal && entry.id === expected.id && entry.role === expected.role, 'policy endpoint schedule mismatch');
  });
}

export function assertLivePolicyAuthorization(policy) {
  assertExactKeys(policy, [
    'schemaVersion', 'a0Digest', 'packageManifestDigest', 'packageSha256SumsDigest',
    'endpoints', 'launchProjection', 'limits', 'paths', 'qualification', 'executionAllowed',
  ], 'live policy authorization');
  invariant(policy.schemaVersion === SCHEMA_VERSION, 'unsupported policy schema version');
  assertDigest(policy.a0Digest, 'policy.a0Digest');
  assertDigest(policy.packageManifestDigest, 'policy.packageManifestDigest');
  assertDigest(policy.packageSha256SumsDigest, 'policy.packageSha256SumsDigest');
  assertEndpointSchedule(policy.endpoints);
  assertExactKeys(policy.launchProjection, ['argv', 'cwd', 'environment'], 'policy.launchProjection');
  invariant(Array.isArray(policy.launchProjection.argv) && policy.launchProjection.argv.length > 0 && policy.launchProjection.argv.every((item) => typeof item === 'string'), 'policy launch argv is invalid');
  assertRelativePath(policy.launchProjection.cwd, 'policy launch cwd');
  invariant(isPlainObject(policy.launchProjection.environment), 'policy launch environment must be an object');
  assertExactKeys(policy.limits, ['maxEndpointCount', 'maxReadyRows'], 'policy limits');
  invariant(policy.limits.maxEndpointCount === 5 && policy.limits.maxReadyRows === 4608, 'policy limits mismatch');
  assertExactKeys(policy.paths, ['claimPath', 'journalRoot', 'outputRoot', 'scratchRoot'], 'policy paths');
  Object.entries(policy.paths).forEach(([key, value]) => assertRelativePath(value, `policy paths.${key}`));
  assertExactKeys(policy.qualification, ['containmentRequired', 'failClosed', 'journalRequired', 'observationRequired'], 'policy qualification');
  Object.values(policy.qualification).forEach((value) => invariant(value === true, 'policy qualification must fail closed'));
  invariant(policy.executionAllowed === false, 'static package cannot authorize execution');
  assertNoRuntimeAuthority(policy);
  return policy;
}

function runtimeExecutableIdentityProjection(projection) {
  return {
    id: projection.id,
    role: projection.role,
    rawSha256: projection.rawSha256,
    byteLength: projection.byteLength,
    stat: { ...projection.stat },
  };
}

export function assertRuntimeExecutableProjection(projection, label = 'runtime executable projection') {
  assertExactKeys(projection, ['id', 'role', 'rawSha256', 'byteLength', 'executableIdentityDigest', 'stat'], label);
  invariant(projection.id === RUNTIME_EXECUTABLE.id && projection.role === RUNTIME_EXECUTABLE.role, `${label} must be the exact retained runtime executable`);
  assertDigest(projection.rawSha256, `${label}.rawSha256`);
  invariant(Number.isSafeInteger(projection.byteLength) && projection.byteLength >= 0, `${label}.byteLength must be a non-negative safe integer`);
  assertDigest(projection.executableIdentityDigest, `${label}.executableIdentityDigest`);
  assertSnapshotStat(projection.stat, `${label}.stat`);
  invariant(projection.stat.size === String(projection.byteLength), `${label}.stat.size must exactly equal byteLength`);
  invariant(
    projection.executableIdentityDigest === domainDigest('runtime-executable-identity', runtimeExecutableIdentityProjection(projection)),
    `${label}.executableIdentityDigest mismatch`,
  );
  return projection;
}

export function recoveryStableProjection(binding) {
  return {
    schemaVersion: binding.schemaVersion,
    a0Digest: binding.a0Digest,
    a1Digest: binding.a1Digest,
    snapshotDigest: binding.snapshotDigest,
    valuesRootDigest: binding.valuesRootDigest,
    catalogBindingDigest: binding.catalogBindingDigest,
    runtimeExecutableProjection: {
      ...binding.runtimeExecutableProjection,
      stat: { ...binding.runtimeExecutableProjection.stat },
    },
    snapshotAdapterBranded: binding.snapshotAdapterBranded,
    externalBJoinStatus: binding.externalBJoinStatus,
    stdinBindings: binding.stdinBindings.map((entry) => ({ ...entry })),
    stdinBindingRootDigest: binding.stdinBindingRootDigest,
  };
}

export function assertSnapshotBinding(binding) {
  assertExactKeys(binding, [
    'schemaVersion', 'a0Digest', 'a1Digest', 'snapshotDigest', 'valuesRootDigest', 'catalogBindingDigest',
    'runtimeExecutableProjection', 'snapshotAdapterBranded', 'externalBJoinStatus',
    'stdinBindings', 'stdinBindingRootDigest', 'recoveryStableDigest',
  ], 'snapshot binding');
  invariant(binding.schemaVersion === SCHEMA_VERSION, 'unsupported snapshot schema version');
  for (const key of ['a0Digest', 'a1Digest', 'snapshotDigest', 'valuesRootDigest', 'catalogBindingDigest', 'stdinBindingRootDigest', 'recoveryStableDigest']) assertDigest(binding[key], `binding.${key}`);
  assertRuntimeExecutableProjection(binding.runtimeExecutableProjection);
  invariant(binding.snapshotAdapterBranded === false, 'static v1 has no branded snapshot adapter');
  invariant(binding.externalBJoinStatus === EXTERNAL_B_JOIN_STATUS, 'external B join must remain pending and non-authorizing');
  invariant(Array.isArray(binding.stdinBindings) && binding.stdinBindings.length === 5, 'snapshot binding needs five stdin bindings');
  binding.stdinBindings.forEach((entry, ordinal) => {
    assertStdinBinding(entry, `stdin binding ${ordinal}`);
    invariant(entry.ordinal === ordinal, 'stdin bindings must be in endpoint order');
  });
  invariant(binding.stdinBindingRootDigest === stdinBindingRootDigest(binding.stdinBindings), 'snapshot stdin-binding root mismatch');
  invariant(binding.recoveryStableDigest === domainDigest('snapshot-stable-projection', recoveryStableProjection(binding)), 'snapshot recovery-stable digest mismatch');
  return binding;
}

export function deriveRetainedDescriptorInventory(binding) {
  assertSnapshotBinding(binding);
  return [{
    id: RUNTIME_EXECUTABLE.id,
    role: RUNTIME_EXECUTABLE.role,
    projectionDigest: domainDigest('runtime-executable-recovery-projection', binding.runtimeExecutableProjection),
  }];
}

export function retainedDescriptorInventoryDigest(inventory) {
  invariant(Array.isArray(inventory) && inventory.length === 1, 'retained descriptor inventory must contain only the retained runtime executable');
  inventory.forEach((entry, index) => {
    assertExactKeys(entry, ['id', 'role', 'projectionDigest'], `retained descriptor ${index}`);
    invariant(entry.id === RUNTIME_EXECUTABLE.id && entry.role === RUNTIME_EXECUTABLE.role, 'retained descriptor inventory must contain only the exact runtime executable');
    assertDigest(entry.projectionDigest, 'retained descriptor projectionDigest');
  });
  return domainDigest('retained-descriptor-inventory', inventory);
}

export function claimJoinSeedProjection(claim) {
  return {
    schemaVersion: claim.schemaVersion,
    a0Digest: claim.a0Digest,
    a1Digest: claim.a1Digest,
    bDigest: claim.bDigest,
    outputRoot: claim.outputRoot,
    claimPath: claim.claimPath,
    claimMode: claim.claimMode,
    claimDisposition: claim.claimDisposition,
    nonreuse: claim.nonreuse,
    retainedDescriptorInventoryDigest: claim.retainedDescriptorInventoryDigest,
  };
}

export function claimJoinSeedDigest(claim) {
  return domainDigest('approved-claim-join-seed', claimJoinSeedProjection(claim));
}

export function assertLiveClaim(claim, policy, binding) {
  assertExactKeys(claim, [
    'schemaVersion', 'a0Digest', 'a1Digest', 'bDigest', 'outputRoot', 'claimPath', 'claimMode',
    'claimDisposition', 'nonreuse', 'retainedDescriptorInventory', 'retainedDescriptorInventoryDigest',
    'joinSeedDigest', 'writerImplemented',
  ], 'live claim');
  invariant(claim.schemaVersion === SCHEMA_VERSION, 'unsupported claim schema version');
  for (const key of ['a0Digest', 'a1Digest', 'bDigest', 'retainedDescriptorInventoryDigest', 'joinSeedDigest']) assertDigest(claim[key], `claim.${key}`);
  assertRelativePath(claim.outputRoot, 'claim.outputRoot');
  assertRelativePath(claim.claimPath, 'claim.claimPath');
  invariant(claim.claimMode === '0600', 'claim mode must be 0600');
  invariant(claim.claimDisposition === 'O_EXCL', 'claim disposition must be O_EXCL');
  invariant(claim.nonreuse === true, 'claim must be non-reusable');
  invariant(claim.retainedDescriptorInventoryDigest === retainedDescriptorInventoryDigest(claim.retainedDescriptorInventory), 'claim retained descriptor inventory digest mismatch');
  invariant(claim.joinSeedDigest === claimJoinSeedDigest(claim), 'claim join seed must bind exact approved C fields');
  invariant(claim.writerImplemented === false, 'this package must not implement a claim writer');
  if (policy !== undefined || binding !== undefined) {
    assertLivePolicyAuthorization(policy);
    assertSnapshotBinding(binding);
    invariant(claim.outputRoot === policy.paths.outputRoot && claim.claimPath === policy.paths.claimPath, 'C outputRoot and claimPath must exactly equal A1 paths');
    const expectedInventory = deriveRetainedDescriptorInventory(binding);
    invariant(canonicalJson(claim.retainedDescriptorInventory) === canonicalJson(expectedInventory), 'C retained descriptor inventory must equal deterministic B-derived inventory');
  }
  return claim;
}

export function assertAttemptJoin(join) {
  assertExactKeys(join, [
    'schemaVersion', 'a0Digest', 'a1Digest', 'bDigest', 'cDigest', 'joinSeedDigest',
    'packageManifestDigest', 'packageSha256SumsDigest', 'launchProjectionDigest',
    'descriptorInventoryDigest', 'stdinBindingRootDigest', 'endpointScheduleDigest',
    'evidenceOnly', 'grantsAuthority',
  ], 'attempt join');
  invariant(join.schemaVersion === SCHEMA_VERSION, 'unsupported attempt join schema version');
  for (const key of ['a0Digest', 'a1Digest', 'bDigest', 'cDigest', 'joinSeedDigest', 'packageManifestDigest', 'packageSha256SumsDigest', 'launchProjectionDigest', 'descriptorInventoryDigest', 'stdinBindingRootDigest', 'endpointScheduleDigest']) assertDigest(join[key], `join.${key}`);
  invariant(join.evidenceOnly === true && join.grantsAuthority === false, 'attempt join must be evidence-only and non-authorizing');
  return join;
}

export function assertExternalA0Binding(a0) {
  assertExactKeys(a0, ['schemaVersion', 'externalAuthorizationDigest'], 'external A0 digest binding');
  invariant(Object.isFrozen(a0), 'external A0 digest binding must be frozen');
  invariant(a0.schemaVersion === EXTERNAL_A0_BINDING_VERSION, 'unsupported external A0 digest binding version');
  assertDigest(a0.externalAuthorizationDigest, 'external A0 digest binding digest');
  return a0;
}

export function externalA0BindingDigest(a0) {
  assertExternalA0Binding(a0);
  return domainDigest('external-a0-digest-binding', a0);
}

export function assertAuthorityDag(a0, policy, binding, claim, join) {
  assertExternalA0Binding(a0);
  assertLivePolicyAuthorization(policy);
  assertSnapshotBinding(binding);
  assertLiveClaim(claim, policy, binding);
  assertAttemptJoin(join);
  const a0Digest = externalA0BindingDigest(a0);
  const a1Digest = identity('a1', policy);
  const bDigest = identity('b', binding);
  const cDigest = identity('c', claim);
  invariant(policy.a0Digest === a0Digest, 'A1 must bind the exact A0 identity');
  invariant(binding.a0Digest === a0Digest && binding.a1Digest === a1Digest, 'B must bind exact A0 and A1 identities');
  invariant(claim.a0Digest === a0Digest && claim.a1Digest === a1Digest && claim.bDigest === bDigest, 'C must bind exact A0/A1/B identities');
  invariant(join.a0Digest === a0Digest && join.a1Digest === a1Digest && join.bDigest === bDigest && join.cDigest === cDigest, 'J must bind exact A0/A1/B/C identities');
  invariant(join.joinSeedDigest === claim.joinSeedDigest, 'J join seed must exactly equal the approved C seed');
  invariant(join.packageManifestDigest === policy.packageManifestDigest && join.packageSha256SumsDigest === policy.packageSha256SumsDigest, 'J package roots must equal A1 package roots');
  invariant(join.launchProjectionDigest === domainDigest('launch-projection', policy.launchProjection), 'J launch projection mismatch');
  invariant(join.descriptorInventoryDigest === claim.retainedDescriptorInventoryDigest, 'J descriptor inventory digest mismatch');
  invariant(join.stdinBindingRootDigest === binding.stdinBindingRootDigest, 'J must bind exact B stdin-binding root');
  invariant(join.endpointScheduleDigest === endpointScheduleDigest(policy.endpoints), 'J must bind exact A1 endpoint schedule');
  return Object.freeze({ a0Digest, a1Digest, bDigest, cDigest, jDigest: identity('j', join) });
}

export function assertStreamBinding(binding, label = 'stream binding') {
  assertExactKeys(binding, ['stream', 'relativePath', 'sha256', 'byteLength', 'stat', 'fsynced'], label);
  invariant(binding.stream === 'stdout' || binding.stream === 'stderr', `${label}.stream is invalid`);
  assertRelativePath(binding.relativePath, `${label}.relativePath`);
  assertDigest(binding.sha256, `${label}.sha256`);
  invariant(Number.isSafeInteger(binding.byteLength) && binding.byteLength >= 0, `${label}.byteLength is invalid`);
  assertStreamStat(binding.stat, `${label}.stat`);
  invariant(binding.stat.size === String(binding.byteLength), `${label}.stat.size must exactly equal byteLength`);
  invariant(binding.fsynced === true, `${label}.fsynced must be true`);
}

function journalCore(entry) {
  const { entryDigest, ...core } = entry;
  return core;
}

export function journalEntryDigest(entry) {
  return domainDigest('journal-entry', journalCore(entry));
}

export function assertJournalEntry(entry) {
  assertExactKeys(entry, [
    'schemaVersion', 'jDigest', 'sequence', 'monotonicTimeNs', 'previousDigest', 'endpointOrdinal', 'endpointId',
    'event', 'stdinBindingDigest', 'streamBindings', 'entryDigest',
  ], 'journal entry');
  invariant(entry.schemaVersion === SCHEMA_VERSION, 'unsupported journal entry schema version');
  assertDigest(entry.jDigest, 'journal entry J digest');
  invariant(Number.isSafeInteger(entry.sequence) && entry.sequence >= 0, 'journal sequence is invalid');
  invariant(typeof entry.monotonicTimeNs === 'string' && DECIMAL.test(entry.monotonicTimeNs), 'journal monotonic time is invalid');
  invariant(entry.previousDigest === GENESIS_DIGEST || DIGEST.test(entry.previousDigest), 'journal previous digest is invalid');
  const endpoint = ENDPOINTS[entry.endpointOrdinal];
  invariant(endpoint && entry.endpointId === endpoint.id, 'journal endpoint identity mismatch');
  invariant(JOURNAL_EVENTS.includes(entry.event), 'journal event is invalid');
  invariant(entry.stdinBindingDigest === null || DIGEST.test(entry.stdinBindingDigest), 'journal stdin binding digest is invalid');
  invariant(Array.isArray(entry.streamBindings), 'journal stream bindings must be an array');
  entry.streamBindings.forEach((stream, index) => assertStreamBinding(stream, `journal stream ${index}`));
  assertDigest(entry.entryDigest, 'journal entry digest');
  invariant(entry.entryDigest === journalEntryDigest(entry), 'journal entry digest mismatch');
  return entry;
}

function assertEventPayload(entry, binding) {
  const expectedEvent = JOURNAL_EVENTS[entry.sequence % JOURNAL_EVENTS.length];
  invariant(entry.event === expectedEvent, 'journal event order mismatch');
  if (entry.event === 'endpoint-input-durable') {
    invariant(entry.stdinBindingDigest === stdinBindingDigest(binding.stdinBindings[entry.endpointOrdinal]), 'endpoint input must bind the exact B stdin record');
    invariant(entry.streamBindings.length === 0, 'input journal entry cannot carry streams');
  } else if (entry.event === 'stdout-durable' || entry.event === 'stderr-durable') {
    invariant(entry.stdinBindingDigest === null, 'stream journal entry cannot carry stdin binding');
    invariant(entry.streamBindings.length === 1 && entry.streamBindings[0].stream === entry.event.slice(0, -'-durable'.length), 'stream journal binding mismatch');
  } else {
    invariant(entry.stdinBindingDigest === null && entry.streamBindings.length === 0, 'journal event carries forbidden payload');
  }
}

function journalIndexCore(index) {
  const { indexDigest, ...core } = index;
  return core;
}

export function journalIndexDigest(index) {
  return domainDigest('journal-index', journalIndexCore(index));
}

export function journalEntriesDigest(entries) {
  return domainDigest('journal-entry-sequence', entries);
}

export function streamBindingsDigest(streamBindings) {
  return domainDigest('journal-stream-bindings', streamBindings);
}

export function assertJournal(entries, index, context) {
  assertExactKeys(context, ['binding', 'jDigest'], 'journal context');
  assertSnapshotBinding(context.binding);
  assertDigest(context.jDigest, 'journal context J digest');
  invariant(Array.isArray(entries) && entries.length <= 30, 'journal may have at most five endpoint traces');
  let previousDigest = GENESIS_DIGEST;
  let previousTime = -1n;
  const expectedStreams = [];
  const claimedArtifactPaths = new Set();
  entries.forEach((entry, sequence) => {
    assertJournalEntry(entry);
    invariant(entry.jDigest === context.jDigest, 'every journal entry must bind exact J identity');
    invariant(entry.sequence === sequence, 'journal sequence must be global and contiguous');
    invariant(entry.previousDigest === previousDigest, 'journal previous-digest chain mismatch');
    const monotonic = BigInt(entry.monotonicTimeNs);
    invariant(monotonic > previousTime, 'journal monotonic time must strictly increase');
    invariant(entry.endpointOrdinal === Math.floor(sequence / JOURNAL_EVENTS.length), 'journal endpoint order mismatch');
    assertEventPayload(entry, context.binding);
    for (const stream of entry.streamBindings) {
      invariant(!claimedArtifactPaths.has(stream.relativePath), 'global journal/index/stream path collision is forbidden');
      claimedArtifactPaths.add(stream.relativePath);
      expectedStreams.push({ endpointOrdinal: entry.endpointOrdinal, endpointId: entry.endpointId, ...stream });
    }
    previousDigest = entry.entryDigest;
    previousTime = monotonic;
  });
  assertExactKeys(index, ['schemaVersion', 'jDigest', 'firstSequence', 'nextSequence', 'headDigest', 'completedEndpointPrefix', 'entries', 'streamBindings', 'indexDigest'], 'journal index');
  invariant(index.schemaVersion === SCHEMA_VERSION, 'unsupported journal index schema version');
  invariant(index.jDigest === context.jDigest, 'journal index must bind exact J identity');
  invariant(index.firstSequence === 0 && index.nextSequence === entries.length, 'journal index sequence bounds mismatch');
  invariant(index.headDigest === previousDigest, 'journal index head mismatch');
  invariant(index.completedEndpointPrefix === Math.floor(entries.length / JOURNAL_EVENTS.length), 'completed endpoint prefix derives only from endpoint-sealed entries');
  invariant(Array.isArray(index.entries) && index.entries.length === entries.length, 'journal index entries mismatch');
  index.entries.forEach((entry, sequence) => {
    assertExactKeys(entry, ['sequence', 'entryDigest', 'relativePath', 'jDigest'], `journal index entry ${sequence}`);
    invariant(entry.sequence === sequence && entry.entryDigest === entries[sequence].entryDigest && entry.jDigest === context.jDigest, 'journal index entry binding mismatch');
    assertRelativePath(entry.relativePath, 'journal index entry path');
    invariant(!claimedArtifactPaths.has(entry.relativePath), 'global journal/index/stream path collision is forbidden');
    claimedArtifactPaths.add(entry.relativePath);
  });
  invariant(Array.isArray(index.streamBindings) && canonicalJson(index.streamBindings) === canonicalJson(expectedStreams), 'journal index stream binding mismatch');
  invariant(index.indexDigest === journalIndexDigest(index), 'journal index digest mismatch');
  return Object.freeze({ completedEndpointPrefix: index.completedEndpointPrefix, headDigest: index.headDigest, durablePrefixEntries: entries.length });
}

export function observationProjection(binding, entries, index) {
  assertSnapshotBinding(binding);
  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    jDigest: index.jDigest,
    journalIndexDigest: identity('journal-index', index),
    journalEntriesDigest: journalEntriesDigest(entries),
    journalHeadDigest: index.headDigest,
    stdinBindingRootDigest: binding.stdinBindingRootDigest,
    streamBindingsDigest: streamBindingsDigest(index.streamBindings),
    completedEndpointPrefix: index.completedEndpointPrefix,
    durablePrefixEntries: entries.length,
  });
}

export function assertObservationProjection(projection) {
  assertExactKeys(projection, [
    'schemaVersion', 'jDigest', 'journalIndexDigest', 'journalEntriesDigest', 'journalHeadDigest',
    'stdinBindingRootDigest', 'streamBindingsDigest', 'completedEndpointPrefix', 'durablePrefixEntries',
  ], 'sealed observation projection');
  invariant(projection.schemaVersion === SCHEMA_VERSION, 'unsupported observation projection schema version');
  for (const key of ['jDigest', 'journalIndexDigest', 'journalEntriesDigest', 'journalHeadDigest', 'stdinBindingRootDigest', 'streamBindingsDigest']) assertDigest(projection[key], `observation.${key}`);
  invariant(Number.isSafeInteger(projection.completedEndpointPrefix) && projection.completedEndpointPrefix >= 0 && projection.completedEndpointPrefix <= 5, 'observation completed prefix is invalid');
  invariant(Number.isSafeInteger(projection.durablePrefixEntries) && projection.durablePrefixEntries >= 0 && projection.durablePrefixEntries <= 30, 'observation durable prefix is invalid');
  return projection;
}

export function observationRequirementDigest(projection) {
  assertObservationProjection(projection);
  return domainDigest('structural-observation-requirement', projection);
}

export function assertSuccessTerminalStructure(entries, journal) {
  invariant(Array.isArray(entries) && entries.length === 30, 'success terminal requires exactly 30 durable journal entries');
  invariant(journal.durablePrefixEntries === 30 && journal.completedEndpointPrefix === 5 && entries.at(-1)?.event === 'endpoint-sealed', 'success terminal requires all five sealed endpoints');
  return Object.freeze({ durablePrefixEntries: 30, completedEndpointPrefix: 5 });
}

export function noObservationTerminalDigest(index, durablePrefixEntries, suffixSelection) {
  assertDigest(index.jDigest, 'no-observation terminal J digest');
  invariant(Number.isSafeInteger(durablePrefixEntries) && durablePrefixEntries >= 0 && durablePrefixEntries <= 30, 'no-observation durable prefix is invalid');
  invariant(suffixSelection === 'failure-after-prefix' || suffixSelection === 'recovery-after-prefix', 'no-observation suffix selection is invalid');
  return domainDigest('no-observation-terminal-prefix', {
    jDigest: index.jDigest,
    journalIndexDigest: identity('journal-index', index),
    durablePrefixEntries,
    suffixSelection,
  });
}

function assertLegacyLeaf(legacy) {
  invariant(isPlainObject(legacy), 'legacy container must be a plain object');
  const keys = Object.keys(legacy);
  invariant(keys.length === 1 && (keys[0] === 'success' || keys[0] === 'failure'), 'legacy container must contain exactly one success or failure leaf');
  invariant(isPlainObject(legacy[keys[0]]), 'legacy leaf must remain an object');
  return keys[0];
}

export function assertTerminalPublication(publication, context) {
  assertExactKeys(publication, [
    'schemaVersion', 'a0Digest', 'a1Digest', 'bDigest', 'cDigest', 'jDigest', 'journalIndexDigest',
    'observationRequirementDigest', 'publicationKind', 'durablePrefixEntries', 'suffixSelection', 'commitMode',
    'writerImplemented', 'legacy',
  ], 'terminal publication');
  assertExactKeys(context, ['a0', 'policy', 'binding', 'claim', 'join', 'entries', 'journalIndex'], 'terminal context');
  invariant(publication.schemaVersion === SCHEMA_VERSION, 'unsupported terminal schema version');
  const identities = assertAuthorityDag(context.a0, context.policy, context.binding, context.claim, context.join);
  for (const key of ['a0Digest', 'a1Digest', 'bDigest', 'cDigest', 'jDigest', 'journalIndexDigest', 'observationRequirementDigest']) assertDigest(publication[key], `terminal.${key}`);
  invariant(publication.a0Digest === identities.a0Digest && publication.a1Digest === identities.a1Digest && publication.bDigest === identities.bDigest && publication.cDigest === identities.cDigest && publication.jDigest === identities.jDigest, 'terminal authority identity mismatch');
  const journal = assertJournal(context.entries, context.journalIndex, { binding: context.binding, jDigest: identities.jDigest });
  invariant(publication.journalIndexDigest === identity('journal-index', context.journalIndex), 'terminal must bind exact final journal index');
  const legacyKind = assertLegacyLeaf(publication.legacy);
  invariant(publication.publicationKind === legacyKind, 'terminal publication kind must match nested legacy leaf');
  invariant(publication.commitMode === 'NOREPLACE', 'terminal commit mode must be no-replace');
  invariant(publication.writerImplemented === false, 'this package must not implement terminal publication');
  invariant(publication.durablePrefixEntries === journal.durablePrefixEntries, 'terminal durable prefix must exactly equal the journal prefix');
  if (publication.publicationKind === 'success') {
    const expectedObservation = observationProjection(context.binding, context.entries, context.journalIndex);
    invariant(publication.observationRequirementDigest === observationRequirementDigest(expectedObservation), 'terminal observation requirement must bind exact observation-to-index projection');
    assertSuccessTerminalStructure(context.entries, journal);
    invariant(publication.suffixSelection === 'success-final', 'success terminal suffix mismatch');
    invariant(false, 'success publication is unavailable in static v1: a future private observation brand is required');
  } else {
    invariant(publication.suffixSelection === 'failure-after-prefix' || publication.suffixSelection === 'recovery-after-prefix', 'failure terminal suffix must preserve its durable prefix');
    invariant(publication.observationRequirementDigest === noObservationTerminalDigest(context.journalIndex, publication.durablePrefixEntries, publication.suffixSelection), 'failure/recovery terminal must not invoke or bind observation');
  }
  return publication;
}
