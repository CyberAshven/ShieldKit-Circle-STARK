import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ENDPOINTS,
  EXTERNAL_A0_BINDING_VERSION,
  GENESIS_DIGEST,
  JOURNAL_EVENTS,
  SCHEMA_VERSION,
  assertAuthorityDag,
  assertExternalA0Binding,
  assertJournal,
  assertSuccessTerminalStructure,
  assertTerminalPublication,
  canonicalJson,
  claimJoinSeedDigest,
  deriveRetainedDescriptorInventory,
  domainDigest,
  endpointScheduleDigest,
  externalA0BindingDigest,
  identity,
  journalEntryDigest,
  journalIndexDigest,
  noObservationTerminalDigest,
  observationProjection,
  observationRequirementDigest,
  retainedDescriptorInventoryDigest,
  stdinBindingDigest,
} from './model.mjs';
import { prepareSnapshotBinding } from './snapshot-boundary.mjs';

const hash = (label) => domainDigest('structural-fixture-only', label);
const clone = (value) => JSON.parse(JSON.stringify(value));
const snapshotStat = (n = '1') => ({ dev: n, ino: n, mode: '0600', uid: '1', gid: '1', nlink: '1', size: n });
const streamStat = (byteLength, n = '1') => ({ dev: n, ino: n, mode: '0600', uid: '1', gid: '1', nlink: '1', size: String(byteLength), mtimeNs: n });
const runtimeExecutable = (byteLength = 8) => ({
  id: '/proc/self/exe',
  role: 'runtime-executable',
  rawSha256: hash(`runtime-executable-raw-${byteLength}`),
  byteLength,
  stat: snapshotStat(String(byteLength)),
});

function makeClaim(a0, policy, binding, inventory = deriveRetainedDescriptorInventory(binding)) {
  const core = {
    schemaVersion: SCHEMA_VERSION,
    a0Digest: externalA0BindingDigest(a0),
    a1Digest: identity('a1', policy),
    bDigest: identity('b', binding),
    outputRoot: policy.paths.outputRoot,
    claimPath: policy.paths.claimPath,
    claimMode: '0600',
    claimDisposition: 'O_EXCL',
    nonreuse: true,
    retainedDescriptorInventory: inventory,
    retainedDescriptorInventoryDigest: retainedDescriptorInventoryDigest(inventory),
    writerImplemented: false,
  };
  return { ...core, joinSeedDigest: claimJoinSeedDigest(core) };
}

function makeJoin(a0, policy, binding, claim) {
  return {
    schemaVersion: SCHEMA_VERSION,
    a0Digest: externalA0BindingDigest(a0),
    a1Digest: identity('a1', policy),
    bDigest: identity('b', binding),
    cDigest: identity('c', claim),
    joinSeedDigest: claim.joinSeedDigest,
    packageManifestDigest: policy.packageManifestDigest,
    packageSha256SumsDigest: policy.packageSha256SumsDigest,
    launchProjectionDigest: domainDigest('launch-projection', policy.launchProjection),
    descriptorInventoryDigest: claim.retainedDescriptorInventoryDigest,
    stdinBindingRootDigest: binding.stdinBindingRootDigest,
    endpointScheduleDigest: endpointScheduleDigest(policy.endpoints),
    evidenceOnly: true,
    grantsAuthority: false,
  };
}

function makeCohort() {
  const a0 = Object.freeze({ schemaVersion: EXTERNAL_A0_BINDING_VERSION, externalAuthorizationDigest: hash('external-a0-pending') });
  const policy = {
    schemaVersion: SCHEMA_VERSION,
    a0Digest: externalA0BindingDigest(a0),
    packageManifestDigest: hash('manifest-pending'),
    packageSha256SumsDigest: hash('sha256sums-pending'),
    endpoints: ENDPOINTS.map(({ ordinal, id, role }) => ({ ordinal, id, role })),
    launchProjection: { argv: ['future-executor'], cwd: 'static', environment: {} },
    limits: { maxEndpointCount: 5, maxReadyRows: 4608 },
    paths: { claimPath: 'claims/attempt', journalRoot: 'journal', outputRoot: 'out', scratchRoot: 'scratch' },
    qualification: { containmentRequired: true, failClosed: true, journalRequired: true, observationRequired: true },
    executionAllowed: false,
  };
  const binding = prepareSnapshotBinding({
    a0Digest: externalA0BindingDigest(a0),
    a1Digest: identity('a1', policy),
    snapshotDigest: hash('snapshot-pending'),
    valuesRootDigest: hash('values-root-pending'),
    catalogBindingDigest: hash('catalog-pending'),
    runtimeExecutable: runtimeExecutable(),
    stdinInputs: ENDPOINTS.map(({ ordinal, id, role }) => ({ ordinal, id, role, codec: 'rows-v1', readyRows: 4608, bytes: Uint8Array.of(ordinal, 4, 6, 0, 8) })),
  });
  const claim = makeClaim(a0, policy, binding);
  const join = makeJoin(a0, policy, binding, claim);
  return { a0, policy, binding, claim, join };
}

function makeJournal(binding, join, count = 30, mutateEntry = undefined) {
  const jDigest = identity('j', join);
  const entries = [];
  for (let sequence = 0; sequence < count; sequence += 1) {
    const ordinal = Math.floor(sequence / JOURNAL_EVENTS.length);
    const event = JOURNAL_EVENTS[sequence % JOURNAL_EVENTS.length];
    const byteLength = ordinal + 1;
    const streamBindings = event === 'stdout-durable' || event === 'stderr-durable' ? [{
      stream: event.slice(0, -'-durable'.length),
      relativePath: `streams/${ordinal}-${event.slice(0, -'-durable'.length)}.bin`,
      sha256: hash(`stream-${ordinal}-${event}`),
      byteLength,
      stat: streamStat(byteLength, String(ordinal + 10)),
      fsynced: true,
    }] : [];
    const entry = {
      schemaVersion: SCHEMA_VERSION,
      jDigest,
      sequence,
      monotonicTimeNs: String(sequence + 1),
      previousDigest: sequence === 0 ? GENESIS_DIGEST : entries.at(-1).entryDigest,
      endpointOrdinal: ordinal,
      endpointId: ENDPOINTS[ordinal].id,
      event,
      stdinBindingDigest: event === 'endpoint-input-durable' ? stdinBindingDigest(binding.stdinBindings[ordinal]) : null,
      streamBindings,
    };
    mutateEntry?.(entry, sequence);
    entries.push({ ...entry, entryDigest: journalEntryDigest(entry) });
  }
  return resealJournal(entries, { jDigest });
}

function resealJournal(unsealedEntries, seedIndex) {
  const entries = unsealedEntries.map((entry) => ({ ...entry }));
  entries.forEach((entry, sequence) => {
    entry.sequence = sequence;
    entry.previousDigest = sequence === 0 ? GENESIS_DIGEST : entries[sequence - 1].entryDigest;
    entry.entryDigest = journalEntryDigest(entry);
  });
  const indexCore = {
    schemaVersion: SCHEMA_VERSION,
    jDigest: seedIndex.jDigest,
    firstSequence: 0,
    nextSequence: entries.length,
    headDigest: entries.length === 0 ? GENESIS_DIGEST : entries.at(-1).entryDigest,
    completedEndpointPrefix: Math.floor(entries.length / JOURNAL_EVENTS.length),
    entries: entries.map((entry) => ({ sequence: entry.sequence, entryDigest: entry.entryDigest, relativePath: `journal/${entry.sequence}.json`, jDigest: seedIndex.jDigest })),
    streamBindings: entries.flatMap((entry) => entry.streamBindings.map((stream) => ({ endpointOrdinal: entry.endpointOrdinal, endpointId: entry.endpointId, ...stream }))),
  };
  return { entries, index: { ...indexCore, indexDigest: journalIndexDigest(indexCore) } };
}

function terminalFor(cohort, entries, journalIndex, publicationKind = 'success', suffixSelection = 'success-final') {
  const requirement = observationRequirementDigest(observationProjection(cohort.binding, entries, journalIndex));
  const legacy = Object.freeze(publicationKind === 'success' ? { success: Object.freeze({ retainedLegacy: 'unchanged' }) } : { failure: Object.freeze({ retainedLegacy: 'unchanged' }) });
  const publication = {
    schemaVersion: SCHEMA_VERSION,
    a0Digest: externalA0BindingDigest(cohort.a0), a1Digest: identity('a1', cohort.policy), bDigest: identity('b', cohort.binding), cDigest: identity('c', cohort.claim), jDigest: identity('j', cohort.join),
    journalIndexDigest: identity('journal-index', journalIndex), observationRequirementDigest: publicationKind === 'success' ? requirement : noObservationTerminalDigest(journalIndex, entries.length, suffixSelection),
    publicationKind, durablePrefixEntries: entries.length, suffixSelection, commitMode: 'NOREPLACE', writerImplemented: false, legacy,
  };
  return { publication, context: { ...cohort, entries, journalIndex }, legacy };
}

test('external A0 is an exact frozen digest-only binding, not parsed authorization content', () => {
  const cohort = makeCohort();
  assert.doesNotThrow(() => assertExternalA0Binding(cohort.a0));
  assert.throws(() => assertExternalA0Binding({ ...cohort.a0 }), /frozen/);
  assert.throws(() => assertExternalA0Binding(Object.freeze({ ...cohort.a0, downstream: hash('forbidden') })), /unexpected keys/);
  assert.equal(cohort.binding.snapshotAdapterBranded, false);
  assert.equal(cohort.binding.externalBJoinStatus, 'PENDING_NONAUTHORIZING');
  assert.doesNotThrow(() => assertAuthorityDag(cohort.a0, cohort.policy, cohort.binding, cohort.claim, cohort.join));
});

test('C binds exact A1 paths, exact B inventory, and approved non-self join seed', () => {
  const cohort = makeCohort();
  for (const [field, value, message] of [['outputRoot', 'other-out', /outputRoot/], ['claimPath', 'other-claim', /claimPath/] ]) {
    const claim = { ...cohort.claim, [field]: value };
    claim.joinSeedDigest = claimJoinSeedDigest(claim);
    assert.throws(() => assertAuthorityDag(cohort.a0, cohort.policy, cohort.binding, claim, makeJoin(cohort.a0, cohort.policy, cohort.binding, claim)), message);
  }
  const inventory = clone(cohort.claim.retainedDescriptorInventory);
  inventory[0].projectionDigest = hash('substituted-inventory');
  const claim = makeClaim(cohort.a0, cohort.policy, cohort.binding, inventory);
  assert.throws(() => assertAuthorityDag(cohort.a0, cohort.policy, cohort.binding, claim, makeJoin(cohort.a0, cohort.policy, cohort.binding, claim)), /B-derived/);
  const catalogInventory = [{ id: 'input-catalog', role: 'catalog', projectionDigest: hash('catalog-substitution') }];
  assert.throws(() => makeClaim(cohort.a0, cohort.policy, cohort.binding, catalogInventory), /runtime executable/);
  const selfSeed = { ...cohort.claim, joinSeedDigest: hash('self-sealed-seed') };
  assert.throws(() => assertAuthorityDag(cohort.a0, cohort.policy, cohort.binding, selfSeed, makeJoin(cohort.a0, cohort.policy, cohort.binding, selfSeed)), /approved C fields/);
});

test('J excludes future journal content and binds exact B stdin root/schedule', () => {
  const cohort = makeCohort();
  assert.throws(() => assertAuthorityDag(cohort.a0, cohort.policy, cohort.binding, cohort.claim, { ...cohort.join, stdinBindingRootDigest: hash('wrong-b-root') }), /stdin-binding root/);
  assert.throws(() => assertAuthorityDag(cohort.a0, cohort.policy, cohort.binding, cohort.claim, { ...cohort.join, journalIndexDigest: hash('future-journal') }), /unexpected keys/);
});

test('journal binds J, exact B stdin records, strict stream stat sizes, and global paths', () => {
  const cohort = makeCohort();
  const journal = makeJournal(cohort.binding, cohort.join);
  assert.equal(assertJournal(journal.entries, journal.index, { binding: cohort.binding, jDigest: identity('j', cohort.join) }).completedEndpointPrefix, 5);
  const wrongInput = makeJournal(cohort.binding, cohort.join, 30, (entry, sequence) => { if (sequence === 0) entry.stdinBindingDigest = hash('self-resealed-input'); });
  assert.throws(() => assertJournal(wrongInput.entries, wrongInput.index, { binding: cohort.binding, jDigest: identity('j', cohort.join) }), /exact B stdin/);
  const wrongSize = makeJournal(cohort.binding, cohort.join, 30, (entry, sequence) => { if (sequence === 2) entry.streamBindings[0].stat.size = '999'; });
  assert.throws(() => assertJournal(wrongSize.entries, wrongSize.index, { binding: cohort.binding, jDigest: identity('j', cohort.join) }), /size/);
  const duplicateStream = makeJournal(cohort.binding, cohort.join, 30, (entry, sequence) => { if (sequence === 3) entry.streamBindings[0].relativePath = 'streams/0-stdout.bin'; });
  assert.throws(() => assertJournal(duplicateStream.entries, duplicateStream.index, { binding: cohort.binding, jDigest: identity('j', cohort.join) }), /global journal/);
  const crossNamespace = makeJournal(cohort.binding, cohort.join, 30, (entry, sequence) => { if (sequence === 2) entry.streamBindings[0].relativePath = 'journal/2.json'; });
  assert.throws(() => assertJournal(crossNamespace.entries, crossNamespace.index, { binding: cohort.binding, jDigest: identity('j', cohort.join) }), /global journal/);
});

test('success structure is checked, but success publication is mechanically unavailable in static v1', () => {
  const cohort = makeCohort();
  const full = makeJournal(cohort.binding, cohort.join);
  const journal = assertJournal(full.entries, full.index, { binding: cohort.binding, jDigest: identity('j', cohort.join) });
  assert.doesNotThrow(() => assertSuccessTerminalStructure(full.entries, journal));
  const success = terminalFor(cohort, full.entries, full.index);
  assert.throws(() => assertTerminalPublication(success.publication, success.context), /private observation brand/);
  const oneEndpoint = makeJournal(cohort.binding, cohort.join, 6);
  const oneJournal = assertJournal(oneEndpoint.entries, oneEndpoint.index, { binding: cohort.binding, jDigest: identity('j', cohort.join) });
  assert.throws(() => assertSuccessTerminalStructure(oneEndpoint.entries, oneJournal), /exactly 30/);
  assert.throws(() => assertTerminalPublication(success.publication, { ...success.context, predicate: () => true }), /unexpected keys/);
  assert.throws(() => assertTerminalPublication({ ...success.publication, observationRequirementDigest: hash('wrong-requirement') }, success.context), /observation requirement/);
});

test('failure terminal preserves exact durable prefix and no observation authorization surface', () => {
  const cohort = makeCohort();
  const partial = makeJournal(cohort.binding, cohort.join, 3);
  const failure = terminalFor(cohort, partial.entries, partial.index, 'failure', 'recovery-after-prefix');
  const before = canonicalJson(failure.legacy);
  assert.doesNotThrow(() => assertTerminalPublication(failure.publication, failure.context));
  assert.equal(canonicalJson(failure.legacy), before);
  assert.throws(() => assertTerminalPublication({ ...failure.publication, durablePrefixEntries: 0 }, failure.context), /durable prefix/);
  assert.throws(() => assertTerminalPublication({ ...failure.publication, suffixSelection: 'success-final' }, failure.context), /suffix/);
});
