import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  LIFECYCLE,
  advanceLifecycle,
  admitDispatch,
  appendJournalEntry,
  assertKBindingEdges,
  deriveJournalIndex,
  endpointRosterRoot,
  externalDispatchModel,
  isAdmittedDispatch,
  isJournalEntry,
  isJournalIndex,
  isPrivateObservation,
  isRetainedDescriptor,
  journalEntryProjection,
  journalIndexProjection,
  newLifecycle,
  openEvidenceJournal,
  openExclusiveClaim,
  recordObservation,
  retainDescriptor,
  validateDispatchPlan,
  workerEnvelope,
  workerRowsRoot
} from '../src/contracts.mjs';

const KAT = JSON.parse(await readFile(new URL('../kats/core.kat.json', import.meta.url), 'utf8'));

function dispatchPlan(overrides = {}) {
  return {
    dispatchPlanRoot: KAT.journal.dispatchPlanRoot,
    rowRoot: workerRowsRoot(KAT.workerRows),
    executionAllowed: false,
    workerRows: KAT.workerRows,
    ...overrides
  };
}

function opening() {
  const b = retainDescriptor(KAT.descriptor);
  const c = openExclusiveClaim(b, KAT.claim);
  const j = openEvidenceJournal(b, c, KAT.journal);
  const d = admitDispatch(b, c, j, dispatchPlan());
  return { b, c, j, d };
}

test('KAT retains B before clone and binds C J D to the exact dispatch shape', () => {
  const { b, c, j, d } = opening();
  assert.equal(isRetainedDescriptor(b), true);
  assert.equal(isAdmittedDispatch(d), true);
  assert.deepEqual(Object.keys(validateDispatchPlan(dispatchPlan())).sort(), ['dispatchPlanRoot', 'executionAllowed', 'rowRoot', 'workerRows']);
  assert.throws(() => openExclusiveClaim(structuredClone(b), KAT.claim), /K_BRAND/);
  assert.throws(() => openExclusiveClaim({}, KAT.claim), /K_BRAND/);
  assert.throws(() => retainDescriptor({ ...KAT.descriptor, uncloneable: () => true }), /K_KEYS/);
  assert.throws(() => validateDispatchPlan(dispatchPlan({ executionAllowed: Boolean(1) })), /K_DISPATCH/);
  assert.throws(() => admitDispatch(b, c, j, dispatchPlan({ rowRoot: '0'.repeat(64) })), /K_BINDING/);
  const incomplete = dispatchPlan();
  delete incomplete.executionAllowed;
  assert.throws(() => admitDispatch(b, c, j, incomplete), /K_KEYS/);
  assert.equal(endpointRosterRoot(KAT.workerRows).length, 64);
});

test('worker boundary has identity and byte authority only', () => {
  const { d } = opening();
  const envelope = workerEnvelope(d, 'worker-one');
  assert.deepEqual(Object.keys(envelope).sort(), ['byteAuthority', 'endpointId', 'workerId']);
  assert.deepEqual(externalDispatchModel(d, 'worker-one', 'module-worker').activationCapability, null);
  assert.equal(externalDispatchModel(d, 'worker-two', 'direct-loader').executionAllowed, false);
});

test('opaque ordered journal chain is the only observation authority', () => {
  const { j, d } = opening();
  const entry = appendJournalEntry(j, d, KAT.entry);
  assert.equal(isJournalEntry(entry), true);
  const index = deriveJournalIndex(j, d, [entry]);
  assert.equal(isJournalIndex(index), true);
  assert.equal(journalIndexProjection(index).entryCount, 1);
  const publicEntry = journalEntryProjection(entry);
  assert.equal(publicEntry.previousRoot, KAT.journal.journalRoot);
  assert.throws(() => recordObservation(d, index, structuredClone(publicEntry)), /K_BRAND/);
  assert.throws(() => recordObservation(d, structuredClone(index), entry), /K_BRAND/);

  const second = appendJournalEntry(j, d, {
    sequence: 1,
    kind: 'observed-followup',
    previousRoot: publicEntry.entryRoot,
    eventRoot: '8888888888888888888888888888888888888888888888888888888888888888'
  });
  assert.throws(() => recordObservation(d, index, second), /K_OBSERVATION/);
  assert.throws(() => deriveJournalIndex(j, d, [second]), /K_INDEX/);
  const forgedChain = appendJournalEntry(j, d, { ...KAT.entry, previousRoot: '0'.repeat(64) });
  assert.throws(() => deriveJournalIndex(j, d, [forgedChain]), /K_INDEX/);
  assert.throws(() => appendJournalEntry(j, structuredClone(d), KAT.entry), /K_BRAND/);

  const observation = recordObservation(d, index, entry);
  assert.equal(isPrivateObservation(observation), true);
  assert.throws(() => recordObservation(structuredClone(d), index, entry), /K_BRAND/);

  let state = newLifecycle();
  state = advanceLifecycle(state, LIFECYCLE.CLAIMED);
  state = advanceLifecycle(state, LIFECYCLE.JOURNALED);
  state = advanceLifecycle(state, LIFECYCLE.ADMITTED);
  state = advanceLifecycle(state, LIFECYCLE.EXTERNALLY_ACTIVE);
  assert.throws(() => advanceLifecycle(state, LIFECYCLE.FAILED), /K_LIFECYCLE/);
  assert.throws(() => advanceLifecycle(state, LIFECYCLE.TERMINAL), /K_LIFECYCLE/);
  state = advanceLifecycle(state, LIFECYCLE.OBSERVED);
  assert.throws(() => advanceLifecycle(state, LIFECYCLE.SUCCEEDED, structuredClone(observation)), /K_LIFECYCLE/);
  state = advanceLifecycle(state, LIFECYCLE.SUCCEEDED, observation);
  state = advanceLifecycle(state, LIFECYCLE.TERMINAL);
  assert.equal(state.phase, LIFECYCLE.TERMINAL);
});

test('J cannot widen into authority', () => {
  const b = retainDescriptor(KAT.descriptor);
  const c = openExclusiveClaim(b, KAT.claim);
  assert.throws(() => openEvidenceJournal(b, c, { ...KAT.journal, grantsAuthority: true }), /K_JOURNAL/);
});

test('K graph is closed, acyclic, and duplicate-free before set comparison', () => {
  const valid = [
    { from: 'B', to: 'C' }, { from: 'B', to: 'J' }, { from: 'C', to: 'J' },
    { from: 'B', to: 'D' }, { from: 'C', to: 'D' }, { from: 'J', to: 'D' }
  ];
  assert.equal(assertKBindingEdges(valid), true);
  assert.throws(() => assertKBindingEdges([...valid, { from: 'B', to: 'C' }]), /duplicate edge/);
  assert.throws(() => assertKBindingEdges([...valid, { from: 'D', to: 'J' }]), /K_EDGES/);
  assert.throws(() => assertKBindingEdges([...valid, { from: 'R', to: 'D' }]), /K_EDGES/);
  assert.throws(() => assertKBindingEdges(valid.filter((edge) => edge.from !== 'C')), /K_EDGES/);
});
