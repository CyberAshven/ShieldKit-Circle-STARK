import {
  canonicalJson,
  deepFreeze,
  domainHash,
  fail,
  opaque,
  requireExactKeys,
  requireIdentifier,
  requireRoot,
  requireUint32
} from './strict.mjs';
import { privateStorageContract, requireClaimDescriptor } from './file-contracts.mjs';

const retainedBrands = new WeakSet();
const claimBrands = new WeakSet();
const journalBrands = new WeakSet();
const dispatchBrands = new WeakSet();
const journalEntryBrands = new WeakSet();
const journalIndexBrands = new WeakSet();
const observationBrands = new WeakSet();
const retainedRecords = new WeakMap();
const claimRecords = new WeakMap();
const journalRecords = new WeakMap();
const dispatchRecords = new WeakMap();
const journalEntryRecords = new WeakMap();
const journalIndexRecords = new WeakMap();
const observationRecords = new WeakMap();

export const LIFECYCLE = Object.freeze({
  RETAINED: 'retained',
  CLAIMED: 'claimed',
  JOURNALED: 'journaled',
  ADMITTED: 'admitted',
  EXTERNALLY_ACTIVE: 'externally-active',
  OBSERVED: 'observed',
  SUCCEEDED: 'succeeded',
  FAILED: 'failed',
  RECOVERING: 'recovering',
  TERMINAL: 'terminal'
});

function assertBrand(set, value, label) {
  if (!set.has(value)) fail('K_BRAND', `${label} is not privately admitted`);
}

function validateRetainedInput(value) {
  requireExactKeys(value, ['descriptorKey', 'revision', 'subjectRoot', 'envelopeRoot'], 'retained descriptor');
  requireIdentifier(value.descriptorKey, 'descriptor key');
  if (!Number.isInteger(value.revision) || value.revision < 1 || value.revision > 0xffffffff) {
    fail('K_REVISION', 'descriptor revision is outside uint32 positive range');
  }
  requireRoot(value.subjectRoot, 'subject root');
  requireRoot(value.envelopeRoot, 'envelope root');
}

export function retainDescriptor(value) {
  validateRetainedInput(value);
  const copied = deepFreeze(structuredClone(value));
  const handle = opaque();
  retainedBrands.add(handle);
  retainedRecords.set(handle, Object.freeze({
    copied,
    receipt: domainHash('K/B', copied)
  }));
  return handle;
}

export function isRetainedDescriptor(value) {
  return retainedBrands.has(value);
}

export function openExclusiveClaim(retained, descriptor) {
  assertBrand(retainedBrands, retained, 'B');
  const copied = requireClaimDescriptor(descriptor);
  const record = retainedRecords.get(retained);
  const handle = opaque();
  claimBrands.add(handle);
  claimRecords.set(handle, Object.freeze({
    retained,
    descriptor: copied,
    receipt: domainHash('K/C', { b: record.receipt, descriptor: copied })
  }));
  return handle;
}

export function isExclusiveClaim(value) {
  return claimBrands.has(value);
}

function validateRows(rows) {
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 4096) fail('K_ROWS', 'worker row cardinality is outside bounds');
  const workers = new Set();
  const endpoints = new Set();
  const copied = rows.map((row) => {
    requireExactKeys(row, ['workerId', 'endpointId', 'byteAuthority'], 'worker row');
    requireIdentifier(row.workerId, 'worker id');
    requireIdentifier(row.endpointId, 'endpoint id');
    requireExactKeys(row.byteAuthority, ['contentRoot', 'byteCount'], 'byte authority');
    requireRoot(row.byteAuthority.contentRoot, 'byte authority root');
    requireUint32(row.byteAuthority.byteCount, 'byte authority count');
    if (workers.has(row.workerId) || endpoints.has(row.endpointId)) fail('K_ROWS', 'worker or endpoint identity repeats');
    workers.add(row.workerId);
    endpoints.add(row.endpointId);
    return deepFreeze(structuredClone(row));
  });
  return deepFreeze(copied);
}

export function workerRowsRoot(rows) {
  return domainHash('K/WORKER-ROWS', validateRows(rows));
}

export function endpointRosterRoot(rows) {
  const copied = validateRows(rows);
  return domainHash('K/ENDPOINT-ROSTER', copied.map(({ endpointId }) => ({ endpointId })));
}

export function validateDispatchPlan(value) {
  requireExactKeys(value, ['dispatchPlanRoot', 'rowRoot', 'executionAllowed', 'workerRows'], 'dispatch plan');
  requireRoot(value.dispatchPlanRoot, 'dispatch plan root');
  requireRoot(value.rowRoot, 'worker row root');
  if (value.executionAllowed !== false) fail('K_DISPATCH', 'K dispatch plan cannot enable execution');
  const workerRows = validateRows(value.workerRows);
  const computedRowRoot = domainHash('K/WORKER-ROWS', workerRows);
  if (computedRowRoot !== value.rowRoot) fail('K_BINDING', 'worker row root differs from roster');
  return deepFreeze({
    dispatchPlanRoot: value.dispatchPlanRoot,
    rowRoot: value.rowRoot,
    executionAllowed: false,
    workerRows
  });
}

export function openEvidenceJournal(retained, claim, journalInput) {
  assertBrand(retainedBrands, retained, 'B');
  assertBrand(claimBrands, claim, 'C');
  const claimRecord = claimRecords.get(claim);
  if (claimRecord.retained !== retained) fail('K_BINDING', 'C is not bound to B');
  requireExactKeys(journalInput, ['journalKey', 'dispatchPlanRoot', 'journalRoot', 'evidenceOnly', 'grantsAuthority'], 'journal opening');
  requireIdentifier(journalInput.journalKey, 'journal key');
  requireRoot(journalInput.dispatchPlanRoot, 'dispatch plan root');
  requireRoot(journalInput.journalRoot, 'journal root');
  if (journalInput.evidenceOnly !== true || journalInput.grantsAuthority !== false) {
    fail('K_JOURNAL', 'J must be evidence-only and authority-free');
  }
  const copied = deepFreeze(structuredClone(journalInput));
  const handle = opaque();
  journalBrands.add(handle);
  journalRecords.set(handle, Object.freeze({
    retained,
    claim,
    copied,
    receipt: domainHash('K/J', { b: retainedRecords.get(retained).receipt, c: claimRecord.receipt, journal: copied })
  }));
  return handle;
}

export function isEvidenceJournal(value) {
  return journalBrands.has(value);
}

export function admitDispatch(retained, claim, journal, input) {
  assertBrand(retainedBrands, retained, 'B');
  assertBrand(claimBrands, claim, 'C');
  assertBrand(journalBrands, journal, 'J');
  const claimRecord = claimRecords.get(claim);
  const journalRecord = journalRecords.get(journal);
  if (claimRecord.retained !== retained || journalRecord.retained !== retained || journalRecord.claim !== claim) {
    fail('K_BINDING', 'B, C, and J do not form one chain');
  }
  const plan = validateDispatchPlan(input);
  if (plan.dispatchPlanRoot !== journalRecord.copied.dispatchPlanRoot) fail('K_BINDING', 'D dispatch plan root differs from J');
  const rosterRoot = domainHash('K/ENDPOINT-ROSTER', plan.workerRows.map(({ endpointId }) => ({ endpointId })));
  const handle = opaque();
  dispatchBrands.add(handle);
  dispatchRecords.set(handle, Object.freeze({
    retained,
    claim,
    journal,
    rows: plan.workerRows,
    dispatchPlanRoot: plan.dispatchPlanRoot,
    rowRoot: plan.rowRoot,
    executionAllowed: false,
    rosterRoot,
    receipt: domainHash('K/D', {
      b: retainedRecords.get(retained).receipt,
      c: claimRecord.receipt,
      j: journalRecord.receipt,
      dispatchPlanRoot: plan.dispatchPlanRoot,
      rowRoot: plan.rowRoot,
      executionAllowed: false,
      rosterRoot
    })
  }));
  return handle;
}

export function isAdmittedDispatch(value) {
  return dispatchBrands.has(value);
}

export function workerEnvelope(dispatch, workerId) {
  assertBrand(dispatchBrands, dispatch, 'D');
  requireIdentifier(workerId, 'worker id');
  const row = dispatchRecords.get(dispatch).rows.find((candidate) => candidate.workerId === workerId);
  if (!row) fail('K_WORKER', 'worker is absent from D');
  return deepFreeze(structuredClone({
    workerId: row.workerId,
    endpointId: row.endpointId,
    byteAuthority: row.byteAuthority
  }));
}

export function externalDispatchModel(dispatch, workerId, mechanism) {
  if (mechanism !== 'module-worker' && mechanism !== 'direct-loader') {
    fail('K_MECHANISM', 'external mechanism is unrecognized');
  }
  return deepFreeze({
    executionAllowed: false,
    mechanism,
    envelope: workerEnvelope(dispatch, workerId),
    activationCapability: null,
    storage: privateStorageContract()
  });
}

function expectedJournalEntryRoot(journalReceipt, dispatchReceipt, input) {
  return domainHash('K/JOURNAL-ENTRY', {
    journalReceipt,
    dispatchReceipt,
    sequence: input.sequence,
    kind: input.kind,
    previousRoot: input.previousRoot,
    eventRoot: input.eventRoot
  });
}

function validateJournalEntryInput(input) {
  requireExactKeys(input, ['sequence', 'kind', 'previousRoot', 'eventRoot'], 'journal entry input');
  requireUint32(input.sequence, 'journal sequence');
  requireIdentifier(input.kind, 'journal kind');
  requireRoot(input.previousRoot, 'journal previous root');
  requireRoot(input.eventRoot, 'journal event root');
  return deepFreeze(structuredClone(input));
}

export function appendJournalEntry(journal, dispatch, input) {
  assertBrand(journalBrands, journal, 'J');
  assertBrand(dispatchBrands, dispatch, 'D');
  const dispatchRecord = dispatchRecords.get(dispatch);
  if (dispatchRecord.journal !== journal) fail('K_BINDING', 'journal entry lacks D-to-J binding');
  const journalRecord = journalRecords.get(journal);
  const copied = validateJournalEntryInput(input);
  const entryRoot = expectedJournalEntryRoot(journalRecord.receipt, dispatchRecord.receipt, copied);
  const handle = opaque();
  journalEntryBrands.add(handle);
  journalEntryRecords.set(handle, Object.freeze({
    journal,
    dispatch,
    data: deepFreeze({
      journalKey: journalRecord.copied.journalKey,
      journalReceipt: journalRecord.receipt,
      dispatchReceipt: dispatchRecord.receipt,
      sequence: copied.sequence,
      kind: copied.kind,
      previousRoot: copied.previousRoot,
      eventRoot: copied.eventRoot,
      entryRoot
    })
  }));
  return handle;
}

export function isJournalEntry(value) {
  return journalEntryBrands.has(value);
}

export function journalEntryProjection(entry) {
  assertBrand(journalEntryBrands, entry, 'journal entry');
  return deepFreeze(structuredClone(journalEntryRecords.get(entry).data));
}

export function deriveJournalIndex(journal, dispatch, entries) {
  assertBrand(journalBrands, journal, 'J');
  assertBrand(dispatchBrands, dispatch, 'D');
  const dispatchRecord = dispatchRecords.get(dispatch);
  const journalRecord = journalRecords.get(journal);
  if (dispatchRecord.journal !== journal) fail('K_BINDING', 'journal index lacks D-to-J binding');
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 0xffffffff) fail('K_INDEX', 'journal entry cardinality is invalid');
  const seen = new Set();
  let previousRoot = journalRecord.copied.journalRoot;
  const copied = entries.map((entry, index) => {
    assertBrand(journalEntryBrands, entry, 'journal entry');
    if (seen.has(entry)) fail('K_INDEX', 'journal entry repeats');
    seen.add(entry);
    const record = journalEntryRecords.get(entry);
    const data = record.data;
    if (record.journal !== journal || record.dispatch !== dispatch || data.sequence !== index || data.previousRoot !== previousRoot) {
      fail('K_INDEX', 'journal entries are not an exact ordered chain');
    }
    const recomputed = expectedJournalEntryRoot(journalRecord.receipt, dispatchRecord.receipt, data);
    if (data.entryRoot !== recomputed) fail('K_INDEX', 'journal entry root transition is invalid');
    previousRoot = data.entryRoot;
    return data;
  });
  const handle = opaque();
  journalIndexBrands.add(handle);
  journalIndexRecords.set(handle, Object.freeze({
    journal,
    dispatch,
    entries: Object.freeze([...entries]),
    data: deepFreeze({
      journalKey: journalRecord.copied.journalKey,
      journalReceipt: journalRecord.receipt,
      dispatchReceipt: dispatchRecord.receipt,
      entryCount: copied.length,
      finalRoot: previousRoot,
      indexRoot: domainHash('K/JOURNAL-INDEX', copied)
    })
  }));
  return handle;
}

export function isJournalIndex(value) {
  return journalIndexBrands.has(value);
}

export function journalIndexProjection(index) {
  assertBrand(journalIndexBrands, index, 'journal index');
  return deepFreeze(structuredClone(journalIndexRecords.get(index).data));
}

export function recordObservation(dispatch, index, entry) {
  assertBrand(dispatchBrands, dispatch, 'D');
  assertBrand(journalIndexBrands, index, 'journal index');
  assertBrand(journalEntryBrands, entry, 'journal entry');
  const dispatchRecord = dispatchRecords.get(dispatch);
  const indexRecord = journalIndexRecords.get(index);
  const entryRecord = journalEntryRecords.get(entry);
  if (indexRecord.dispatch !== dispatch || entryRecord.dispatch !== dispatch || entryRecord.journal !== indexRecord.journal || !indexRecord.entries.includes(entry)) {
    fail('K_OBSERVATION', 'observation lacks exact J/D/index/entry authority');
  }
  const data = entryRecord.data;
  const journalRecord = journalRecords.get(indexRecord.journal);
  const recomputed = expectedJournalEntryRoot(journalRecord.receipt, dispatchRecord.receipt, data);
  if (data.journalKey !== journalRecord.copied.journalKey || data.journalReceipt !== journalRecord.receipt || data.dispatchReceipt !== dispatchRecord.receipt || data.entryRoot !== recomputed) {
    fail('K_OBSERVATION', 'observation entry authority is invalid');
  }
  const handle = opaque();
  observationBrands.add(handle);
  observationRecords.set(handle, Object.freeze({ dispatch, index, entry }));
  return handle;
}

export function isPrivateObservation(value) {
  return observationBrands.has(value);
}

export function newLifecycle() {
  return deepFreeze({ phase: LIFECYCLE.RETAINED, externalActive: false, executionAllowed: false });
}

const FORWARD = new Map([
  [LIFECYCLE.RETAINED, new Set([LIFECYCLE.CLAIMED])],
  [LIFECYCLE.CLAIMED, new Set([LIFECYCLE.JOURNALED])],
  [LIFECYCLE.JOURNALED, new Set([LIFECYCLE.ADMITTED])],
  [LIFECYCLE.ADMITTED, new Set([LIFECYCLE.EXTERNALLY_ACTIVE, LIFECYCLE.FAILED])],
  [LIFECYCLE.EXTERNALLY_ACTIVE, new Set([LIFECYCLE.OBSERVED])],
  [LIFECYCLE.OBSERVED, new Set([LIFECYCLE.SUCCEEDED, LIFECYCLE.FAILED])],
  [LIFECYCLE.FAILED, new Set([LIFECYCLE.RECOVERING, LIFECYCLE.TERMINAL])],
  [LIFECYCLE.RECOVERING, new Set([LIFECYCLE.FAILED])],
  [LIFECYCLE.SUCCEEDED, new Set([LIFECYCLE.TERMINAL])],
  [LIFECYCLE.TERMINAL, new Set()]
]);

export function advanceLifecycle(model, next, observation) {
  requireExactKeys(model, ['phase', 'externalActive', 'executionAllowed'], 'lifecycle model');
  if (model.executionAllowed !== false || typeof model.externalActive !== 'boolean' || !FORWARD.has(model.phase) || !FORWARD.get(model.phase).has(next)) {
    fail('K_LIFECYCLE', 'lifecycle transition is outside the closed grammar');
  }
  if ((next === LIFECYCLE.FAILED || next === LIFECYCLE.RECOVERING || next === LIFECYCLE.TERMINAL) && model.externalActive) {
    fail('K_LIFECYCLE', 'failure, recovery, and terminal require inactive external state');
  }
  if (next === LIFECYCLE.SUCCEEDED) {
    if (model.phase !== LIFECYCLE.OBSERVED || !observationBrands.has(observation)) {
      fail('K_LIFECYCLE', 'success requires a private observation');
    }
  }
  const externalActive = next === LIFECYCLE.EXTERNALLY_ACTIVE;
  if (next === LIFECYCLE.OBSERVED && model.externalActive !== true) fail('K_LIFECYCLE', 'observation requires active external state');
  return deepFreeze({ phase: next, externalActive, executionAllowed: false });
}

export function assertAcyclicEdges(edges) {
  if (!Array.isArray(edges)) fail('K_EDGES', 'edges must be an array');
  const adjacency = new Map();
  for (const edge of edges) {
    requireExactKeys(edge, ['from', 'to'], 'edge');
    if (typeof edge.from !== 'string' || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(edge.from)) {
      fail('K_EDGES', 'edge source is outside grammar');
    }
    if (typeof edge.to !== 'string' || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(edge.to)) {
      fail('K_EDGES', 'edge target is outside grammar');
    }
    if (edge.from === edge.to) fail('K_EDGES', 'self edge is forbidden');
    if (!adjacency.has(edge.from)) adjacency.set(edge.from, new Set());
    adjacency.get(edge.from).add(edge.to);
  }
  const visiting = new Set();
  const visited = new Set();
  const visit = (node) => {
    if (visiting.has(node)) fail('K_EDGES', 'cycle is forbidden');
    if (visited.has(node)) return;
    visiting.add(node);
    for (const child of adjacency.get(node) ?? []) visit(child);
    visiting.delete(node);
    visited.add(node);
  };
  for (const node of adjacency.keys()) visit(node);
  return true;
}

export function assertKBindingEdges(edges) {
  if (!Array.isArray(edges)) fail('K_EDGES', 'edges must be an array');
  const encoded = edges.map((edge) => {
    requireExactKeys(edge, ['from', 'to'], 'edge');
    return `${edge.from}>${edge.to}`;
  });
  if (new Set(encoded).size !== encoded.length) fail('K_EDGES', 'duplicate edge is forbidden');
  assertAcyclicEdges(edges);
  const seen = new Set(encoded);
  const needed = ['B>C', 'B>J', 'C>J', 'B>D', 'C>D', 'J>D'];
  if (seen.size !== needed.length || needed.some((edge) => !seen.has(edge))) {
    fail('K_EDGES', 'K binding edges are incomplete or widened');
  }
  if (seen.has('D>J')) fail('K_EDGES', 'J cannot depend on D');
  return true;
}

export function retainedReceipt(retained) {
  assertBrand(retainedBrands, retained, 'B');
  return retainedRecords.get(retained).receipt;
}

export function canonicalWorkerEnvelope(value) {
  requireExactKeys(value, ['workerId', 'endpointId', 'byteAuthority'], 'worker envelope');
  return canonicalJson(value);
}
