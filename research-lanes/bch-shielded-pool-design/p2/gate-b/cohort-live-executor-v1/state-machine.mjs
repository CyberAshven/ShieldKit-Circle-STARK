import { ENDPOINTS, JOURNAL_EVENTS, invariant } from './model.mjs';

export const INITIAL_STATE = 'STATIC';
export const SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION = 'SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION';
export const RECOVERY_BLOCKED = 'RECOVERY_BLOCKED_ACTIVE_EXTERNAL';

const PREFIX = [
  ['STATIC', 'POLICY_AUTHENTICATE', 'POLICY_AUTHENTICATED'],
  ['POLICY_AUTHENTICATED', 'SNAPSHOT_PREPARE', 'SNAPSHOT_PREPARED'],
  ['SNAPSHOT_PREPARED', 'B_DURABLE', 'B_DURABLE_UNCLAIMED'],
  ['B_DURABLE_UNCLAIMED', 'C_DURABLE', 'C_DURABLE_CLAIMED'],
  ['C_DURABLE_CLAIMED', 'J_DURABLE', 'J_DURABLE'],
  ['J_DURABLE', 'SCRATCH_DURABLE', 'SCRATCH_DURABLE'],
];

function endpointState(ordinal, event) {
  return `ENDPOINT_${ordinal}_${event.toUpperCase().replaceAll('-', '_')}`;
}

const SUCCESS_TRANSITIONS = new Map(PREFIX.map(([from, event, to]) => [`${from}\u0000${event}`, to]));
let previous = 'SCRATCH_DURABLE';
for (const endpoint of ENDPOINTS) {
  for (const journalEvent of JOURNAL_EVENTS) {
    const event = `ENDPOINT_${journalEvent.toUpperCase().replaceAll('-', '_')}`;
    const next = endpoint.ordinal === ENDPOINTS.length - 1 && journalEvent === 'endpoint-sealed'
      ? SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION
      : endpointState(endpoint.ordinal, journalEvent);
    SUCCESS_TRANSITIONS.set(`${previous}\u0000${event}`, next);
    previous = next;
  }
}

function eventType(event) {
  invariant(typeof event === 'string', 'state event must be an exact static string; caller metadata is not authority');
  return event;
}

function isConservativeExternalRiskState(state) {
  // endpoint-started is a durable pre-spawn barrier. For BCHN and both Lean
  // endpoints, a crash after it and before close-observed is conservatively
  // treated as potentially externally active even if launch never ran.
  for (const ordinal of [2, 3, 4]) {
    for (const journalEvent of ['endpoint-started', 'stdout-durable', 'stderr-durable']) {
      if (state === endpointState(ordinal, journalEvent)) return true;
    }
  }
  return false;
}

function endpointPrefixEntries(state) {
  for (const endpoint of ENDPOINTS) {
    for (let eventIndex = 0; eventIndex < JOURNAL_EVENTS.length; eventIndex += 1) {
      if (state === endpointState(endpoint.ordinal, JOURNAL_EVENTS[eventIndex])) return endpoint.ordinal * JOURNAL_EVENTS.length + eventIndex + 1;
    }
  }
  return null;
}

export function durablePrefixEntries(state) {
  const endpointPrefix = endpointPrefixEntries(state);
  if (endpointPrefix !== null) return endpointPrefix;
  if (['STATIC', 'POLICY_AUTHENTICATED', 'SNAPSHOT_PREPARED', 'B_DURABLE_UNCLAIMED', 'C_DURABLE_CLAIMED', 'J_DURABLE', 'SCRATCH_DURABLE'].includes(state)) return 0;
  if ([SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION].includes(state)) return 30;
  const prefixed = /^(?:FAILURE|RECOVERY)_PREFIX_(\d+)(?:_C_UNJOINED)?(?:_STAGED|_TERMINAL_STAGED_VALIDATED|_COMMITTED_NOREPLACE)$/.exec(state);
  if (prefixed) return Number(prefixed[1]);
  return null;
}

function failureStage(prefix) {
  return `FAILURE_PREFIX_${prefix}_STAGED`;
}

function recoveryStage(prefix, cUnjoined = false) {
  return `RECOVERY_PREFIX_${prefix}${cUnjoined ? '_C_UNJOINED' : ''}_STAGED`;
}

function terminalProgress(state, family) {
  const pattern = new RegExp(`^${family}_PREFIX_(\\d+)(_C_UNJOINED)?_(STAGED|TERMINAL_STAGED_VALIDATED)$`);
  const match = pattern.exec(state);
  if (!match) return null;
  return { prefix: Number(match[1]), cUnjoined: match[2] === '_C_UNJOINED', phase: match[3] };
}

export function transition(state, event) {
  invariant(typeof state === 'string', 'state must be a string');
  const type = eventType(event);
  if ((type === 'FAIL' || type === 'RECOVER') && isConservativeExternalRiskState(state)) return RECOVERY_BLOCKED;
  if (state === RECOVERY_BLOCKED) invariant(false, 'blocked active-external state has no local continuation');

  if (type === 'FAIL') {
    invariant(!['FAILURE_COMMITTED_NOREPLACE', 'RECOVERY_COMMITTED_NOREPLACE'].includes(state), 'cannot fail a committed terminal state');
    const prefix = durablePrefixEntries(state);
    invariant(prefix !== null, `cannot fail from ${state}`);
    return failureStage(prefix);
  }

  const failure = terminalProgress(state, 'FAILURE');
  if (failure && failure.phase === 'STAGED' && type === 'FAILURE_TERMINAL_VALIDATE') return `FAILURE_PREFIX_${failure.prefix}_TERMINAL_STAGED_VALIDATED`;
  if (failure && failure.phase === 'TERMINAL_STAGED_VALIDATED' && type === 'FAILURE_COMMIT_NOREPLACE') return `FAILURE_PREFIX_${failure.prefix}_COMMITTED_NOREPLACE`;

  if (type === 'RECOVER') {
    if (state === 'B_DURABLE_UNCLAIMED') return 'RECOVERY_UNCLAIMED';
    if (state === 'C_DURABLE_CLAIMED') return recoveryStage(0, true);
    const prefix = durablePrefixEntries(state);
    invariant(prefix !== null && ['J_DURABLE', 'SCRATCH_DURABLE', SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION].includes(state) || endpointPrefixEntries(state) !== null, `recovery is not available from ${state}`);
    return recoveryStage(prefix);
  }

  const recovery = terminalProgress(state, 'RECOVERY');
  if (recovery && recovery.phase === 'STAGED' && type === 'RECOVERY_TERMINAL_VALIDATE') return `RECOVERY_PREFIX_${recovery.prefix}${recovery.cUnjoined ? '_C_UNJOINED' : ''}_TERMINAL_STAGED_VALIDATED`;
  if (recovery && recovery.phase === 'TERMINAL_STAGED_VALIDATED' && type === 'RECOVERY_COMMIT_NOREPLACE') return `RECOVERY_PREFIX_${recovery.prefix}${recovery.cUnjoined ? '_C_UNJOINED' : ''}_COMMITTED_NOREPLACE`;

  const next = SUCCESS_TRANSITIONS.get(`${state}\u0000${type}`);
  invariant(next !== undefined, `invalid transition ${state} --${type}-->`);
  return next;
}

export function successTraceEvents() {
  const events = PREFIX.map(([, event]) => event);
  for (const endpoint of ENDPOINTS) {
    for (const journalEvent of JOURNAL_EVENTS) events.push(`ENDPOINT_${journalEvent.toUpperCase().replaceAll('-', '_')}`);
  }
  return Object.freeze(events);
}

export function replay(initialState, events) {
  invariant(Array.isArray(events), 'trace events must be an array');
  return events.reduce((state, event) => transition(state, event), initialState);
}

export function completedEndpointPrefix(state) {
  const prefix = durablePrefixEntries(state);
  return prefix === null ? 0 : Math.floor(prefix / JOURNAL_EVENTS.length);
}
