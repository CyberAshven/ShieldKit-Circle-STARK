import assert from 'node:assert/strict';
import test from 'node:test';
import {
  INITIAL_STATE,
  RECOVERY_BLOCKED,
  SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION,
  completedEndpointPrefix,
  durablePrefixEntries,
  replay,
  successTraceEvents,
  transition,
} from './state-machine.mjs';

function reach(target) {
  let state = INITIAL_STATE;
  for (const event of successTraceEvents()) {
    state = transition(state, event);
    if (state === target) return state;
  }
  throw new Error(`unreachable test target ${target}`);
}

const RISK_STATES = [
  'ENDPOINT_2_ENDPOINT_STARTED', 'ENDPOINT_2_STDOUT_DURABLE', 'ENDPOINT_2_STDERR_DURABLE',
  'ENDPOINT_3_ENDPOINT_STARTED', 'ENDPOINT_3_STDOUT_DURABLE', 'ENDPOINT_3_STDERR_DURABLE',
  'ENDPOINT_4_ENDPOINT_STARTED', 'ENDPOINT_4_STDOUT_DURABLE', 'ENDPOINT_4_STDERR_DURABLE',
];

test('exact static-to-structural-success trace has five ordered six-event endpoint traces', () => {
  const events = successTraceEvents();
  assert.equal(events.length, 36);
  assert.equal(events.filter((event) => event === 'ENDPOINT_ENDPOINT_SEALED').length, 5);
  assert.equal(replay(INITIAL_STATE, events), SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION);
  assert.equal(completedEndpointPrefix('ENDPOINT_0_ENDPOINT_SEALED'), 1);
  assert.equal(completedEndpointPrefix(SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION), 5);
  assert.throws(() => transition(SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION, ['SUCCESS', 'COMMIT_NOREPLACE'].join('_')), /invalid transition/);
  assert.throws(() => transition(SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION, ['OBSERVATION', 'SEAL'].join('_')), /invalid transition/);
  assert.throws(() => transition(SUCCESS_STRUCTURE_READY_PENDING_PRIVATE_OBSERVATION, ['TERMINAL', 'STAGE_VALIDATE'].join('_')), /invalid transition/);
});

test('failure branches preserve prefixes except the durable BCHN/Lean pre-spawn risk barrier', () => {
  let state = INITIAL_STATE;
  const predecessors = [state];
  for (const event of successTraceEvents()) {
    state = transition(state, event);
    predecessors.push(state);
  }
  for (const predecessor of predecessors) {
    const outcome = transition(predecessor, 'FAIL');
    if (RISK_STATES.includes(predecessor)) {
      assert.equal(outcome, RECOVERY_BLOCKED);
    } else {
      const prefix = durablePrefixEntries(predecessor);
      assert.equal(outcome, `FAILURE_PREFIX_${prefix}_STAGED`);
      assert.equal(transition(transition(outcome, 'FAILURE_TERMINAL_VALIDATE'), 'FAILURE_COMMIT_NOREPLACE'), `FAILURE_PREFIX_${prefix}_COMMITTED_NOREPLACE`);
    }
  }
});

test('B/C/J crash gaps preserve their only allowed recovery meaning and prefix', () => {
  assert.equal(transition(reach('B_DURABLE_UNCLAIMED'), 'RECOVER'), 'RECOVERY_UNCLAIMED');
  const cRecovery = transition(reach('C_DURABLE_CLAIMED'), 'RECOVER');
  assert.equal(cRecovery, 'RECOVERY_PREFIX_0_C_UNJOINED_STAGED');
  assert.equal(durablePrefixEntries(cRecovery), 0);
  assert.throws(() => transition(cRecovery, 'ENDPOINT_ENDPOINT_INPUT_DURABLE'), /invalid transition/);
  assert.throws(() => transition(cRecovery, ['OBSERVATION', 'SEAL'].join('_')), /invalid transition/);
  assert.equal(transition(transition(cRecovery, 'RECOVERY_TERMINAL_VALIDATE'), 'RECOVERY_COMMIT_NOREPLACE'), 'RECOVERY_PREFIX_0_C_UNJOINED_COMMITTED_NOREPLACE');
  assert.equal(transition(reach('J_DURABLE'), 'RECOVER'), 'RECOVERY_PREFIX_0_STAGED');
  const progress = reach('ENDPOINT_0_STDOUT_DURABLE');
  assert.equal(durablePrefixEntries(progress), 3);
  assert.equal(transition(progress, 'RECOVER'), 'RECOVERY_PREFIX_3_STAGED');
});

test('BCHN and Lean durable endpoint-started is a conservative pre-spawn barrier', () => {
  for (const state of RISK_STATES) {
    assert.equal(reach(state), state);
    assert.equal(transition(state, 'FAIL'), RECOVERY_BLOCKED);
    assert.equal(transition(state, 'RECOVER'), RECOVERY_BLOCKED);
    assert.throws(() => transition(state, { type: 'FAIL', activeExternal: false, qualifiedContainment: true }), /exact static string/);
    assert.throws(() => transition(state, { type: 'RECOVER' }), /exact static string/);
  }
  assert.notEqual(transition(reach('ENDPOINT_2_ENDPOINT_CLOSE_OBSERVED'), 'RECOVER'), RECOVERY_BLOCKED);
  assert.notEqual(transition(reach('ENDPOINT_3_ENDPOINT_CLOSE_OBSERVED'), 'FAIL'), RECOVERY_BLOCKED);
});

test('journal events cannot be reordered, skipped, duplicated, or started before J', () => {
  assert.throws(() => transition(INITIAL_STATE, 'ENDPOINT_ENDPOINT_STARTED'), /invalid transition/);
  const scratch = reach('SCRATCH_DURABLE');
  assert.throws(() => transition(scratch, 'ENDPOINT_ENDPOINT_STARTED'), /invalid transition/);
  const input = transition(scratch, 'ENDPOINT_ENDPOINT_INPUT_DURABLE');
  assert.throws(() => transition(input, 'ENDPOINT_ENDPOINT_INPUT_DURABLE'), /invalid transition/);
  assert.throws(() => transition(input, 'ENDPOINT_STDOUT_DURABLE'), /invalid transition/);
});
