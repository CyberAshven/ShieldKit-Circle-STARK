import assert from 'node:assert/strict';
import test from 'node:test';
import { stateDigest } from '../src/model.mjs';
import { assertState, emptyState, guardTransition, replay, transition } from '../src/state-machine.mjs';

function apply(state, event, verdict = 'ALLOW') {
  const step = transition(state, event);
  assert.equal(step.verdict, verdict, event);
  return step.state;
}

test('initial admits LIVE_F before Q and after Q through J', () => {
  for (const events of [
    ['MATCH_LIVE_F', 'MATCH_Q', 'MATCH_A', 'MATCH_B', 'MATCH_C', 'MATCH_J'],
    ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J'],
  ]) {
    const trace = replay('initial', events);
    assert.deepEqual(trace.verdicts, Array(events.length).fill('ALLOW'));
    assert.equal(trace.state.facts.at(-1), 'J');
    assert.doesNotThrow(() => assertState(trace.state));
  }
});

test('abort permits Q then A then closes permanently', () => {
  let state = emptyState('abort');
  state = apply(state, 'MATCH_Q');
  state = apply(state, 'MATCH_A');
  state = apply(state, 'CLOSE_ABORT');
  assert.equal(state.phase, 'abort-closed');
  for (const event of ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D', 'CLOSE_ABORT']) {
    assert.equal(guardTransition(state, event), 'DENY_CLOSED');
  }
});

test('retry and D are externally blocked without mutation', () => {
  const retry = emptyState('retry');
  assert.equal(guardTransition(retry, 'MATCH_Q'), 'BLOCKED_EXTERNAL');
  assert.equal(guardTransition(retry, 'MATCH_A'), 'DENY_PREREQUISITE');
  assert.equal(guardTransition(retry, 'MATCH_LIVE_F'), 'DENY_VARIANT');
  const retryResult = transition(retry, 'MATCH_Q');
  assert.notStrictEqual(retryResult.state, retry);
  assert.deepEqual(retryResult.state, retry);
  const initial = replay('initial', ['MATCH_LIVE_F', 'MATCH_Q', 'MATCH_A', 'MATCH_B', 'MATCH_C', 'MATCH_J']).state;
  assert.equal(guardTransition(initial, 'MATCH_D'), 'BLOCKED_EXTERNAL');
  const dResult = transition(initial, 'MATCH_D');
  assert.notStrictEqual(dResult.state, initial);
  assert.deepEqual(dResult.state, initial);
  assert.equal(guardTransition(emptyState('initial'), 'MATCH_D'), 'DENY_PREREQUISITE');
  assert.equal(guardTransition(emptyState('abort'), 'MATCH_D'), 'DENY_VARIANT');
});

test('ordering, duplicates, unknowns, D injection, and invalid continuations fail closed', () => {
  const q = apply(emptyState('initial'), 'MATCH_Q');
  assert.equal(guardTransition(q, 'MATCH_B'), 'DENY_PREREQUISITE');
  assert.equal(guardTransition(q, 'MATCH_Q'), 'DENY_DUPLICATE');
  assert.equal(guardTransition(q, 'NOPE'), 'DENY_UNKNOWN');
  assert.throws(() => assertState({ ...q, facts: ['Q', 'A', 'A'] }), /duplicate/);
  assert.throws(() => assertState({ ...q, facts: ['Q', 'LIVE_F', 'A'] }), /canonical order/);
  assert.throws(() => assertState({ ...q, facts: ['Q', 'B', 'A', 'LIVE_F'] }), /canonical order/);
  assert.throws(() => assertState({ ...q, facts: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D'] }), /never admitted/);
  assert.throws(() => assertState({ ...q, phase: 'abort-closed' }), /only abort/);
});

test('guards ignore forged arguments and returned states do not alias caller state', () => {
  const caller = { schema: 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/state/v2', identifier: 'cohort-live-executor-v2', variant: 'initial', facts: ['LIVE_F'], phase: 'open' };
  const checked = assertState(caller);
  assert.notStrictEqual(checked, caller);
  assert.equal(guardTransition(caller, 'MATCH_A', { satisfy: 'Q' }), 'DENY_PREREQUISITE');
  const step = transition(caller, 'MATCH_A');
  caller.facts.push('Q');
  assert.deepEqual(step.state.facts, ['LIVE_F']);
  assert.throws(() => step.state.facts.push('Q'), /object is not extensible/);
});

test('replay neither mutates its event input nor partially mutates a caller-visible state', () => {
  const events = Object.freeze(['MATCH_LIVE_F', 'MATCH_B', 'MATCH_Q', 'MATCH_A', 'MATCH_B', 'MATCH_C', 'MATCH_J']);
  const before = [...events];
  const trace = replay('initial', events);
  assert.deepEqual(events, before);
  assert.deepEqual(trace.verdicts, ['ALLOW', 'DENY_PREREQUISITE', 'ALLOW', 'ALLOW', 'ALLOW', 'ALLOW', 'ALLOW']);
  assert.deepEqual(trace.state.facts, ['Q', 'A', 'LIVE_F', 'B', 'C', 'J']);
});

test('state digests bind order and phase', () => {
  const first = replay('initial', ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F']).state;
  const second = replay('initial', ['MATCH_LIVE_F', 'MATCH_Q', 'MATCH_A']).state;
  const abortOpen = replay('abort', ['MATCH_Q', 'MATCH_A']).state;
  const abortClosed = replay('abort', ['MATCH_Q', 'MATCH_A', 'CLOSE_ABORT']).state;
  assert.equal(stateDigest(first), stateDigest(second));
  assert.notEqual(stateDigest(abortOpen), stateDigest(abortClosed));
});
