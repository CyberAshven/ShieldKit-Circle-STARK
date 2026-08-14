import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AUTHORITY_DAG,
  EVENTS,
  FACTS,
  TRANSITION_GRAMMAR,
  VARIANTS,
  VERDICTS,
  assertAuthorityDag,
  assertTransitionGrammar,
  authorityDagDigest,
  requiredPredecessors,
  transitionGrammarDigest,
} from '../src/model.mjs';

test('the P-authority projection is the exact 17-node 22-edge prefix', () => {
  assert.deepEqual(AUTHORITY_DAG.nodes, ['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT']);
  assert.equal(AUTHORITY_DAG.edges.length, 22);
  assert.doesNotThrow(() => assertAuthorityDag());
  assert.match(authorityDagDigest(), /^[0-9a-f]{64}$/);
});

test('DAG validation rejects missing, extra, reversed, duplicate, cyclic, and downstream authority edges', () => {
  const clone = () => ({ nodes: [...AUTHORITY_DAG.nodes], edges: [...AUTHORITY_DAG.edges] });
  const missing = clone(); missing.edges.pop();
  const extra = clone(); extra.edges.push('J→JOURNAL');
  const reversed = clone(); reversed.edges[0] = 'R→N';
  const duplicate = clone(); duplicate.edges[1] = duplicate.edges[0];
  const cycle = clone(); cycle.edges[21] = 'D→Q';
  for (const candidate of [missing, extra, reversed, duplicate, cycle]) assert.throws(() => assertAuthorityDag(candidate));
});

test('grammar fixes the vocabulary and keeps J authority-free', () => {
  assert.deepEqual(VARIANTS, ['initial', 'retry', 'abort']);
  assert.deepEqual(FACTS, ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D']);
  assert.deepEqual(EVENTS, ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D', 'CLOSE_ABORT']);
  assert.deepEqual(VERDICTS, ['ALLOW', 'BLOCKED_EXTERNAL', 'DENY_VARIANT', 'DENY_PREREQUISITE', 'DENY_DUPLICATE', 'DENY_CLOSED', 'DENY_UNKNOWN']);
  assert.deepEqual(requiredPredecessors('J'), ['B', 'C']);
  assert.deepEqual(requiredPredecessors('D'), ['B', 'C', 'J', 'WORKER_ROWS_ROOT']);
  assert.deepEqual(requiredPredecessors('LIVE_F'), []);
  assert.deepEqual(TRANSITION_GRAMMAR.j, { grantsAuthority: false, predecessors: ['B', 'C'] });
  assert.deepEqual(requiredPredecessors('Q', 'retry'), ['RETRY_PREDECESSOR']);
  assert.doesNotThrow(() => assertTransitionGrammar());
  assert.match(transitionGrammarDigest(), /^[0-9a-f]{64}$/);
});

test('grammar rejects prerequisite changes, J authority injection, and external-guard bypass', () => {
  const mutate = (mutator) => {
    const candidate = JSON.parse(JSON.stringify(TRANSITION_GRAMMAR));
    mutator(candidate);
    assert.throws(() => assertTransitionGrammar(candidate));
  };
  mutate((grammar) => { grammar.predecessors.B = ['A']; });
  mutate((grammar) => { grammar.predecessors.J = ['B', 'C', 'P']; });
  mutate((grammar) => { grammar.j.grantsAuthority = true; });
  mutate((grammar) => { grammar.externalGuards.d = 'SATISFIED'; });
  mutate((grammar) => { grammar.admission.retry.allowedEvents.push('MATCH_LIVE_F'); });
});
