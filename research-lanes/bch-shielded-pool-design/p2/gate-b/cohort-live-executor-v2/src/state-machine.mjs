import { EVENTS, FACTS, TRANSITION_GRAMMAR, VARIANTS, requiredPredecessors, stateDigest } from './model.mjs';

const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/';
const IDENTIFIER = 'cohort-live-executor-v2';
const STATE_SCHEMA = `${PREFIX}state/v2`;
const FACTS_ORDER = FACTS;
const EVENT_FACT = Object.freeze({
  MATCH_Q: 'Q',
  MATCH_A: 'A',
  MATCH_LIVE_F: 'LIVE_F',
  MATCH_B: 'B',
  MATCH_C: 'C',
  MATCH_J: 'J',
  MATCH_D: 'D',
});

function fail(message) {
  throw new TypeError(`cohort-live-executor-v2 state: ${message}`);
}

function freezeState(variant, facts, phase = 'open') {
  const orderedFacts = [...facts].sort((left, right) => FACTS_ORDER.indexOf(left) - FACTS_ORDER.indexOf(right));
  return Object.freeze({ schema: STATE_SCHEMA, identifier: IDENTIFIER, variant, facts: Object.freeze(orderedFacts), phase });
}

function assertState(state) {
  stateDigest(state);
  return freezeState(state.variant, state.facts, state.phase);
}

function emptyState(variant = 'initial') {
  if (!VARIANTS.includes(variant)) fail('unknown variant');
  return freezeState(variant, []);
}

function eventAllowedByVariant(variant, event) {
  return TRANSITION_GRAMMAR.admission[variant].allowedEvents.includes(event);
}

function guardTransition(state, event) {
  const current = assertState(state);
  if (!EVENTS.includes(event)) return 'DENY_UNKNOWN';
  if (current.phase === 'abort-closed') return 'DENY_CLOSED';
  if (!eventAllowedByVariant(current.variant, event)) return 'DENY_VARIANT';
  if (event === 'MATCH_D') {
    const internal = requiredPredecessors('D').filter((predecessor) => predecessor !== 'WORKER_ROWS_ROOT');
    return internal.every((predecessor) => current.facts.includes(predecessor)) ? 'BLOCKED_EXTERNAL' : 'DENY_PREREQUISITE';
  }
  if (event === 'CLOSE_ABORT') return current.facts.join(',') === 'Q,A' ? 'ALLOW' : 'DENY_PREREQUISITE';
  const fact = EVENT_FACT[event];
  if (current.facts.includes(fact)) return 'DENY_DUPLICATE';
  const predecessors = requiredPredecessors(fact, current.variant);
  if (predecessors.some((predecessor) => !current.facts.includes(predecessor))) {
    return fact === 'Q' && current.variant === 'retry' ? 'BLOCKED_EXTERNAL' : 'DENY_PREREQUISITE';
  }
  return 'ALLOW';
}

function transition(state, event) {
  const current = assertState(state);
  const verdict = guardTransition(current, event);
  if (verdict !== 'ALLOW') return Object.freeze({ verdict, state: current });
  if (event === 'CLOSE_ABORT') return Object.freeze({ verdict, state: freezeState('abort', current.facts, 'abort-closed') });
  return Object.freeze({ verdict, state: freezeState(current.variant, [...current.facts, EVENT_FACT[event]]) });
}

function replay(variant, events) {
  if (!Array.isArray(events)) fail('replay events must be an array');
  let state = emptyState(variant);
  const verdicts = [];
  for (const event of events) {
    const step = transition(state, event);
    verdicts.push(step.verdict);
    state = step.state;
  }
  return Object.freeze({ state, verdicts: Object.freeze(verdicts), stateDigest: stateDigest(state) });
}

export { emptyState, assertState, guardTransition, transition, replay };
