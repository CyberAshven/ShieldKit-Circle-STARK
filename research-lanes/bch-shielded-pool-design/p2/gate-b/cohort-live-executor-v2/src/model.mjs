import { canonicalJson, utf8Encode } from './canonical.mjs';
import { sha256Hex } from './sha256.mjs';

const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/';
const IDENTIFIER = 'cohort-live-executor-v2';
const STATE_SCHEMA = `${PREFIX}state/v2`;
const ROOT_SCHEMA = `${PREFIX}model-root/v2`;

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}

function fail(message) {
  throw new TypeError(`cohort-live-executor-v2 model: ${message}`);
}

function exactRecord(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be a record`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has an unclosed key set`);
  return value;
}

function exactArray(value, expected, label) {
  if (!Array.isArray(value) || value.length !== expected.length || value.some((item, index) => item !== expected[index])) {
    fail(`${label} is not exact`);
  }
  return value;
}

function digest(suffix, value) {
  return sha256Hex(utf8Encode(`${PREFIX}${suffix}\u0000${canonicalJson(value)}\n`));
}

const VARIANTS = deepFreeze(['initial', 'retry', 'abort']);
const FACTS = deepFreeze(['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D']);
const EVENTS = deepFreeze(['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D', 'CLOSE_ABORT']);
const VERDICTS = deepFreeze(['ALLOW', 'BLOCKED_EXTERNAL', 'DENY_VARIANT', 'DENY_PREREQUISITE', 'DENY_DUPLICATE', 'DENY_CLOSED', 'DENY_UNKNOWN']);

const AUTHORITY_DAG = deepFreeze({
  nodes: ['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT'],
  edges: ['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D'],
});

const TRANSITION_GRAMMAR = deepFreeze({
  schema: `${PREFIX}transition-grammar/v2`,
  identifier: IDENTIFIER,
  variants: [...VARIANTS],
  facts: [...FACTS],
  events: [...EVENTS],
  verdicts: [...VERDICTS],
  state: {
    schema: STATE_SCHEMA,
    keys: ['schema', 'identifier', 'variant', 'facts', 'phase'],
    phases: ['open', 'abort-closed'],
    orderedUniqueFacts: true,
    neverAdmitted: ['D'],
  },
  externalGuards: {
    retryQ: 'RETRY_PREDECESSOR',
    d: 'WORKER_ROWS_ROOT',
  },
  admission: {
    initial: { allowedEvents: ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D'], initialFacts: ['Q', 'LIVE_F'] },
    retry: { allowedEvents: ['MATCH_Q', 'MATCH_A'], retryQ: 'BLOCKED_EXTERNAL', stateAlwaysEmpty: true },
    abort: { allowedEvents: ['MATCH_Q', 'MATCH_A', 'CLOSE_ABORT'], allowedFacts: ['Q', 'A'], close: 'abort-closed' },
  },
  j: { grantsAuthority: false, predecessors: ['B', 'C'] },
  predecessors: {
    Q: [],
    A: ['Q'],
    LIVE_F: [],
    B: ['A', 'LIVE_F'],
    C: ['B'],
    J: ['B', 'C'],
    D: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'],
  },
});

const POLICY_AUTHORITY_BINDING = deepFreeze({
  schema: 'shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/root',
  artifactId: 'artifact:gate-b:cohort-policy-authority-v1',
  path: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-policy-authority-v1/policy-authority-root.v1.json',
  rawSha256: 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e',
  contentDigest: '9f040a5bbafc56a71dcd19081262c5411eea91e1fc35707ae4a0c2aa784c3f50',
  bindingDigest: '36ab3e7ca0594ef20c9ac1ec9f4f2ec21a3ed415815bde51d1e0c63163e4a654',
  policyDigest: '179009bd062d3207a995ee68da150e5c1622d4ad1576a68474d1d8331594e0bf',
  authorityDagDigest: '98a4ba8298744602e9979ce0e4fc28883953fecac467993d2196bcf279bbfd4d',
  liveFDigest: '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be',
});

function assertAuthorityDag(candidate = AUTHORITY_DAG) {
  exactRecord(candidate, ['nodes', 'edges'], 'authority DAG');
  if (!Array.isArray(candidate.nodes) || !Array.isArray(candidate.edges)) fail('authority DAG fields must be arrays');
  const nodes = new Set(candidate.nodes);
  if (nodes.size !== candidate.nodes.length || candidate.nodes.some((node) => typeof node !== 'string')) fail('authority DAG nodes are not unique identifiers');
  const edges = new Set();
  const adjacency = new Map(candidate.nodes.map((node) => [node, []]));
  for (const edge of candidate.edges) {
    if (typeof edge !== 'string' || !edge.includes('→')) fail('authority DAG edge is malformed');
    if (edges.has(edge)) fail('authority DAG has a duplicate edge');
    edges.add(edge);
    const parts = edge.split('→');
    if (parts.length !== 2 || !nodes.has(parts[0]) || !nodes.has(parts[1])) fail('authority DAG edge has an unknown endpoint');
    adjacency.get(parts[0]).push(parts[1]);
  }
  const visiting = new Set();
  const visited = new Set();
  const visit = (node) => {
    if (visiting.has(node)) fail('authority DAG contains a cycle');
    if (visited.has(node)) return;
    visiting.add(node);
    for (const next of adjacency.get(node)) visit(next);
    visiting.delete(node);
    visited.add(node);
  };
  for (const node of candidate.nodes) visit(node);
  exactArray(candidate.nodes, AUTHORITY_DAG.nodes, 'authority DAG nodes');
  exactArray(candidate.edges, AUTHORITY_DAG.edges, 'authority DAG edges');
  return AUTHORITY_DAG;
}

function assertTransitionGrammar(candidate = TRANSITION_GRAMMAR) {
  if (canonicalJson(candidate) !== canonicalJson(TRANSITION_GRAMMAR)) fail('transition grammar is not exact');
  return TRANSITION_GRAMMAR;
}

function requiredPredecessors(fact, variant = 'initial') {
  if (!FACTS.includes(fact)) fail('unknown fact');
  if (!VARIANTS.includes(variant)) fail('unknown variant');
  if (fact === 'Q' && variant === 'retry') return deepFreeze(['RETRY_PREDECESSOR']);
  return deepFreeze([...TRANSITION_GRAMMAR.predecessors[fact]]);
}

function authorityDagDigest() {
  assertAuthorityDag();
  return digest('authority-dag', AUTHORITY_DAG);
}

function transitionGrammarDigest() {
  assertTransitionGrammar();
  return digest('transition-grammar', TRANSITION_GRAMMAR);
}

function modelRootDigest() {
  const authority = deepFreeze({
    pRoot: POLICY_AUTHORITY_BINDING,
    semanticBindingDigest: digest('policy-authority-binding', POLICY_AUTHORITY_BINDING),
  });
  return digest('root', { schema: ROOT_SCHEMA, identifier: IDENTIFIER, authority, authorityDag: AUTHORITY_DAG, transitionGrammar: TRANSITION_GRAMMAR });
}

function assertStateForDigest(state) {
  exactRecord(state, ['schema', 'identifier', 'variant', 'facts', 'phase'], 'state');
  if (state.schema !== STATE_SCHEMA || state.identifier !== IDENTIFIER) fail('state has the wrong schema identity');
  if (!VARIANTS.includes(state.variant)) fail('state has an unknown variant');
  if (!Array.isArray(state.facts)) fail('state facts must be an array');
  if (!['open', 'abort-closed'].includes(state.phase)) fail('state has an unknown phase');
  const seen = new Set();
  for (const fact of state.facts) {
    if (!FACTS.includes(fact)) fail('state has an unknown fact');
    if (seen.has(fact)) fail('state has a duplicate fact');
    seen.add(fact);
  }
  if (seen.has('D')) fail('D is never admitted');
  if (state.variant === 'retry') {
    if (state.phase !== 'open' || state.facts.length !== 0) fail('retry state must remain empty and open');
    return state;
  }
  if (state.variant === 'abort') {
    const abortFacts = state.facts.join(',');
    if (!['', 'Q', 'Q,A'].includes(abortFacts)) fail('abort admits only the Q then A prefix');
    if (state.phase === 'abort-closed' && abortFacts !== 'Q,A') fail('closed abort requires Q and A');
    return state;
  }
  if (state.phase !== 'open') fail('only abort can close');
  if (state.facts.length === 0) return state;
  const canonicalFacts = [...state.facts].sort((left, right) => FACTS.indexOf(left) - FACTS.indexOf(right));
  if (state.facts.some((fact, index) => fact !== canonicalFacts[index])) fail('initial facts are not in canonical order');
  const index = (fact) => state.facts.indexOf(fact);
  const before = (left, right) => index(left) !== -1 && index(right) !== -1 && index(left) < index(right);
  if (seen.has('A') && !before('Q', 'A')) fail('A requires Q');
  if (seen.has('B') && !(before('A', 'B') && before('LIVE_F', 'B'))) fail('B requires A and LIVE_F');
  if (seen.has('C') && !before('B', 'C')) fail('C requires B');
  if (seen.has('J') && !(before('B', 'J') && before('C', 'J'))) fail('J requires B and C');
  return state;
}

function stateDigest(state) {
  assertStateForDigest(state);
  return digest('state', state);
}

export {
  AUTHORITY_DAG,
  TRANSITION_GRAMMAR,
  VARIANTS,
  FACTS,
  EVENTS,
  VERDICTS,
  assertAuthorityDag,
  assertTransitionGrammar,
  requiredPredecessors,
  authorityDagDigest,
  transitionGrammarDigest,
  modelRootDigest,
  stateDigest,
};
