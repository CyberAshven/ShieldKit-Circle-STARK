import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import * as model from '../src/model.mjs';

const expectedExports = [
  'AUTHORITY_DAG', 'DEPENDENCY_CATALOG', 'EXTERNAL_ORIGINS', 'FACT_CATALOG', 'STATE_GRAMMAR', 'DISPOSITIONS',
  'assertAuthorityDag', 'assertDependencyCatalog', 'assertExternalOrigins', 'assertFactCatalog', 'assertStateGrammar',
  'requiredPredecessors', 'ownerOf', 'availabilityOf', 'authorityDisposition', 'authorityDagDigest',
  'dependencyCatalogDigest', 'externalOriginsDigest', 'factCatalogDigest', 'stateGrammarDigest', 'modelRootDigest'
].sort();

function rootDocument() {
  return JSON.parse(readFileSync(new URL('../authority-binding-root.v1.json', import.meta.url)));
}

function dagClone() {
  return { nodes: [...model.AUTHORITY_DAG.nodes], edges: [...model.AUTHORITY_DAG.edges] };
}

test('pure model has exactly the approved export surface', () => {
  assert.deepEqual(Object.keys(model), expectedExports);
  assert.equal(Object.keys(model).some((name) => /(?:transition|replay|construct|admit)/i.test(name)), false);
});

test('pinned authority DAG is exact 17 nodes and 22 edges', () => {
  assert.equal(model.AUTHORITY_DAG.nodes.length, 17);
  assert.equal(model.AUTHORITY_DAG.edges.length, 22);
  assert.equal(model.AUTHORITY_DAG.edges.includes('RETRY_PREDECESSOR→Q'), false);
  assert.equal(model.AUTHORITY_DAG.edges.includes('B→LIVE_F_CAPTURE'), false);
  assert.equal(model.AUTHORITY_DAG.edges.includes('P→J'), false);
  assert.equal(model.assertAuthorityDag(), model.AUTHORITY_DAG);
});

test('static dependencies are exact and cohort-freeze is not a top-level dependency', () => {
  assert.deepEqual(model.DEPENDENCY_CATALOG.entries.map((entry) => entry.id), ['R', 'K', 'F', 'P', 'V2']);
  assert.equal(model.DEPENDENCY_CATALOG.entries.some((entry) => entry.id === 'EPOCH'), false);
  assert.deepEqual(Object.fromEntries(model.DEPENDENCY_CATALOG.entries.map((entry) => [entry.id, entry.pins.map((pin) => pin.id)])), {
    R: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-digest', 'runtime-authority-digest'],
    K: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'manifest-package-root', 'manifest-root', 'entries-root', 'binding-digest', 'worker-row-schema-raw-sha256', 'dispatch-plan-schema-raw-sha256', 'worker-row-endpoint-id-aliases'],
    F: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-digest', 'source-native-semantic-digest', 'freeze-artifact-semantic-digest', 'ordered-leaf-ids', 'frozen-four-surface-order'],
    P: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-root', 'policy-content-digest', 'causal-dag-root', 'live-f-template-digest', 'worker-alias-map', 'q-initial-template-digest', 'q-retry-template-digest', 'q-abort-template-digest', 'a-initial-template-digest', 'a-retry-template-digest', 'a-abort-template-digest', 'b-subject-template-digest', 'b-envelope-template-digest'],
    V2: ['root-content-digest', 'manifest-raw-sha256', 'sha256sums-raw-sha256', 'validator-raw-sha256', 'manifest-roster-digest', 'p-semantic-binding-digest', 'authority-dag-digest', 'transition-grammar-digest']
  });
  const k = model.DEPENDENCY_CATALOG.entries.find((entry) => entry.id === 'K');
  assert.equal(k.pins.some((pin) => pin.value.includes('engine:')), false);
  const p = model.DEPENDENCY_CATALOG.entries.find((entry) => entry.id === 'P');
  assert.equal(p.pins.find((pin) => pin.id === 'worker-alias-map').value, 'native=>engine:native,libauth=>engine:libauth,bchn=>engine:bchn,leanbch-primary=>engine:leanbch:primary,leanbch-secondary=>engine:leanbch:secondary');
  const f = model.DEPENDENCY_CATALOG.entries.find((entry) => entry.id === 'F');
  assert.equal(f.pins.some((pin) => pin.id === 'frozen-four-surface-order'), true);
});

test('external origins and facts have exact non-authorizing rosters', () => {
  assert.deepEqual(model.EXTERNAL_ORIGINS.entries.map((entry) => entry.id), ['RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKER_ROWS_ROOT']);
  assert.deepEqual(model.FACT_CATALOG.entries.map((entry) => entry.id), ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D']);
  assert.equal([...model.EXTERNAL_ORIGINS.entries, ...model.FACT_CATALOG.entries].every((entry) => entry.grantsAuthority === false), true);
  assert.equal(model.EXTERNAL_ORIGINS.entries.some((entry) => ['A', 'B', 'C', 'D', 'J', 'Q', 'LIVE_F', 'F', 'LIVE_F_TEMPLATE'].includes(entry.id)), false);
});

test('every fact covers closed variant predecessor maps', () => {
  for (const entry of model.FACT_CATALOG.entries) {
    assert.deepEqual(Object.keys(entry.statePredecessors).sort(), ['abort', 'initial', 'retry'], entry.id);
    assert.deepEqual(Object.keys(entry.originRequirements).sort(), ['abort', 'initial', 'retry'], entry.id);
    assert.equal(entry.variants.every((variant) => ['initial', 'retry', 'abort'].includes(variant)), true);
  }
  assert.deepEqual(model.requiredPredecessors('Q', 'retry'), ['RETRY_PREDECESSOR']);
  assert.deepEqual(model.requiredPredecessors('A', 'retry'), ['Q']);
  assert.deepEqual(model.requiredPredecessors('D'), ['B', 'C', 'J', 'WORKER_ROWS_ROOT']);
});

test('retry, capture, D, and J preserve their external/non-authorizing boundaries', () => {
  const facts = Object.fromEntries(model.FACT_CATALOG.entries.map((entry) => [entry.id, entry]));
  assert.deepEqual(facts.LIVE_F.originRequirements.initial, ['LIVE_F_CAPTURE']);
  assert.equal(facts.LIVE_F.originRequirements.initial.includes('LIVE_F_TEMPLATE'), false);
  assert.equal(facts.LIVE_F.originRequirements.initial.includes('F'), false);
  assert.deepEqual(facts.B.statePredecessors.initial, ['A', 'LIVE_F']);
  assert.deepEqual(facts.J.statePredecessors.initial, ['B', 'C']);
  assert.equal(facts.J.grantsAuthority, false);
  assert.deepEqual(facts.D.originRequirements.initial, ['WORKER_ROWS_ROOT']);
  assert.equal(model.authorityDisposition('RETRY_PREDECESSOR'), 'BLOCKED_EXTERNAL');
  assert.equal(model.authorityDisposition('LIVE_F_CAPTURE'), 'UNAVAILABLE_EXTERNAL');
  assert.equal(model.authorityDisposition('D'), 'BLOCKED_EXTERNAL');
});

test('owner and availability queries are declarative only', () => {
  assert.equal(model.ownerOf('Q'), 'unavailable-request-owner');
  assert.equal(model.ownerOf('LIVE_F_CAPTURE'), 'unavailable-private-capture-owner');
  assert.equal(model.availabilityOf('LIVE_F_CAPTURE'), 'unavailable');
  assert.equal(model.availabilityOf('LIVE_F'), 'abstract');
  assert.throws(() => model.ownerOf('unknown'));
  assert.throws(() => model.requiredPredecessors('unknown'));
  assert.throws(() => model.requiredPredecessors('Q', 'unknown'));
});

test('cardinality and alias separation stay unresolved', () => {
  const grammar = model.STATE_GRAMMAR;
  assert.deepEqual(grammar.aliasSeparation.workerRowEndpointIds, ['native', 'libauth', 'bchn', 'leanbch-primary', 'leanbch-secondary']);
  assert.deepEqual(grammar.aliasSeparation.frozenEngineOrder, ['native', 'libauth', 'bchn', 'leanbch']);
  assert.equal(grammar.aliasSeparation.mayInterchange, false);
  assert.equal(grammar.aliasSeparation.acceptedRowOrder, null);
  assert.equal(grammar.aliasSeparation.workerRowsRootDomain, null);
  const root = rootDocument();
  assert.equal(root.cardinalitySeparation.workloadTemplate.value, 4608);
  assert.equal(root.cardinalitySeparation.workerRowSchema.maximum, 4096);
  assert.equal(root.cardinalitySeparation.projection.mayEquate, false);
  assert.equal(root.cardinalitySeparation.projection.mayDerive, false);
});

test('model-root digest is checked into the canonical envelope', () => {
  const root = rootDocument();
  assert.equal(root.contentDigest.value, model.modelRootDigest());
  assert.equal(root.contentDigest.domain, 'shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/root');
  assert.equal(Object.isFrozen(model.AUTHORITY_DAG), true);
  assert.equal(Object.isFrozen(model.FACT_CATALOG), true);
});

test('DAG assertion rejects hidden, symbol, accessor, and extended-array surfaces', () => {
  const hidden = dagClone();
  Object.defineProperty(hidden, 'hidden', { value: true });
  assert.throws(() => model.assertAuthorityDag(hidden));
  const symbol = dagClone();
  symbol[Symbol('hidden')] = true;
  assert.throws(() => model.assertAuthorityDag(symbol));
  const accessor = dagClone();
  Object.defineProperty(accessor, 'hidden', { enumerable: true, get() { return true; } });
  assert.throws(() => model.assertAuthorityDag(accessor));
  const extended = dagClone();
  extended.nodes.extra = 'N';
  assert.throws(() => model.assertAuthorityDag(extended));
});

test('assertion APIs reject semantic mutations', () => {
  const dag = dagClone();
  dag.edges.pop();
  assert.throws(() => model.assertAuthorityDag(dag));
  const facts = JSON.parse(JSON.stringify(model.FACT_CATALOG));
  facts.entries[5].grantsAuthority = true;
  assert.throws(() => model.assertFactCatalog(facts));
  const origins = JSON.parse(JSON.stringify(model.EXTERNAL_ORIGINS));
  origins.entries.pop();
  assert.throws(() => model.assertExternalOrigins(origins));
  const grammar = JSON.parse(JSON.stringify(model.STATE_GRAMMAR));
  grammar.retry.stateFacts = ['Q'];
  assert.throws(() => model.assertStateGrammar(grammar));
  const dependencies = JSON.parse(JSON.stringify(model.DEPENDENCY_CATALOG));
  [dependencies.entries[0].pins[0], dependencies.entries[0].pins[1]] = [dependencies.entries[0].pins[1], dependencies.entries[0].pins[0]];
  assert.throws(() => model.assertDependencyCatalog(dependencies));
  const malformedDependencies = { ...model.DEPENDENCY_CATALOG, entries: {} };
  assert.throws(() => model.assertDependencyCatalog(malformedDependencies));
});
