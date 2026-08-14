import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  ENDPOINT_ORDER,
  EXTERNALS,
  MODULE_WORKERS,
  PACKAGE,
  REPO,
  buildExternalEndpoint,
  buildModuleEndpoint,
  validateEndpointUnion,
  validateLeafBinding
} from '../semantic-validator.mjs';

const E_ROOT = path.resolve(REPO, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-endpoint-modules-v1');
const X_ROOT = path.resolve(REPO, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-materialized-v1');
const root = JSON.parse(fs.readFileSync(path.join(PACKAGE, 'runtime-binding-root.v1.json'), 'utf8'));

const union = () => ({
  expectedRows: 4608,
  order: [...ENDPOINT_ORDER],
  entries: [
    buildModuleEndpoint(E_ROOT, 'engine:native'),
    buildModuleEndpoint(E_ROOT, 'engine:libauth'),
    buildExternalEndpoint(X_ROOT, 'engine:bchn'),
    buildExternalEndpoint(X_ROOT, 'engine:leanbch:primary'),
    buildExternalEndpoint(X_ROOT, 'engine:leanbch:secondary')
  ]
});

const mutant = (label, edit) => test(`causal endpoint-boundary mutant rejects: ${label}`, () => {
  const value = union();
  edit(value);
  assert.throws(() => validateEndpointUnion({ endpointUnion: value }), /cohort-runtime-binding-v1/);
});

test('baseline concrete endpoint union is semantically accepted', () => {
  assert.doesNotThrow(() => validateEndpointUnion({ endpointUnion: union() }));
});

mutant('row cardinality', value => { value.expectedRows = 4607; });
mutant('ordered roster', value => { value.order[2] = value.order[3]; });
mutant('module/external discriminant', value => { value.entries[0].kind = 'external'; });
mutant('external/module discriminant', value => { value.entries[2].kind = 'module'; });
mutant('module workdir template', value => { value.entries[0].workdir.template = 'work/04-lean-secondary'; });
mutant('future attempt-root mode', value => { value.entries[1].workdir.mode = 493; });
mutant('WorkerRow exact key roster', value => { value.entries[0].workerRow.exactKeys[0] = 'forged'; });
mutant('WorkerRow forbidden key roster', value => { value.entries[1].workerRow.forbiddenKeys.pop(); });
mutant('brand transit precondition', value => { value.entries[0].brandPrecondition.brandTransit = 'allowed'; });
mutant('module monotonic deadline', value => { value.entries[1].deadline.clock = 'wall'; });
mutant('combined output cap', value => { value.entries[0].output.combinedCapBytes = 134217727; });
mutant('BCHN replacement environment', value => { value.entries[2].environment.BCHN_DEBUG = '1'; });
mutant('Lean shared deadline policy', value => { value.entries[3].deadline.policy = 'secondary-resets-deadline'; });
mutant('direct loader argv', value => { value.entries[2].argv.values[0] = '/usr/bin/loader'; });
mutant('DSO closure cardinality', value => { value.entries[2].dsoClosure.count = 16; });
mutant('host fallback', value => { value.entries[4].hostFallback = 'allowed'; });
mutant('provenance-only image workdir', value => { value.entries[4].imageWorkdir.path = 42; });
mutant('extra endpoint key', value => { value.entries[2].extra = true; });

test('native versus R digest domains cannot be confused', () => {
  const n = structuredClone(root.packageClosure.leaves[0]);
  n.nativeManifest.contentDigest = '0'.repeat(64);
  assert.throws(() => validateLeafBinding(PACKAGE, n), /N native manifest binding/);
  const e = structuredClone(root.packageClosure.leaves[1]);
  e.nativeManifest.rosterDomain = 'shieldkit-labs/p2/gate-b/cohort-runtime-binding/v1/file-content';
  assert.throws(() => validateLeafBinding(PACKAGE, e), /E native manifest\/runtime binding/);
});

test('X native manifest has no fabricated content field or roster domain', () => {
  const x = structuredClone(root.packageClosure.leaves[2]);
  x.nativeManifest.contentField = 'present';
  assert.throws(() => validateLeafBinding(PACKAGE, x), /X native manifest binding/);
});
