import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { canonicalJson, semanticDigest, validateStatic } from '../validate-static.mjs';

const PACKAGE = new URL('..', import.meta.url).pathname;
const REPOSITORY_ROOT = resolve(PACKAGE, '../../../../../');
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/';
const COMPONENTS = Object.freeze([['staticDependencies', 'dependency-catalog'], ['ecocContractPrefix', 'ecoc-contract-prefix'], ['providerCausalDag', 'provider-causal-dag'], ['ownerProviderCatalog', 'owner-provider-catalog'], ['rootProviderCatalog', 'root-provider-catalog'], ['orderProviderCatalog', 'order-provider-catalog'], ['projectionProviderCatalog', 'projection-provider-catalog'], ['externalOriginProviderCatalog', 'external-origin-provider-catalog'], ['factProviderCatalog', 'fact-provider-catalog'], ['nonAuthorityBoundary', 'non-authority-boundary']]);
function tempPackage() { const root = mkdtempSync(join(tmpdir(), 'uopc-mut-')); const copy = join(root, 'package'); cpSync(PACKAGE, copy, { recursive: true }); rmSync(join(copy, 'MANIFEST.json'), { force: true }); rmSync(join(copy, 'SHA256SUMS'), { force: true }); symlinkSync(join(REPOSITORY_ROOT, 'node_modules'), join(root, 'node_modules'), 'dir'); return { root, copy }; }
function mutate(copy, fn) { const file = join(copy, 'upstream-origin-provider-contract-root.v1.json'); const value = JSON.parse(readFileSync(file, 'utf8')); fn(value); writeFileSync(file, canonicalJson(value) + '\n'); }
function rejects(label, fn) { test(label, () => { const fixture = tempPackage(); try { fn(fixture.copy); assert.throws(() => validateStatic({ root: fixture.copy, allowUnsealed: true, allowTemporaryMetadata: true })); } finally { rmSync(fixture.root, { recursive: true, force: true }); } }); }
function without(value, key) { const copy = {}; for (const [name, item] of Object.entries(value)) if (name !== key) copy[name] = item; return copy; }
function pinSnapshot(root) { const pins = {}; for (const [field] of COMPONENTS) pins[field] = root[field].contentDigest.value; pins.root = root.contentDigest.value; return pins; }
function recommit(root) { for (const [field, suffix] of COMPONENTS) root[field].contentDigest.value = semanticDigest(PREFIX + suffix, without(root[field], 'contentDigest')); root.contentDigest.value = semanticDigest(PREFIX + 'model-root', without(root, 'contentDigest')); return pinSnapshot(root); }
function causalReject(label, expected, change) { test(label, async () => { const fixture = tempPackage(); try { const rootFile = join(fixture.copy, 'upstream-origin-provider-contract-root.v1.json'); const root = JSON.parse(readFileSync(rootFile, 'utf8')); const before = pinSnapshot(root); change(root); const after = recommit(root); writeFileSync(rootFile, canonicalJson(root) + '\n'); const validatorFile = join(fixture.copy, 'validate-static.mjs'); let validator = readFileSync(validatorFile, 'utf8'); for (const key of Object.keys(before)) validator = validator.replaceAll(before[key], after[key]); writeFileSync(validatorFile, validator); const copied = await import(pathToFileURL(validatorFile).href + '?causal=' + Date.now() + Math.random()); assert.throws(() => copied.validateStatic({ root: fixture.copy, repositoryRoot: REPOSITORY_ROOT, allowUnsealed: true, allowTemporaryMetadata: true }), expected); } finally { rmSync(fixture.root, { recursive: true, force: true }); } }); }

rejects('dependency hash locator and role drift reject', (copy) => mutate(copy, (root) => { root.staticDependencies.entries[0].rawSha256 = '0'.repeat(64); }));
rejects('dependency order duplicate and omission reject', (copy) => mutate(copy, (root) => { root.staticDependencies.entries.reverse(); }));
rejects('ECOC pin drift rejects', (copy) => mutate(copy, (root) => { root.ecocContractPrefix.binding.root.contentDigest = '0'.repeat(64); }));
rejects('provider DAG edge and order drift reject', (copy) => mutate(copy, (root) => { root.providerCausalDag.edges.reverse(); }));
rejects('provider DAG static dependency insertion rejects', (copy) => mutate(copy, (root) => { root.providerCausalDag.nodes.push('P'); }));
rejects('owner scope continuity weakening rejects', (copy) => mutate(copy, (root) => { root.ownerProviderCatalog.entries[3].scope = ['LIVE_F']; }));
rejects('J owner or authority insertion rejects', (copy) => mutate(copy, (root) => { root.factProviderCatalog.entries[5].ownerProviderId = 'REQUEST_OWNER_PROVIDER'; }));
rejects('future material and null representations reject', (copy) => mutate(copy, (root) => { root.rootProviderCatalog.entries[0].rootValue = null; }));
rejects('retry reuse or automatic retry mutation rejects', (copy) => mutate(copy, (root) => { root.orderProviderCatalog.entries[0].rules.push('automatic-retry-is-allowed'); }));
rejects('A retry denial and abort prohibition mutation reject', (copy) => mutate(copy, (root) => { root.factProviderCatalog.entries[1].modelDispositionByVariant.retry = 'CATALOG_ONLY'; }));
rejects('LIVE_F template collapse rejects', (copy) => mutate(copy, (root) => { root.externalOriginProviderCatalog.entries[1].originId = 'LIVE_F'; }));
rejects('D admission execution and guard lift reject', (copy) => mutate(copy, (root) => { root.factProviderCatalog.entries[6].admissionAllowed = true; }));
rejects('projection cardinality alias and ordering reject', (copy) => mutate(copy, (root) => { root.projectionProviderCatalog.entries[0].templates[0].workloadCount = 4096; }));
rejects('catalog digest cannot become a root value', (copy) => mutate(copy, (root) => { root.rootProviderCatalog.entries[1].rootValue = root.contentDigest.value; }));
rejects('nested future-key injection rejects', (copy) => mutate(copy, (root) => { root.factProviderCatalog.entries[0].futurePreimageKeys.initial.push('privateBytes'); }));
causalReject('redigested capture scope continuity mutation reaches owner guard', /owner scope 3/, (root) => { root.ownerProviderCatalog.entries[3].scope = ['LIVE_F']; });
causalReject('redigested dispatch scope continuity mutation reaches owner guard', /owner scope 6/, (root) => { root.ownerProviderCatalog.entries[6].scope = ['D']; });
causalReject('redigested capture continuity removal reaches required schema guard', /root schema/, (root) => { delete root.ownerProviderCatalog.entries[3].ownerBindingContinuity; });
causalReject('redigested capture continuity same-class replacement reaches schema guard', /root schema/, (root) => { root.ownerProviderCatalog.entries[3].ownerBindingContinuity = 'SAME_CLASS'; });
causalReject('redigested dispatch continuity removal reaches required schema guard', /root schema/, (root) => { delete root.ownerProviderCatalog.entries[6].ownerBindingContinuity; });
causalReject('redigested dispatch continuity same-class replacement reaches schema guard', /root schema/, (root) => { root.ownerProviderCatalog.entries[6].ownerBindingContinuity = 'SAME_CLASS'; });
causalReject('redigested LIVE_F exact continuity rule mutation reaches semantic guard', /LIVE_F continuity rules/, (root) => { root.factProviderCatalog.entries[2].futureValidationRules[1] = 'LIVE_F_CAPTURE-and-LIVE_F-require-same-owner-class'; });
causalReject('redigested D exact continuity rule mutation reaches semantic guard', /D continuity rules/, (root) => { root.factProviderCatalog.entries[6].futureValidationRules[2] = 'WORKER_ROWS_ROOT-and-D-require-same-owner-class'; });
causalReject('redigested K minimum zero mutation reaches schema guard', /root schema/, (root) => { root.projectionProviderCatalog.entries[0].kWorkerRowBounds.minimum = 0; });
causalReject('redigested K maximum 4608 mutation reaches schema guard', /root schema/, (root) => { root.projectionProviderCatalog.entries[0].kWorkerRowBounds.maximum = 4608; });
causalReject('redigested equality relation mutation reaches schema guard', /root schema/, (root) => { root.projectionProviderCatalog.entries[0].targetWorkerRowCountRelation = 'EQUALS_K_WORKER_ROW_BOUNDS'; });
causalReject('redigested five-within rule removal reaches projection guard', /workload projection rules/, (root) => { root.projectionProviderCatalog.entries[0].rules.splice(2, 1); });
causalReject('redigested target rows 4096 mutation reaches schema guard', /root schema/, (root) => { root.projectionProviderCatalog.entries[0].targetWorkerRowCount = 4096; });
test('extra file and symlink closure reject', () => { const fixture = tempPackage(); try { writeFileSync(join(fixture.copy, 'extra.txt'), 'x'); assert.throws(() => validateStatic({ root: fixture.copy, allowUnsealed: true, allowTemporaryMetadata: true })); rmSync(join(fixture.copy, 'extra.txt')); symlinkSync(join(fixture.copy, 'README.md'), join(fixture.copy, 'linked.md')); assert.throws(() => validateStatic({ root: fixture.copy, allowUnsealed: true, allowTemporaryMetadata: true })); } finally { rmSync(fixture.root, { recursive: true, force: true }); } });
