import Ajv2020 from 'ajv/dist/2020.js';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, semanticDigest, sha256, validateStatic } from '../validate-static.mjs';

const fixtureParent = fileURLToPath(new URL('../../', import.meta.url));
const prepareUnsealedCopy = destination => {
  cpSync(new URL('..', import.meta.url), destination, { recursive: true });
  rmSync(join(destination, 'MANIFEST.json'), { force: true });
  rmSync(join(destination, 'SHA256SUMS'), { force: true });
  for (const dir of ['', 'schemas', 'test']) chmodSync(join(destination, dir), 0o755);
};
const schemas = readdirSync(new URL('../schemas/', import.meta.url)).map(name => JSON.parse(readFileSync(new URL(`../schemas/${name}`, import.meta.url))));
const independentCanonicalJson = value => Array.isArray(value)
  ? `[${value.map(independentCanonicalJson).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${independentCanonicalJson(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const independentSha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const kat = JSON.parse(readFileSync(new URL('./digest.kat.json', import.meta.url), 'utf8'));
assert.equal(kat.fileDigest.algorithm, 'sha256');
assert.equal(kat.fileDigest.domain, 'shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/file');
assert.equal(kat.fileDigest.frame, 'utf8(domain)||0x00||raw-file-bytes');
assert.deepEqual(kat.fileDigest.cases.map(item => item.name), ['EMPTY', 'FF_00_80']);
for (const item of kat.fileDigest.cases) {
  const framed = Buffer.concat([Buffer.from(kat.fileDigest.domain), Buffer.from([0]), Buffer.from(item.bytesHex, 'hex')]);
  assert.equal(independentSha256(framed), item.expectedSha256);
  assert.equal(sha256(framed), item.expectedSha256);
}
assert.equal(kat.semanticDigest.algorithm, 'sha256');
assert.equal(kat.semanticDigest.canonicalization, 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1');
assert.equal(kat.semanticDigest.domain, 'shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root');
assert.equal(kat.semanticDigest.frame, 'utf8(domain)||0x00||canonical-json-utf8-lf-v1');
assert.deepEqual(kat.semanticDigest.cases.map(item => item.name), ['KEY_ORDER_B_A', 'KEY_ORDER_A_B', 'UNICODE_NFC_NFD_EMOJI', 'ARRAY_ORDER_FORWARD', 'ARRAY_ORDER_REVERSE']);
for (const item of kat.semanticDigest.cases) {
  const value = JSON.parse(item.inputJson);
  const framed = Buffer.concat([Buffer.from(kat.semanticDigest.domain), Buffer.from([0]), Buffer.from(`${independentCanonicalJson(value)}\n`)]);
  assert.equal(independentSha256(framed), item.expectedSha256);
  assert.equal(semanticDigest(kat.semanticDigest.domain, value), item.expectedSha256);
}
assert.equal(kat.semanticDigest.cases[0].expectedSha256, kat.semanticDigest.cases[1].expectedSha256);
assert.notEqual(kat.semanticDigest.cases[3].expectedSha256, kat.semanticDigest.cases[4].expectedSha256);
validateStatic();
const fixture = mkdtempSync(join(fixtureParent, '.shieldkit-uopc-map-validator-'));
try {
  prepareUnsealedCopy(join(fixture, 'pkg'));
  validateStatic({ packageRoot: join(fixture, 'pkg'), allowUnsealed: true, repositoryRoot: '/home/toorik/Projects/ShieldKit-LABS' });
} finally { rmSync(fixture, { recursive: true, force: true }); }
const sealedFixture = mkdtempSync(join(fixtureParent, '.shieldkit-uopc-map-sealed-'));
try {
  const pkg = join(sealedFixture, 'pkg'); cpSync(new URL('..', import.meta.url), pkg, { recursive: true }); for (const dir of ['', 'schemas', 'test']) chmodSync(join(pkg, dir), 0o755);
  const roster = ['COMMAND.txt','README.md','upstream-provider-source-map-root.v1.json','schemas/b1-reentry-boundary.v1.schema.json','schemas/dependency-catalog.v1.schema.json','schemas/digest.v1.schema.json','schemas/interface-source-map.v1.schema.json','schemas/manifest.v1.schema.json','schemas/mapping-dag.v1.schema.json','schemas/model-root.v1.schema.json','schemas/non-authority-boundary.v1.schema.json','schemas/source-reference-catalog.v1.schema.json','schemas/uopc-contract-prefix.v1.schema.json','validate-static.mjs','test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/static.test.mjs'];
  const domain='shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1', entries=roster.map(locator=>{const raw=readFileSync(join(pkg,locator));return {bytes:raw.length,fileDigest:sha256(Buffer.concat([Buffer.from(`${domain}/file`),Buffer.from([0]),raw])),locator,sha256:sha256(raw)}}), manifest={schema:`${domain}/manifest/v1`,format:`${domain}/manifest/1`,package:'cohort-upstream-provider-source-map-v1',entryCount:18,entries,rosterDigest:semanticDigest(`${domain}/manifest-roster`,roster)};
  const manifestPath=join(pkg,'MANIFEST.json'), sumsPath=join(pkg,'SHA256SUMS'); writeFileSync(manifestPath,`${canonicalJson(manifest)}\n`); writeFileSync(sumsPath,`${[...entries.map(e=>`${e.sha256}  ${e.locator}`),`${sha256(readFileSync(manifestPath))}  MANIFEST.json`].join('\n')}\n`); const goodManifest=readFileSync(manifestPath),goodSums=readFileSync(sumsPath); validateStatic({packageRoot:pkg,allowUnsealed:false,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'});
  rmSync(sumsPath); assert.throws(()=>validateStatic({packageRoot:pkg,allowUnsealed:false,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),/PARTIAL_ENVELOPE/); writeFileSync(sumsPath,goodSums);
  const drift=JSON.parse(goodManifest); drift.entries[0].bytes++; writeFileSync(manifestPath,`${canonicalJson(drift)}\n`); assert.throws(()=>validateStatic({packageRoot:pkg,allowUnsealed:false,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),/MANIFEST_ENTRY:COMMAND.txt/); writeFileSync(manifestPath,goodManifest);
  const rosterDrift=JSON.parse(goodManifest); rosterDrift.rosterDigest='0'.repeat(64); writeFileSync(manifestPath,`${canonicalJson(rosterDrift)}\n`); assert.throws(()=>validateStatic({packageRoot:pkg,allowUnsealed:false,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),/ROSTER_DIGEST/); writeFileSync(manifestPath,goodManifest);
  writeFileSync(sumsPath,goodSums.subarray(0,goodSums.length-1)); assert.throws(()=>validateStatic({packageRoot:pkg,allowUnsealed:false,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),/CHECKSUM_ROWS/); writeFileSync(sumsPath,goodSums);
  writeFileSync(manifestPath,` ${goodManifest}`); assert.throws(()=>validateStatic({packageRoot:pkg,allowUnsealed:false,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),/MANIFEST_BYTES:NONCANONICAL/); writeFileSync(manifestPath,goodManifest);
} finally { rmSync(sealedFixture,{recursive:true,force:true}); }
const domains = { staticDependencies:'dependency-catalog', sourceReferenceCatalog:'source-reference-catalog', interfaceSourceMap:'interface-source-map', mappingDag:'mapping-dag', uopcContractPrefix:'uopc-contract-prefix', nonAuthorityBoundary:'non-authority-boundary', b1ReentryBoundary:'b1-reentry-boundary' };
const sibling = { staticDependencies:'dependencyCatalogDigest', sourceReferenceCatalog:'sourceReferenceCatalogDigest', interfaceSourceMap:'interfaceSourceMapDigest', mappingDag:'mappingDagDigest', uopcContractPrefix:'uopcContractPrefixDigest', nonAuthorityBoundary:'nonAuthorityBoundaryDigest', b1ReentryBoundary:'b1ReentryBoundaryDigest' };
for (const [component, domain] of Object.entries(domains)) {
  const tmp = mkdtempSync(join(fixtureParent, '.shieldkit-uopc-map-semantic-'));
  try {
    prepareUnsealedCopy(join(tmp, 'pkg'));
    const file = join(tmp, 'pkg', 'upstream-provider-source-map-root.v1.json'), value = JSON.parse(readFileSync(file));
    if (component === 'staticDependencies') [value[component].entries[0], value[component].entries[1]] = [value[component].entries[1], value[component].entries[0]];
    else if (component === 'sourceReferenceCatalog') value[component].entries[0].kind = 'JSON_SCHEMA_DOCUMENT';
    else if (component === 'interfaceSourceMap') value[component].entries[0].missingSourceKinds[0] = 'MUTATED_SOURCE';
    else if (component === 'mappingDag') value[component].edges[0] = 'RETRY_TARGET_MAP→RETRY_PREDECESSOR_MAP';
    else if (component === 'uopcContractPrefix') value[component].binding.root.rawSha256 = '0'.repeat(64);
    else if (component === 'nonAuthorityBoundary') value[component].forbiddenValueBearingMemberNames[0] = 'mutatedRoot';
    else value[component].nextGate = `${value[component].nextGate} mutated`;
    value[component].contentDigest.value = semanticDigest(`shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/${domain}`, value[component]);
    value[sibling[component]].value = value[component].contentDigest.value;
    value.contentDigest.value = semanticDigest('shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root', value);
    writeFileSync(file, `${canonicalJson(value)}\n`);
    assert.throws(() => validateStatic({ packageRoot: join(tmp, 'pkg'), allowUnsealed: true, repositoryRoot: '/home/toorik/Projects/ShieldKit-LABS' }), new RegExp(`SEMANTIC_${component === 'staticDependencies' ? 'DEPENDENCIES' : component === 'sourceReferenceCatalog' ? 'SOURCE_REFERENCES' : component === 'interfaceSourceMap' ? 'INTERFACE_MAP' : component === 'mappingDag' ? 'DAG' : component === 'uopcContractPrefix' ? 'UOPC_PREFIX' : component === 'nonAuthorityBoundary' ? 'NONAUTHORITY' : 'B1'}`));
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
const rootMutation = mkdtempSync(join(fixtureParent, '.shieldkit-uopc-map-root-semantic-'));
try { prepareUnsealedCopy(join(rootMutation, 'pkg')); const file=join(rootMutation,'pkg','upstream-provider-source-map-root.v1.json'), value=JSON.parse(readFileSync(file)); value.status=`${value.status}-mutated`; value.contentDigest.value=semanticDigest('shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root',value); writeFileSync(file,`${canonicalJson(value)}\n`); assert.throws(()=>validateStatic({packageRoot:join(rootMutation,'pkg'),allowUnsealed:true,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),/SCHEMA/); } finally { rmSync(rootMutation,{recursive:true,force:true}); }
for (const [relativePath, expected] of [['upstream-provider-source-map-root.v1.json','ROOT_BYTES:NONCANONICAL'],['schemas/digest.v1.schema.json','SCHEMA_BYTES:digest.v1.schema.json:NONCANONICAL'],['test/digest.kat.json','KAT_BYTES:NONCANONICAL']]) {
  const tmp=mkdtempSync(join(fixtureParent,'.shieldkit-uopc-map-canonical-'));
  try { const pkg=join(tmp,'pkg'); prepareUnsealedCopy(pkg); const f=join(pkg,relativePath); writeFileSync(f,` ${readFileSync(f,'utf8')}`); assert.throws(()=>validateStatic({packageRoot:pkg,allowUnsealed:true,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),new RegExp(expected)); } finally { rmSync(tmp,{recursive:true,force:true}); }
}
const symlinkRepo=mkdtempSync(join(tmpdir(),'shieldkit-uopc-map-symlink-repo-'));
try { symlinkSync('/home/toorik/Projects/ShieldKit-LABS/research-lanes',join(symlinkRepo,'research-lanes'),'dir'); assert.throws(()=>validateStatic({repositoryRoot:symlinkRepo}),/LEAF_SYMLINK_COMPONENT/); } finally { rmSync(symlinkRepo,{recursive:true,force:true}); }
const extraDirectoryFixture = mkdtempSync(join(fixtureParent, '.shieldkit-uopc-map-extra-directory-'));
try { const pkg=join(extraDirectoryFixture,'pkg'); prepareUnsealedCopy(pkg); mkdirSync(join(pkg,'empty-extra'),{mode:0o755}); assert.throws(()=>validateStatic({packageRoot:pkg,allowUnsealed:true,repositoryRoot:'/home/toorik/Projects/ShieldKit-LABS'}),/DIRECTORY_ROSTER/); } finally { rmSync(extraDirectoryFixture,{recursive:true,force:true}); }
const ajv = new Ajv2020({ allErrors: true, strict: true });
for (const schema of schemas) ajv.addSchema(schema);
const scan = (node, trail = '$') => {
  if (!node || typeof node !== 'object') return;
  if (node.type === 'object' && node.additionalProperties !== false) throw new Error(`OPEN_OBJECT_SCHEMA:${trail}`);
  if (node.type === 'array' && !('items' in node) && !('prefixItems' in node) && !('const' in node)) throw new Error(`OPEN_ARRAY_SCHEMA:${trail}`);
  for (const [key, child] of Object.entries(node)) {
    if (key === 'const' || key === 'enum') continue;
    if (Array.isArray(child)) child.forEach((entry, index) => scan(entry, `${trail}/${key}/${index}`));
    else scan(child, `${trail}/${key}`);
  }
};
schemas.forEach(scan);
const model = JSON.parse(readFileSync(new URL('../upstream-provider-source-map-root.v1.json', import.meta.url)));
const validate = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root.v1.schema.json');
if (!validate(model)) throw new Error(ajv.errorsText(validate.errors));
assert.deepEqual(model.mappingDag.nodes, ['OWNER_CONTRACT_MAP','RETRY_TARGET_MAP','RETRY_PREDECESSOR_MAP','LIVE_F_CAPTURE_MAP','WORKLOAD_ROOT_MAP','WORKLOAD_ORDER_MAP','ENDPOINT_BYTE_AUTHORITY_MAP','WORKER_ROWS_MAP','DISPATCH_PLAN_MAP','Q_MAP','A_MAP','LIVE_F_MAP','B_MAP','C_MAP','J_MAP','D_MAP']);
assert.equal(model.mappingDag.edges.length, 29);
assert.deepEqual(model.b1ReentryBoundary.conditions, ['final-package-bytes-are-sealed','independent-SOL-static-re-gate-passes','lane-integration-externally-pins-root-seven-semantic-digests-manifest-roster-sums-validator-counts-and-status','complete-lane-validator-exits-zero']);
assert.deepEqual(model.b1ReentryBoundary.allowedSchemaArchitectureScope, ['closed-additive-schema','canonical-encodings','cross-field-constraints','source-resolution-rules','causal-soundness-structure']);
assert.equal(model.b1ReentryBoundary.forbiddenBeforeFullB0AndRootSolReview.length, 23);
