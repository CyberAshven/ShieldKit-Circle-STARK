import Ajv2020 from 'ajv/dist/2020.js';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync, existsSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const canonicalJson = value => Array.isArray(value) ? `[${value.map(canonicalJson).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}` : JSON.stringify(value);
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const semanticDigest = (domain, value) => { const copy = structuredClone(value); delete copy.contentDigest; return sha256(Buffer.concat([Buffer.from(domain), Buffer.from([0]), Buffer.from(`${canonicalJson(copy)}\n`)])); };
const fail = code => { throw new Error(code); };
const expectedFiles = ['COMMAND.txt','README.md','upstream-provider-source-map-root.v1.json','schemas/b1-reentry-boundary.v1.schema.json','schemas/dependency-catalog.v1.schema.json','schemas/digest.v1.schema.json','schemas/interface-source-map.v1.schema.json','schemas/manifest.v1.schema.json','schemas/mapping-dag.v1.schema.json','schemas/model-root.v1.schema.json','schemas/non-authority-boundary.v1.schema.json','schemas/source-reference-catalog.v1.schema.json','schemas/uopc-contract-prefix.v1.schema.json','validate-static.mjs','test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/static.test.mjs'];
const walk = (dir, prefix = '') => readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(join(dir, e.name), `${prefix}${e.name}/`) : [`${prefix}${e.name}`]);
const walkDirectories = (dir, prefix = '') => readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? [`${prefix}${entry.name}`, ...walkDirectories(join(dir, entry.name), `${prefix}${entry.name}/`)] : []);
const rejectPackageLinks = (dir, prefix = '') => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name), locator = `${prefix}${entry.name}`;
    if (lstatSync(path).isSymbolicLink()) fail(`${statSync(path).isDirectory() ? 'PACKAGE_INTERMEDIATE_SYMLINK' : 'PACKAGE_LEAF_SYMLINK'}:${locator}`);
    if (entry.isDirectory()) rejectPackageLinks(path, `${locator}/`);
  }
};
const digestDomain = 'shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1';
const canonicalFile = (file, code) => { const raw=readFileSync(file,'utf8'); let value; try { value=JSON.parse(raw); } catch { fail(`${code}:PARSE`); } if (raw !== `${canonicalJson(value)}\n`) fail(`${code}:NONCANONICAL`); return value; };
const expectedSemanticDigests = { dependencyCatalogDigest:'629fc51a1dcd712444ed1632b30ad0a1a8d337086932af1af5054aa589ff99dd', sourceReferenceCatalogDigest:'d91be196b34e664d28fa855fea8943e9771b30763d3b860b7a72041f49672512', interfaceSourceMapDigest:'59f580240c4d9c6402835710eadb0503ad0b58316fecf0fae07e382d082c4eb0', mappingDagDigest:'a6ad2552b9c585dd5f35a2a732f0fc35f4d3cf6c3831a39c4fe6fef3bdd9f2b1', uopcContractPrefixDigest:'735485a117e15899cd1a4b3aa720599785efa4bb61adab825e0f9fb862957551', nonAuthorityBoundaryDigest:'b5c60933657ad66d992d5c703c0e4ae497b887fc53d01adbd5980c3923b3eb95', b1ReentryBoundaryDigest:'a0619058be75e650f155814b55be7af94069fba7fcdc48d743814c91cc127f29', root:'afddc9f5c7ff6a8f3950a50892e1ff281ab9f64e65f9f85df913e6e865cbf75b' };

export function validateStatic({ packageRoot = import.meta.dirname, repositoryRoot = null, allowUnsealed = false, expectedExternalPins = null } = {}) {
  const root = resolve(packageRoot), modelPath = join(root, 'upstream-provider-source-map-root.v1.json');
  if (!existsSync(modelPath)) fail('ROOT_MISSING');
  rejectPackageLinks(root);
  const files = walk(root).sort(), directories = walkDirectories(root).sort(), hasManifest = existsSync(join(root, 'MANIFEST.json')), hasSums = existsSync(join(root, 'SHA256SUMS')), sealed = hasManifest && hasSums;
  if (hasManifest !== hasSums) fail('PARTIAL_ENVELOPE');
  if (!allowUnsealed && !sealed) fail('UNSEALED_PACKAGE');
  if (allowUnsealed && sealed) fail('SEALED_ARTIFACT_PRESENT');
  if (!sealed && JSON.stringify(files) !== JSON.stringify(expectedFiles.slice().sort())) fail('UNSEALED_ROSTER');
  if (sealed && JSON.stringify(files) !== JSON.stringify([...expectedFiles, 'MANIFEST.json', 'SHA256SUMS'].sort())) fail('SEALED_ROSTER');
  if (JSON.stringify(directories) !== JSON.stringify(['schemas', 'test'])) fail('DIRECTORY_ROSTER');
  for (const f of files) { const s = lstatSync(join(root, f)); if (!s.isFile() || s.nlink !== 1 || (s.mode & 0o777) !== 0o644) fail(`LOCAL_FILE_METADATA:${f}`); }
  for (const d of ['','schemas','test']) { const s=lstatSync(join(root,d)); if (!s.isDirectory() || s.nlink!==1 || (s.mode&0o777)!==0o755) fail(`LOCAL_DIR_METADATA:${d||'.'}`); }
  const schemas = readdirSync(join(root, 'schemas')).map(n => canonicalFile(join(root, 'schemas', n), `SCHEMA_BYTES:${n}`));
  const ajv = new Ajv2020({ strict: true, allErrors: true }); for (const schema of schemas) ajv.addSchema(schema);
  const model = canonicalFile(modelPath, 'ROOT_BYTES'); canonicalFile(join(root, 'test/digest.kat.json'), 'KAT_BYTES');
  if (expectedExternalPins?.rootRawSha256 && sha256(readFileSync(modelPath)) !== expectedExternalPins.rootRawSha256) fail('EXTERNAL_ROOT_PIN');
  if (expectedExternalPins?.validatorRawSha256 && sha256(readFileSync(join(root, 'validate-static.mjs'))) !== expectedExternalPins.validatorRawSha256) fail('EXTERNAL_VALIDATOR_PIN');
  if (sealed) {
    const manifest = canonicalFile(join(root, 'MANIFEST.json'), 'MANIFEST_BYTES');
    const manifestValidate = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-upstream-provider-source-map/v1/manifest.v1.schema.json'); if (!manifestValidate(manifest)) fail(`MANIFEST_SCHEMA:${ajv.errorsText(manifestValidate.errors)}`);
    if (manifest.schema !== `${digestDomain}/manifest/v1` || manifest.format !== `${digestDomain}/manifest/1` || manifest.package !== 'cohort-upstream-provider-source-map-v1' || manifest.entryCount !== 18 || !Array.isArray(manifest.entries) || manifest.entries.length !== 18) fail('MANIFEST_SHAPE');
    const authored = expectedFiles; if (JSON.stringify(manifest.entries.map(e => e.locator)) !== JSON.stringify(authored)) fail('MANIFEST_ORDER');
    const roster = semanticDigest(`${digestDomain}/manifest-roster`, authored); if (manifest.rosterDigest !== roster) fail('ROSTER_DIGEST');
    for (const entry of manifest.entries) { const raw=readFileSync(join(root,entry.locator)); if (entry.bytes !== raw.length || entry.sha256 !== sha256(raw) || entry.fileDigest !== sha256(Buffer.concat([Buffer.from(`${digestDomain}/file`),Buffer.from([0]),raw]))) fail(`MANIFEST_ENTRY:${entry.locator}`); }
    const lines=readFileSync(join(root,'SHA256SUMS'),'utf8').split('\n'); if (lines.at(-1)!=='' || lines.length!==20) fail('CHECKSUM_ROWS'); const expectedRows=[...manifest.entries.map(e=>`${e.sha256}  ${e.locator}`),`${sha256(readFileSync(join(root,'MANIFEST.json')))}  MANIFEST.json`]; if (JSON.stringify(lines.slice(0,-1))!==JSON.stringify(expectedRows)) fail('CHECKSUM_CONTENT');
  }
  const validate = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root.v1.schema.json'); if (!validate(model)) fail(`SCHEMA:${ajv.errorsText(validate.errors)}`);
  const components = [['dependencyCatalogDigest','staticDependencies','dependency-catalog'],['uopcContractPrefixDigest','uopcContractPrefix','uopc-contract-prefix'],['sourceReferenceCatalogDigest','sourceReferenceCatalog','source-reference-catalog'],['interfaceSourceMapDigest','interfaceSourceMap','interface-source-map'],['mappingDagDigest','mappingDag','mapping-dag'],['nonAuthorityBoundaryDigest','nonAuthorityBoundary','non-authority-boundary'],['b1ReentryBoundaryDigest','b1ReentryBoundary','b1-reentry-boundary']];
  for (const [field,key,name] of components) { const got=semanticDigest(`${digestDomain}/${name}`,model[key]); if (model[key].contentDigest.value!==got || model[field].value!==got) fail(`STALE_COMPONENT_DIGEST:${field}`); }
  if (model.contentDigest.value !== semanticDigest(`${digestDomain}/model-root`,model)) fail('STALE_ROOT_DIGEST');
  if (model.staticDependencies.entries.length!==37) fail('DEPENDENCY_COUNT'); if (model.sourceReferenceCatalog.entries.length!==16) fail('SOURCE_REFERENCE_COUNT');
  if (model.interfaceSourceMap.entries.length!==16 || model.interfaceSourceMap.ownerScopeMappings.length!==7) fail('MAP_COUNTS');
  if (model.mappingDag.nodes.length!==16 || model.mappingDag.edges.length!==29 || model.mappingDag.edges.includes('OWNER_CONTRACT_MAP→J_MAP')) fail('DAG');
  { const repo = resolve(repositoryRoot || resolve(root, '../../../../../')); for (const e of model.staticDependencies.entries.concat(model.sourceReferenceCatalog.entries)) { const parts=e.locator.split('/'), leaf=resolve(repo,e.locator), rel=relative(repo,leaf); if (!rel || rel.startsWith('..')) fail(`LEAF_ESCAPE:${e.locator}`); let cursor=repo; for (let i=0;i<parts.length;i++) { cursor=join(cursor,parts[i]); const st=lstatSync(cursor); if (st.isSymbolicLink()) fail(`LEAF_SYMLINK_COMPONENT:${e.locator}`); if (i<parts.length-1 && !st.isDirectory()) fail(`LEAF_INTERMEDIATE:${e.locator}`); } const st=lstatSync(leaf); if (realpathSync(leaf)!==leaf || !st.isFile() || st.nlink!==1) fail(`LEAF_PATH:${e.locator}`); if (sha256(readFileSync(leaf))!==e.rawSha256) fail(`RAW_HASH_DRIFT:${e.locator}`); } }
  const semanticPins = expectedSemanticDigests;
  for (const [field, code] of [['dependencyCatalogDigest','SEMANTIC_DEPENDENCIES'],['sourceReferenceCatalogDigest','SEMANTIC_SOURCE_REFERENCES'],['interfaceSourceMapDigest','SEMANTIC_INTERFACE_MAP'],['mappingDagDigest','SEMANTIC_DAG'],['uopcContractPrefix','SEMANTIC_UOPC_PREFIX'],['nonAuthorityBoundaryDigest','SEMANTIC_NONAUTHORITY'],['b1ReentryBoundaryDigest','SEMANTIC_B1']]) if ((field === 'uopcContractPrefix' ? model.uopcContractPrefixDigest.value : model[field].value) !== semanticPins[field === 'uopcContractPrefix' ? 'uopcContractPrefixDigest' : field]) fail(code);
  if (model.contentDigest.value !== semanticPins.root) fail('SEMANTIC_ROOT');
  return { files: files.length, sealed, rootDigest: model.contentDigest.value };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) { const result=validateStatic({ allowUnsealed: process.argv.includes('--unsealed') }); console.log(`PASS static source-map files=${result.files} sealed=${result.sealed}`); }
