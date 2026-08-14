import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

export const PACKAGE_ROOT = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-frozen-inputs-v1';
export const FILE_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/file';
export const ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/root';
export const LEAF_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/leaf';
export const ROSTER_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest-roster';
export const MANIFEST_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest';
export const OWN_FILES = [
  'COMMAND.txt', 'README.md', 'frozen-inputs-root.v1.json', 'generate.mjs',
  'schemas/frozen-inputs-root.v1.schema.json', 'schemas/manifest.v1.schema.json',
  'tests/mutation.test.mjs', 'tests/static-kat.test.mjs', 'validate.mjs'
];
export const OWN_DIRECTORIES = ['.', 'schemas', 'tests'];

const here = path.dirname(fileURLToPath(import.meta.url));
const fail = (message) => { throw new Error(`FAIL-CLOSED: ${message}`); };
export const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
export const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
};
export const canonicalBytes = (value) => Buffer.from(`${canonical(value)}\n`, 'utf8');
export const domainDigest = (domain, value) => sha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), canonicalBytes(value)]));
export const exactFileDigest = (bytes) => sha256(Buffer.concat([Buffer.from(FILE_DOMAIN, 'utf8'), Buffer.from([0]), bytes]));
const canonicalDigest = (domain, omittedField, value) => ({algorithm:'sha256', canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame:`utf8(domain)||0x00||canonical-json-utf8-with-top-level-${omittedField}-omitted`, value});
const rosterDigest = (value) => ({algorithm:'sha256', canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain:ROSTER_DOMAIN, frame:'utf8(domain)||0x00||canonical-json-roster-v1', value});
const rawFileDigest = (value) => ({algorithm:'sha256', domain:FILE_DOMAIN, frame:'utf8(domain)||0x00||raw-file-bytes', value});
const isHex = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const safePath = (value) => typeof value === 'string' && value.length > 0 && !value.startsWith('/') && !value.includes('\0') && !value.split('/').some((part) => part === '' || part === '.' || part === '..');
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) fail(`${label} has non-closed keys`);
};
const readCanonicalJson = (file, label) => {
  const raw = fs.readFileSync(file);
  let value; try { value = JSON.parse(raw.toString('utf8')); } catch { fail(`${label} is not JSON`); }
  if (!raw.equals(canonicalBytes(value))) fail(`${label} is not exact canonical JSON`);
  return value;
};
const readJson = (file, label) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { fail(`${label} is not JSON`); } };
const relative = (base, file) => path.relative(base, file).split(path.sep).join('/');
const lstatRegular = (file, label) => {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail(`${label} is not a single-link regular file`);
  if ((stat.mode & 0o777) !== 0o644) fail(`${label} mode is not 0644`);
  return stat;
};
export const assertDirectoryChain = (base, relativePath, label) => {
  if (!path.isAbsolute(base) || (relativePath !== '.' && !safePath(relativePath))) fail(`${label} invalid component path`);
  const basePath = path.resolve(base); const baseStat = fs.lstatSync(basePath);
  if (baseStat.isSymbolicLink() || !baseStat.isDirectory() || (baseStat.mode & 0o777) !== 0o755) fail(`${label} root is not a 0755 non-symlink directory`);
  const realBase = fs.realpathSync(basePath); let current = basePath;
  const parts = relativePath === '.' ? [] : relativePath.split('/');
  for (const part of parts) {
    current = path.join(current, part); const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory() || (stat.mode & 0o777) !== 0o755) fail(`${label} component is not a 0755 non-symlink directory: ${part}`);
    const realCurrent = fs.realpathSync(current); const relation = path.relative(realBase, realCurrent);
    if (relation === '..' || relation.startsWith(`..${path.sep}`) || path.isAbsolute(relation)) fail(`${label} component escapes containment: ${part}`);
  }
  return current;
};
const assertOwnPackageRoot = (packageDir, repoRoot, allowDetached) => {
  const expected = path.join(repoRoot, PACKAGE_ROOT);
  if (!allowDetached && path.resolve(packageDir) !== expected) fail('own package root is not the canonical repository path');
  return allowDetached ? assertDirectoryChain(path.resolve(packageDir), '.', 'own package') : assertDirectoryChain(repoRoot, PACKAGE_ROOT, 'own package');
};
const collectTree = (root) => {
  const files = []; const directories = ['.'];
  const walk = (directory) => {
    const entries = fs.readdirSync(directory, {withFileTypes:true}).sort((a,b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const full = path.join(directory, entry.name); const rel = relative(root, full); const stat = fs.lstatSync(full);
      if (stat.isSymbolicLink()) fail(`symlink forbidden: ${rel}`);
      if (stat.isDirectory()) { if ((stat.mode & 0o777) !== 0o755) fail(`directory mode is not 0755: ${rel}`); directories.push(rel); walk(full); }
      else if (stat.isFile()) { if (stat.nlink !== 1) fail(`hardlink forbidden: ${rel}`); if ((stat.mode & 0o777) !== 0o644) fail(`file mode is not 0644: ${rel}`); files.push(rel); }
      else fail(`non-regular entry forbidden: ${rel}`);
    }
  };
  walk(root); return {files:files.sort(), directories:directories.sort()};
};
const parseSums = (file, label) => {
  const text = fs.readFileSync(file, 'utf8');
  if (!text.endsWith('\n') || text.includes('\r')) fail(`${label} checksum formatting`);
  const result = new Map();
  for (const line of text.trimEnd().split('\n')) {
    const match = /^([0-9a-f]{64})  ([^\s].*)$/.exec(line);
    if (!match || !safePath(match[2]) || result.has(match[2])) fail(`${label} malformed checksum row`);
    result.set(match[2], match[1]);
  }
  return result;
};
const binding = (repoRoot, localRoot, localPath) => {
  const file = path.join(localRoot, localPath); const bytes = fs.readFileSync(file);
  return {path:path.posix.join(relative(repoRoot, localRoot), localPath), bytes:bytes.length, rawSha256:sha256(bytes), fileContentDigest:rawFileDigest(exactFileDigest(bytes))};
};
const assertCanonicalDigest = (actual, domain, omittedField, expectedValue, label) => {
  exactKeys(actual, ['algorithm','canonicalization','domain','frame','value'], label);
  if (actual.algorithm !== 'sha256' || actual.canonicalization !== 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1' || actual.domain !== domain || actual.frame !== `utf8(domain)||0x00||canonical-json-utf8-with-top-level-${omittedField}-omitted` || actual.value !== expectedValue) fail(`${label} mismatch`);
};
const assertRawFileDigest = (actual, expectedValue, label) => {
  exactKeys(actual, ['algorithm','domain','frame','value'], label);
  if (actual.algorithm !== 'sha256' || actual.domain !== FILE_DOMAIN || actual.frame !== 'utf8(domain)||0x00||raw-file-bytes' || actual.value !== expectedValue) fail(`${label} mismatch`);
};
const assertFileBinding = (actual, expected, label) => {
  exactKeys(actual, ['bytes','fileContentDigest','path','rawSha256'], label);
  if (actual.path !== expected.path || actual.bytes !== expected.bytes || actual.rawSha256 !== expected.rawSha256) fail(`${label} raw binding mismatch`);
  assertRawFileDigest(actual.fileContentDigest, expected.fileContentDigest.value, `${label}.fileContentDigest`);
};
const leafSpec = (repoRoot, id) => id === 'source-set-v1' ? {
  id, packageRoot:'research-lanes/bch-shielded-pool-design/p2/source-set-v1', root:'source-set.v1.json',
  rawRoot:'53e9acc311a123ad26908b84cf73149913781c1fe72253cc6cd28fef644751b5',
  native:'58e7765b066b1917b1fa0b4b96182010ad7f5c8ce8bce601c083bc764845482e',
  manifest:'d830276ccae8efe9ab10a04de539521a6637fd7a09429d5834c22fbcf5b33ba2', sums:'8c108df96e1b5757fbb0ca93894496bade08ca5e8a9e68143f701c85380ff103'
} : {
  id, packageRoot:'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2', root:'execution-epoch.v2.json',
  rawRoot:'84ff8f6a85244b65d5d4f6e80c38b516223641ee444a133a67eb5794311d2dbc', artifact:'6fcbaba3bb52d5e1eb9c6f1cb04b1d46cb65e2c91eba20ca38356dc323ebb11e',
  manifest:'f600f81a716fb968ee1602c088e438d08008bce336e2191f68b37919b8bf5171', sums:'57eee7a1cc1fdd9c10e9f97176b77b138eb3b97949fe3bf1518bf1517f04275e'
};
export const validateLeafClosure = (repoRoot, spec) => {
  const root = assertDirectoryChain(repoRoot, spec.packageRoot, `${spec.id} package`);
  const manifestPath = path.join(root, 'MANIFEST.json'); const sumsPath = path.join(root, 'SHA256SUMS');
  lstatRegular(manifestPath, `${spec.id} manifest`); lstatRegular(sumsPath, `${spec.id} sums`);
  const manifest = readJson(manifestPath, `${spec.id} manifest`);
  if (!Array.isArray(manifest.files)) fail(`${spec.id} manifest files missing`);
  const records = manifest.files; const names = new Set();
  for (let index = 0; index < records.length; index++) {
    const record = records[index]; exactKeys(record, ['byteCount','fileDigest','orderIndex','path'], `${spec.id} record`);
    exactKeys(record.fileDigest, ['algorithm','preimage','value'], `${spec.id} record digest`);
    if (record.orderIndex !== index || !safePath(record.path) || names.has(record.path) || record.fileDigest.algorithm !== 'sha256' || record.fileDigest.preimage !== 'exact-file-bytes' || !isHex(record.fileDigest.value)) fail(`${spec.id} manifest record invalid`);
    names.add(record.path); const file = path.join(root, record.path); lstatRegular(file, `${spec.id}:${record.path}`); const bytes = fs.readFileSync(file);
    if (bytes.length !== record.byteCount || sha256(bytes) !== record.fileDigest.value) fail(`${spec.id} manifest record byte binding`);
  }
  const expectedFiles = [...names, 'MANIFEST.json', 'SHA256SUMS'].sort(); const tree = collectTree(root);
  if (canonical(tree.files) !== canonical(expectedFiles)) fail(`${spec.id} file closure mismatch`);
  const expectedDirs = new Set(['.']); for (const name of names) { let part = path.posix.dirname(name); while (part !== '.') { expectedDirs.add(part); part = path.posix.dirname(part); } }
  if (canonical(tree.directories) !== canonical([...expectedDirs].sort())) fail(`${spec.id} directory closure mismatch`);
  const sums = parseSums(sumsPath, `${spec.id} sums`); const expectedSums = [...names, 'MANIFEST.json'].sort();
  if (canonical([...sums.keys()].sort()) !== canonical(expectedSums)) fail(`${spec.id} sums closure mismatch`);
  for (const name of expectedSums) if (sums.get(name) !== sha256(fs.readFileSync(path.join(root, name)))) fail(`${spec.id} sums byte mismatch: ${name}`);
  if (sha256(fs.readFileSync(path.join(root, spec.root))) !== spec.rawRoot || sha256(fs.readFileSync(manifestPath)) !== spec.manifest || sha256(fs.readFileSync(sumsPath)) !== spec.sums) fail(`${spec.id} accepted raw root mismatch`);
  if (spec.native) { const native = readJson(path.join(root, spec.root), `${spec.id} root`); if (!native.contentDigest || native.contentDigest.value !== spec.native) fail(`${spec.id} native semantic root mismatch`); }
  if (spec.artifact) { const artifact = readJson(path.join(root, spec.root), `${spec.id} root`); if (!artifact.contentDigest || artifact.contentDigest.value !== spec.artifact) fail(`${spec.id} artifact semantic root mismatch`); }
  return root;
};
const containsForbiddenReference = (value) => {
  const text = typeof value === 'string' ? value : canonical(value);
  const frozen = `cohort-${'v3-freeze'}`; const execution = `cohort-${'execution-v3'}`;
  const other = [`${'snap'}${'shot'}`, `${'live-'}${'executor'}`, `${'predecessor-'}${'executor'}`, `${'attempt-'}${'accounting'}`, `${'cohort-'}${'retry'}`];
  return text.includes(frozen) || text.includes(execution) || other.some((token) => text.includes(token));
};
const assertNoForbiddenPackageText = (packageDir, files) => {
  const forbidden = [`cohort-${'v3-freeze'}`, `cohort-${'execution-v3'}`, `${'snap'}${'shot'}`, `${'live-'}${'executor'}`, `${'predecessor-'}${'executor'}`, `${'attempt-'}${'accounting'}`, `${'cohort-'}${'retry'}`];
  for (const name of files) {
    const text = fs.readFileSync(path.join(packageDir, name), 'utf8');
    if (forbidden.some((token) => text.includes(token))) fail(`forbidden package reference: ${name}`);
  }
};
const applySchemas = (packageDir, root, manifest) => {
  const ajv = new Ajv2020({allErrors:true, strict:true, validateFormats:false});
  const rootSchema = readJson(path.join(packageDir, 'schemas/frozen-inputs-root.v1.schema.json'), 'root schema');
  const manifestSchema = readJson(path.join(packageDir, 'schemas/manifest.v1.schema.json'), 'manifest schema');
  const validateRoot = ajv.compile(rootSchema); const validateManifest = ajv.compile(manifestSchema);
  if (!validateRoot(root)) fail(`root schema: ${ajv.errorsText(validateRoot.errors)}`);
  if (!validateManifest(manifest)) fail(`manifest schema: ${ajv.errorsText(validateManifest.errors)}`);
};
const expectedLeaf = (repoRoot, id) => {
  const spec = leafSpec(repoRoot, id); const root = validateLeafClosure(repoRoot, spec);
  const wrapper = {root:binding(repoRoot, root, spec.root), manifest:binding(repoRoot, root, 'MANIFEST.json'), sums:binding(repoRoot, root, 'SHA256SUMS')};
  const value = {id, packageRoot:spec.packageRoot, wrapper};
  if (spec.native) value.nativeSemanticDigest = readJson(path.join(root, spec.root), `${id} root`).contentDigest;
  if (spec.artifact) value.artifactSemanticDigest = readJson(path.join(root, spec.root), `${id} root`).contentDigest;
  value.leafDigest = canonicalDigest(`${LEAF_DOMAIN}/${id}`, 'leafDigest', domainDigest(`${LEAF_DOMAIN}/${id}`, value));
  return value;
};
const ownBinding = (packageDir, localPath) => {
  const bytes = fs.readFileSync(path.join(packageDir, localPath));
  return {path:path.posix.join(PACKAGE_ROOT, localPath), bytes:bytes.length, rawSha256:sha256(bytes), fileContentDigest:rawFileDigest(exactFileDigest(bytes))};
};
export const makeRoot = (repoRoot, packageDir = here) => {
  const leaves = ['source-set-v1','cohort-freeze-v2'].map((id) => expectedLeaf(repoRoot, id));
  const value = {artifactId:'artifact:gate-b:cohort-frozen-inputs-v1', classification:{buildTooling:'static-generator-validator-tests-outside-runtime-authority',runtimeAuthority:'empty'}, executionAllowed:false, leafClosure:{leafCount:2, leaves}, packageId:'cohort-frozen-inputs-v1', schema:'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/root', schemaBindings:[ownBinding(packageDir, 'schemas/frozen-inputs-root.v1.schema.json'), ownBinding(packageDir, 'schemas/manifest.v1.schema.json')], status:'static-content-addressed-frozen-inputs'};
  value.contentDigest = canonicalDigest(ROOT_DOMAIN, 'contentDigest', domainDigest(ROOT_DOMAIN, value)); return value;
};
export const validateRootObject = (root, repoRoot, packageDir = here) => {
  exactKeys(root, ['artifactId','classification','contentDigest','executionAllowed','leafClosure','packageId','schema','schemaBindings','status'], 'root');
  if (root.artifactId !== 'artifact:gate-b:cohort-frozen-inputs-v1' || root.packageId !== 'cohort-frozen-inputs-v1' || root.schema !== 'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/root' || root.status !== 'static-content-addressed-frozen-inputs' || root.executionAllowed !== false || canonical(root.classification) !== canonical({buildTooling:'static-generator-validator-tests-outside-runtime-authority',runtimeAuthority:'empty'})) fail('root fixed field mismatch');
  if (!Array.isArray(root.schemaBindings) || root.schemaBindings.length !== 2) fail('root schema binding count');
  const expectedSchemas = [ownBinding(packageDir, 'schemas/frozen-inputs-root.v1.schema.json'), ownBinding(packageDir, 'schemas/manifest.v1.schema.json')];
  root.schemaBindings.forEach((item, index) => assertFileBinding(item, expectedSchemas[index], `root schema binding ${index}`));
  if (containsForbiddenReference(root)) fail('forbidden lineage reference');
  exactKeys(root.leafClosure, ['leafCount','leaves'], 'root.leafClosure'); if (root.leafClosure.leafCount !== 2 || !Array.isArray(root.leafClosure.leaves) || root.leafClosure.leaves.length !== 2) fail('root must have exactly two leaves');
  const ids = ['source-set-v1','cohort-freeze-v2'];
  for (let i = 0; i < ids.length; i++) {
    const actual = root.leafClosure.leaves[i]; const expected = expectedLeaf(repoRoot, ids[i]);
    const allowed = ids[i] === 'source-set-v1' ? ['id','leafDigest','nativeSemanticDigest','packageRoot','wrapper'] : ['artifactSemanticDigest','id','leafDigest','packageRoot','wrapper'];
    exactKeys(actual, allowed, `leaf ${i}`); if (actual.id !== ids[i] || actual.packageRoot !== expected.packageRoot) fail(`leaf ${i} identity mismatch`);
    for (const field of ['root','manifest','sums']) assertFileBinding(actual.wrapper[field], expected.wrapper[field], `leaf ${i}.${field}`);
    if (ids[i] === 'source-set-v1') { exactKeys(actual.nativeSemanticDigest, ['algorithm','canonicalization','domain','frame','value'], 'source native semantic root'); if (canonical(actual.nativeSemanticDigest) !== canonical(expected.nativeSemanticDigest)) fail('source native semantic root mismatch'); }
    else { exactKeys(actual.artifactSemanticDigest, ['algorithm','canonicalization','domain','frame','value'], 'freeze artifact semantic root'); if (canonical(actual.artifactSemanticDigest) !== canonical(expected.artifactSemanticDigest)) fail('freeze artifact semantic root mismatch'); }
    const without = {...actual}; delete without.leafDigest; assertCanonicalDigest(actual.leafDigest, `${LEAF_DOMAIN}/${ids[i]}`, 'leafDigest', domainDigest(`${LEAF_DOMAIN}/${ids[i]}`, without), `leaf ${i} digest`);
  }
  const without = {...root}; delete without.contentDigest; assertCanonicalDigest(root.contentDigest, ROOT_DOMAIN, 'contentDigest', domainDigest(ROOT_DOMAIN, without), 'root digest');
  return true;
};
const makeManifest = (packageDir) => {
  const files = OWN_FILES.map((name) => { const bytes = fs.readFileSync(path.join(packageDir, name)); return {path:name, bytes:bytes.length, mode:0o644, rawSha256:sha256(bytes), fileContentDigest:rawFileDigest(exactFileDigest(bytes))}; });
  const roster = domainDigest(ROSTER_DOMAIN, files); const value = {directories:OWN_DIRECTORIES.map((path) => ({path, mode:0o755})), directoryCount:3, executionAllowed:false, fileCount:files.length, files, manifestRosterDigest:rosterDigest(roster), packageRoot:PACKAGE_ROOT, schema:'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest', status:'static-content-addressed'};
  value.contentDigest = canonicalDigest(MANIFEST_DOMAIN, 'contentDigest', domainDigest(MANIFEST_DOMAIN, value)); return value;
};
export const validatePackage = (packageDir = here, repoRoot = findRepoRoot(packageDir), {allowDetachedForTest = false} = {}) => {
  packageDir = assertOwnPackageRoot(packageDir, repoRoot, allowDetachedForTest);
  const tree = collectTree(packageDir); const expectedFiles = [...OWN_FILES, 'MANIFEST.json', 'SHA256SUMS'].sort();
  if (canonical(tree.files) !== canonical(expectedFiles) || canonical(tree.directories) !== canonical([...OWN_DIRECTORIES].sort())) fail('own package tree closure mismatch');
  assertNoForbiddenPackageText(packageDir, tree.files);
  const manifest = readCanonicalJson(path.join(packageDir, 'MANIFEST.json'), 'own manifest'); exactKeys(manifest, ['contentDigest','directories','directoryCount','executionAllowed','fileCount','files','manifestRosterDigest','packageRoot','schema','status'], 'own manifest');
  if (manifest.packageRoot !== PACKAGE_ROOT || manifest.schema !== 'shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest' || manifest.status !== 'static-content-addressed' || manifest.executionAllowed !== false || manifest.directoryCount !== 3 || manifest.fileCount !== OWN_FILES.length || canonical(manifest.directories) !== canonical(OWN_DIRECTORIES.map((path) => ({path,mode:0o755})))) fail('own manifest fixed fields');
  const expectedManifest = makeManifest(packageDir); if (canonical(manifest.files) !== canonical(expectedManifest.files)) fail('own manifest file roster mismatch');
  exactKeys(manifest.manifestRosterDigest, ['algorithm','canonicalization','domain','frame','value'], 'own manifest roster digest'); if (canonical(manifest.manifestRosterDigest) !== canonical(expectedManifest.manifestRosterDigest)) fail('own manifest roster digest'); const without = {...manifest}; delete without.contentDigest; assertCanonicalDigest(manifest.contentDigest, MANIFEST_DOMAIN, 'contentDigest', domainDigest(MANIFEST_DOMAIN, without), 'own manifest content digest');
  const sums = parseSums(path.join(packageDir, 'SHA256SUMS'), 'own sums'); const names = [...OWN_FILES, 'MANIFEST.json'].sort(); if (canonical([...sums.keys()].sort()) !== canonical(names)) fail('own sums closure mismatch');
  for (const name of names) if (sums.get(name) !== sha256(fs.readFileSync(path.join(packageDir, name)))) fail(`own sums byte mismatch: ${name}`);
  const root = readCanonicalJson(path.join(packageDir, 'frozen-inputs-root.v1.json'), 'root'); validateRootObject(root, repoRoot, packageDir); applySchemas(packageDir, root, manifest); return {root:sha256(fs.readFileSync(path.join(packageDir, 'frozen-inputs-root.v1.json'))), manifest:sha256(fs.readFileSync(path.join(packageDir, 'MANIFEST.json'))), sums:sha256(fs.readFileSync(path.join(packageDir, 'SHA256SUMS'))), files:tree.files.length, directories:tree.directories.length};
};
export const findRepoRoot = (start) => { let current = path.resolve(start); while (true) { if (fs.existsSync(path.join(current, 'research-lanes'))) return current; const next = path.dirname(current); if (next === current) fail('repository root not found'); current = next; } };
export const seal = (packageDir = here, repoRoot = findRepoRoot(packageDir)) => {
  packageDir = assertOwnPackageRoot(packageDir, repoRoot, false);
  fs.writeFileSync(path.join(packageDir, 'frozen-inputs-root.v1.json'), canonicalBytes(makeRoot(repoRoot, packageDir)), {mode:0o644});
  fs.writeFileSync(path.join(packageDir, 'MANIFEST.json'), canonicalBytes(makeManifest(packageDir)), {mode:0o644});
  const names = [...OWN_FILES, 'MANIFEST.json'].sort(); const sums = `${names.map((name) => `${sha256(fs.readFileSync(path.join(packageDir, name)))}  ${name}`).join('\n')}\n`;
  fs.writeFileSync(path.join(packageDir, 'SHA256SUMS'), sums, {mode:0o644}); return validatePackage(packageDir, repoRoot);
};
if (process.argv[1] === fileURLToPath(import.meta.url)) { try { console.log(JSON.stringify(validatePackage())); } catch (error) { console.error(error.message); process.exitCode = 1; } }
