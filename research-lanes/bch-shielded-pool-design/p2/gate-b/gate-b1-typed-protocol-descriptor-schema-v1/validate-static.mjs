import Ajv2020 from 'ajv/dist/2020.js';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertArchitectureRoot, assertFixedStatementCodecBlockedDependency, assertNoDuplicateJsonKeys, assertTypedSchemaRefReachability, canonicalJson, sha256 } from './semantic-validator.mjs';

const packageRootDefault = dirname(fileURLToPath(import.meta.url));
export const AUTHORED_FILES = Object.freeze(['COMMAND.txt', 'README.md', 'descriptor-schema-architecture-root.v1.json', 'schemas/architecture-root.v1.schema.json', 'schemas/common.v1.schema.json', 'schemas/dependency-catalog.v1.schema.json', 'schemas/digest.v1.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/source-reference.v1.schema.json', 'schemas/typed-protocol-descriptor.v1.schema.json', 'semantic-validator.mjs', 'test/digest.kat.json', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/static.test.mjs', 'validate-static.mjs']);
const directories = Object.freeze(['.', 'schemas', 'test']);
const fail = code => { throw new Error(code); };
const assert = (value, code) => { if (!value) fail(code); };
const local = (root, locator) => resolve(root, locator);
const walk = (root, prefix = '') => readdirSync(root, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? [{ kind: 'directory', locator: `${prefix}${entry.name}` }, ...walk(local(root, entry.name), `${prefix}${entry.name}/`)] : [{ kind: 'file', locator: `${prefix}${entry.name}` }]);
const canonicalJsonFile = (root, locator) => { const bytes = readFileSync(local(root, locator)); try { assertNoDuplicateJsonKeys(bytes, `JSON_DUPLICATE:${locator}`); } catch (error) { fail(error.message); } let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`JSON_PARSE:${locator}`); } assert(bytes.toString('utf8') === `${canonicalJson(value)}\n`, `JSON_CANONICAL:${locator}`); return value; };
export const safeReadDependency = (repositoryRoot, locator, expected) => {
  assert(typeof locator === 'string' && locator.length > 0 && !locator.includes('\\') && !locator.includes('\0'), `DEPENDENCY_LOCATOR_SYNTAX:${locator}`);
  const parts = locator.split('/'); assert(parts.every(part => part.length > 0 && part !== '.' && part !== '..'), `DEPENDENCY_LOCATOR_SEGMENT:${locator}`);
  assert(expected && Number.isInteger(expected.bytes) && expected.bytes >= 0 && typeof expected.rawSha256 === 'string', `DEPENDENCY_EXPECTED_SHAPE:${locator}`);
  const canonicalRepositoryRoot = realpathSync(resolve(repositoryRoot)); const rootStat = lstatSync(canonicalRepositoryRoot); assert(rootStat.isDirectory() && !rootStat.isSymbolicLink(), 'DEPENDENCY_REPOSITORY_ROOT');
  const leaf = resolve(canonicalRepositoryRoot, locator); const rel = relative(canonicalRepositoryRoot, leaf); assert(rel && !rel.startsWith('..'), `DEPENDENCY_ESCAPE:${locator}`); let cursor = canonicalRepositoryRoot;
  for (const part of parts) { cursor = resolve(cursor, part); const stat = lstatSync(cursor); assert(!stat.isSymbolicLink() && (cursor === leaf ? stat.isFile() && stat.nlink === 1 : stat.isDirectory()), `DEPENDENCY_LINK_OR_TYPE:${locator}`); }
  const bytes = readFileSync(leaf); assert(realpathSync(leaf) === leaf && bytes.length === expected.bytes && sha256(bytes) === expected.rawSha256, `DEPENDENCY_RAW_OR_BYTES_DRIFT:${locator}`); return bytes;
};
export const assertFixedStatementCodecEvidence = ({ repositoryRoot, entry, code = 'FIXED_STATEMENT_CODEC_EVIDENCE' }) => {
  const components = assertFixedStatementCodecBlockedDependency(entry, `${code}:DEPENDENCY`);
  components.forEach(component => safeReadDependency(repositoryRoot, component.locator, component));
  return components;
};
const assertDirectoryPath = (repositoryRoot, target, code) => {
  const rel = relative(repositoryRoot, target); assert(rel && !rel.startsWith('..') && !resolve(repositoryRoot, rel).includes('\0'), `${code}:ESCAPE`);
  let cursor = repositoryRoot;
  for (const part of rel.split('/')) { cursor = resolve(cursor, part); const stat = lstatSync(cursor); assert(stat.isDirectory() && !stat.isSymbolicLink(), `${code}:LINK_OR_TYPE`); }
};
const safeCurrentLaneRead = repositoryRoot => {
  const locator = 'research-lanes/bch-shielded-pool-design/lane.json'; const leaf = resolve(repositoryRoot, locator); const rel = relative(repositoryRoot, leaf); assert(rel && !rel.startsWith('..'), 'LANE_AUTHORITY_PROJECTION_ESCAPE'); let cursor = repositoryRoot;
  for (const part of locator.split('/')) { cursor = resolve(cursor, part); const stat = lstatSync(cursor); assert(!stat.isSymbolicLink() && (cursor === leaf ? stat.isFile() && stat.nlink === 1 : stat.isDirectory()), 'LANE_AUTHORITY_PROJECTION_LINK_OR_TYPE'); }
  assert(realpathSync(leaf) === leaf, 'LANE_AUTHORITY_PROJECTION_REALPATH'); return readFileSync(leaf);
};
const checkFilesystem = root => {
  const entries = walk(root); const files = entries.filter(item => item.kind === 'file').map(item => item.locator).sort(); const dirs = ['.', ...entries.filter(item => item.kind === 'directory').map(item => item.locator)].sort();
  assert(JSON.stringify(files) === JSON.stringify([...AUTHORED_FILES].sort()), 'UNSEALED_FILE_CLOSURE'); assert(JSON.stringify(dirs) === JSON.stringify([...directories].sort()), 'UNSEALED_DIRECTORY_CLOSURE');
  for (const locator of ['.', ...files]) { const stat = lstatSync(local(root, locator)); assert(!stat.isSymbolicLink() && (locator === '.' ? stat.isDirectory() : stat.isFile()) && stat.nlink === 1 && (stat.mode & 0o777) === (locator === '.' ? 0o755 : 0o644), `PACKAGE_METADATA:${locator}`); }
  for (const locator of ['schemas', 'test']) { const stat = lstatSync(local(root, locator)); assert(stat.isDirectory() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o755, `PACKAGE_DIRECTORY_METADATA:${locator}`); }
  assert(!existsSync(local(root, 'MANIFEST.json')) && !existsSync(local(root, 'SHA256SUMS')), 'PACKAGE_MUST_REMAIN_UNSEALED');
};
export const validateStatic = ({ packageRoot = packageRootDefault, repositoryRoot = resolve(packageRootDefault, '../../../../..') } = {}) => {
  const repository = realpathSync(resolve(repositoryRoot)); const root = resolve(packageRoot); assertDirectoryPath(repository, root, 'PACKAGE_ANCESTOR'); checkFilesystem(root);
  const schemas = AUTHORED_FILES.filter(locator => locator.startsWith('schemas/')).map(locator => canonicalJsonFile(root, locator)); const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: true }); schemas.forEach(schema => ajv.addSchema(schema));
  const architecture = canonicalJsonFile(root, 'descriptor-schema-architecture-root.v1.json'); const validator = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/gate-b1-typed-protocol-descriptor/v1/architecture-root.v1.schema.json'); assert(validator && validator(architecture), `ROOT_SCHEMA:${ajv.errorsText(validator?.errors)}`);
  const typedValidator = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/gate-b1-typed-protocol-descriptor/v1/typed-protocol-descriptor/v1'); assert(typedValidator, 'TYPED_DESCRIPTOR_SCHEMA');
  const typedSchema = canonicalJsonFile(root, 'schemas/typed-protocol-descriptor.v1.schema.json'); assertTypedSchemaRefReachability(typedSchema, 'STATIC_TYPED_SCHEMA_REACHABILITY');
  const typedSchemaRawSha256 = sha256(readFileSync(local(root, 'schemas/typed-protocol-descriptor.v1.schema.json'))); const laneBytes = safeCurrentLaneRead(repository); assertNoDuplicateJsonKeys(laneBytes, 'JSON_DUPLICATE:lane.json'); const lane = JSON.parse(laneBytes.toString('utf8'));
  for (const entry of architecture.dependencyCatalog.entries) {
    if (entry.kind === 'JSON_TYPED_PROJECTION') continue;
    if (entry.kind === 'BLOCKED_EXTERNAL_REQUIREMENT') {
      assertFixedStatementCodecEvidence({ repositoryRoot: repository, entry, code: 'STATIC_BLOCKED_DEPENDENCY' });
      continue;
    }
    safeReadDependency(repository, entry.locator, entry);
  }
  const result = assertArchitectureRoot({ root: architecture, lane, typedSchemaRawSha256 }); return { files: AUTHORED_FILES.length, directories: directories.length, ...result, unsealed: true };
};
if (process.argv[1] === fileURLToPath(import.meta.url)) { const result = validateStatic(); console.log(`PASS Gate B1 schema architecture unsealed files=${result.files} directories=${result.directories}`); }
