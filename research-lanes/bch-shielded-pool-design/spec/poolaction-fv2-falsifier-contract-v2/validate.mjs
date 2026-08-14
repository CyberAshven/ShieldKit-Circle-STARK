import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '../../../..');
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(HERE, name), 'utf8'));
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const contract = readJson('contract.v2.json');
const schema = readJson('contract.v2.schema.json');
const sourcePins = readJson('source-pins.v2.json');
const sourcePinsSchema = readJson('source-pins.v2.schema.json');
const manifest = readJson('MANIFEST.json');
const manifestSchema = readJson('manifest.v2.schema.json');
const roster = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'poolactionfv1-refreeze-falsifier-contract-v2', 'matrix-roster.v2.json'), 'utf8'));

const retainedIds = roster.families.map((row) => row.familyId);
const retainedSet = new Set(retainedIds);
const additiveIds = [
  'F2-TOKEN-OBSERVATION-CLOSED',
  'F2-TOKEN-COLLISION-FUNGIBLE-EMPTY-NFT',
  'F2-TOKEN-CAPABILITY-MUTATION',
  'F2-TOKEN-AMOUNT-LENGTH-CATEGORY-MUTATION',
  'F2-DEPLOYMENT-LABEL-SUBSTITUTION',
  'F2-DEPLOYMENT-IDENTICAL-HISTORY-RESIDUAL',
  'F2-ROLE-RELOCATION-LOCAL-INPUTINDEX',
  'F2-CARRIER-ALL-FULL-SCRIPT-FRAME',
  'F2-CARRIER-SESSION-ROOTS',
  'F2-BINARY-ALIASES-JSON-REJECTION',
  'F2-RUNTIME-PROVENANCE-EXCLUSION',
  'F2-CARRIER-COUNT-ORDER-ORDINAL-SPLICE',
  'F2-STRUCTURAL-COMPILER-ALWAYS-FALSE-SUBSTITUTION',
  'F2-ROLE-TEMPLATE-SWAP',
  'F2-STRUCTURAL-ACCEPTING-OPCODE-SUBSTITUTION',
  'F2-GENESIS-PROVENANCE-PREIMAGE-MUTATION'
];

export function validateContract() {
  const ajv = new Ajv({ allErrors: true, strict: true });
  const validSchema = ajv.compile(schema)(contract);
  if (!validSchema) throw new Error(`schema validation failed: ${JSON.stringify(ajv.errors)}`);
  const validPins = ajv.compile(sourcePinsSchema)(sourcePins);
  if (!validPins) throw new Error(`source-pins schema validation failed: ${JSON.stringify(ajv.errors)}`);
  const validManifest = ajv.compile(manifestSchema)(manifest);
  if (!validManifest) throw new Error(`manifest schema validation failed: ${JSON.stringify(ajv.errors)}`);
  if (manifest.fileCount !== manifest.files.length) throw new Error('manifest fileCount mismatch');
  for (const file of manifest.files) if (!fs.existsSync(path.join(HERE, file))) throw new Error(`manifest file missing: ${file}`);
  if (manifest.materializedVariantCount !== 0 || manifest.executedVariantCount !== 0) throw new Error('manifest claims materialized or executed variants');
  if (sourcePins.charter.sha256 !== 'aa1a63b17c74bc5f4f09c4c5009914a42c0942cd320cbf82fce6bad19d45191e') throw new Error('charter source pin mismatch');
  for (const [name, pin] of Object.entries({
    charter: sourcePins.charter,
    retainedRoster: sourcePins.retainedRoster,
    outsideReviewAnchor: sourcePins.outsideReviewAnchor,
    supersededV1Charter: sourcePins.supersededV1Charter
  })) {
    const bytes = fs.readFileSync(path.join(REPO_ROOT, pin.path));
    if (sha256(bytes) !== pin.sha256) throw new Error(`${name} live sha256 mismatch`);
    if (pin.bytes !== undefined && bytes.length !== pin.bytes) throw new Error(`${name} live byte count mismatch`);
    if (pin.lines !== undefined && bytes.toString('utf8').split('\n').length - 1 !== pin.lines) throw new Error(`${name} live line count mismatch`);
  }

  const rows = contract.rows;
  const ids = rows.map((row) => row.familyId);
  if (new Set(ids).size !== ids.length) throw new Error('duplicate familyId in contract rows');
  const retainedRows = rows.filter((row) => row.familyId.startsWith('RF-'));
  const additiveRows = rows.filter((row) => row.familyId.startsWith('F2-'));
  if (retainedRows.length !== 57) throw new Error(`retained row count ${retainedRows.length} != 57`);
  if (additiveRows.length !== 16) throw new Error(`additive row count ${additiveRows.length} != 16`);
  if (JSON.stringify([...new Set(retainedRows.map((row) => row.familyId))].sort()) !== JSON.stringify([...retainedSet].sort())) {
    throw new Error('retained IDs do not exactly match the frozen 57-family roster');
  }
  if (JSON.stringify(additiveRows.map((row) => row.familyId)) !== JSON.stringify(additiveIds)) {
    throw new Error('additive v2-only family order or membership mismatch');
  }

  const groupCounts = Object.fromEntries(Object.keys(contract.groupCounts).map((group) => [group, retainedRows.filter((row) => row.group === group).length]));
  for (const [group, count] of Object.entries(contract.groupCounts)) {
    if (count !== groupCounts[group]) throw new Error(`group ${group}: declared ${count}, observed ${groupCounts[group]}`);
  }
  const classCounts = Object.fromEntries(Object.keys(contract.classificationCounts).map((kind) => [kind, retainedRows.filter((row) => row.classification === kind).length]));
  for (const [kind, count] of Object.entries(contract.classificationCounts)) {
    if (count !== classCounts[kind]) throw new Error(`classification ${kind}: declared ${count}, observed ${classCounts[kind]}`);
  }
  for (const row of rows) {
    if (row.classification === 'DEFER_VM_TIER' && row.status !== 'DEFERRED_VM_OR_SUITE') throw new Error(`${row.familyId}: deferred row has non-deferred status`);
    if (row.classification === 'HISTORICAL_CONTROL_ONLY' && row.status !== 'HISTORICAL_CONTROL_ONLY') throw new Error(`${row.familyId}: historical row has non-historical status`);
    if (row.classification !== 'DEFER_VM_TIER' && row.classification !== 'HISTORICAL_CONTROL_ONLY' && row.status !== 'CONTRACT_FROZEN') throw new Error(`${row.familyId}: contract row is not CONTRACT_FROZEN`);
  }
  const mustExist = ['F2-TOKEN-COLLISION-FUNGIBLE-EMPTY-NFT', 'F2-DEPLOYMENT-IDENTICAL-HISTORY-RESIDUAL', 'F2-ROLE-RELOCATION-LOCAL-INPUTINDEX', 'F2-CARRIER-ALL-FULL-SCRIPT-FRAME', 'F2-BINARY-ALIASES-JSON-REJECTION', 'F2-RUNTIME-PROVENANCE-EXCLUSION', 'F2-STRUCTURAL-COMPILER-ALWAYS-FALSE-SUBSTITUTION', 'F2-ROLE-TEMPLATE-SWAP', 'F2-STRUCTURAL-ACCEPTING-OPCODE-SUBSTITUTION', 'F2-GENESIS-PROVENANCE-PREIMAGE-MUTATION'];
  for (const id of mustExist) if (!ids.includes(id)) throw new Error(`required additive family missing: ${id}`);
  const runtimeNetwork = rows.find((row) => row.familyId === 'RF-NET-RUNTIME-SELECTION-MISMATCH');
  if (!runtimeNetwork.layer.includes('never physical-chain identity') || runtimeNetwork.dependencyGate.includes('V')) throw new Error('runtime network family retained physical-chain/VM semantics');
  const fullScript = rows.find((row) => row.familyId === 'F2-CARRIER-SESSION-ROOTS');
  if (!fullScript.layer.includes('same payload under different full script bytes') || !fullScript.minStableVariants.includes('preserving extracted payload')) throw new Error('same-payload/different-full-script obligation missing');
  if (contract.materializedVariantCount !== 0 || contract.executedVariantCount !== 0) throw new Error('contract claims materialized or executed variants');
  if (!rows.some((row) => row.familyId === 'F2-DEPLOYMENT-IDENTICAL-HISTORY-RESIDUAL' && row.status === 'HISTORICAL_CONTROL_ONLY')) throw new Error('identical-history residual is not explicit historical control');
  return { retained: retainedRows.length, additive: additiveRows.length, total: rows.length, groupCounts, classificationCounts: classCounts, materialized: contract.materializedVariantCount, executed: contract.executedVariantCount };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(validateContract()));
}
