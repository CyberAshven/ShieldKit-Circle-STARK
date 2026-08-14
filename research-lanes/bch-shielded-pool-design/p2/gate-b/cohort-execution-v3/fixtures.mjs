import fs from 'node:fs';
import path from 'node:path';
import { canonicalize, contractPaths, ENGINE_ORDER } from './contract.mjs';
import { deriveExecutionFixture, loadSourceSetPlan, parseLowercaseEvenHex } from '../cohort-freeze-v2/execution-fixture.mjs';

const freezeRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2';
const workspace = contractPaths.workspace;
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-execution-v3 fixture authority: ${message}`); };
const read = rel => JSON.parse(fs.readFileSync(path.resolve(workspace, rel), 'utf8'));
const exact = (left, right, label) => assert(JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right)), label);

/**
 * Regenerates each fixed synthetic P2SH32 fixture from exact source-set bytes.
 * It has no VM, process, or transaction-policy evaluation path.
 */
export function deriveVerifiedFixtureRows() {
  const fixtureRoster = read(`${freezeRel}/fixture-roster.v2.json`); const workRoster = read(`${freezeRel}/work-item-roster.v2.json`); const corpus = read(`${freezeRel}/canonical-corpus.v2.json`);
  assert(fixtureRoster.records.length === 4732 && workRoster.workItems.length === 18928, 'frozen roster cardinalities');
  const cases = new Map(corpus.constructions.flatMap(construction => construction.cases).map(entry => [entry.caseKey, entry]));
  const plans = new Map(); const bases = new Map();
  for (const record of fixtureRoster.records) {
    const entry = cases.get(record.epochIdentity.caseKey); assert(entry && entry.caseDigest?.value === record.epochIdentity.caseDigest, `canonical case binding ${record.fixtureKey}`);
    let plan = plans.get(record.planId); if (!plan) { plan = loadSourceSetPlan(record.planId); plans.set(record.planId, plan); }
    const fixture = deriveExecutionFixture({ sourcePlan: plan, operandsBottomToTop: entry.stackArgsBottomToTop.map((hex, ordinal) => parseLowercaseEvenHex(hex, `corpus operand ${ordinal}`)) });
    exact(fixture.bindings, record.byteBindings, `fixture byte bindings ${record.fixtureKey}`); exact(fixture.sourceBinding, record.sourceBinding, `fixture source binding ${record.fixtureKey}`);
    bases.set(record.fixtureKey, Object.freeze({ fixtureRecord: record, fixture, expected: entry.expected, caseEntry: entry, preflightLimitViolation: Boolean(record.preflightLimitViolation?.scriptSig || record.preflightLimitViolation?.redeem) }));
  }
  assert(plans.size === 42 && bases.size === 4732, 'source-plan/fixture cardinalities');
  const perEngine = new Map(ENGINE_ORDER.map(engineId => [engineId, []]));
  for (const work of workRoster.workItems) {
    const base = bases.get(work.fixtureKey); assert(base && work.engineId && base.fixtureRecord.planId === work.planId, `work fixture binding ${work.workItemId}`);
    perEngine.get(work.engineId).push(Object.freeze({ ...base, workItem: work }));
  }
  for (const engineId of ENGINE_ORDER) { const rows = perEngine.get(engineId); assert(rows.length === 4732, `${engineId} full row cardinality`); for (let ordinal = 0; ordinal < rows.length; ordinal += 1) assert(rows[ordinal].workItem.workItemOrdinal === undefined || rows[ordinal].workItem.workItemOrdinal === ordinal, `${engineId} order`); }
  return Object.freeze({ fixtureRows: Object.freeze([...bases.values()]), byEngine: Object.freeze(Object.fromEntries(ENGINE_ORDER.map(engineId => [engineId, Object.freeze(perEngine.get(engineId))]))), counts: Object.freeze({ fixtures: 4732, engines: 4, obligations: 18928, preflightFixtures: 124, executablePerEngine: 4608 }) });
}
