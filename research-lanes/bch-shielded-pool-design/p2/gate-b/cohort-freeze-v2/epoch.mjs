import { createHash } from 'node:crypto';

export const SCHEMA = 'shieldkit-labs/p2/gate-b/execution-epoch/v2';
export const STATUS = 'frozen-contract-only-unexecuted';
export const WORK_ITEM_ROSTER_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-epoch/v2/work-item-roster';
export const ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-epoch/v2/root';
export const FIXTURE_KEY_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-key';
export const ENGINE_ORDER = Object.freeze(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
export const RELATION_ORDER = Object.freeze(['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check']);
export const CATEGORY_ORDER = Object.freeze(['category:valid', 'category:boundary', 'category:random', 'category:metamorphic', 'category:malformed']);
export const EXPECTED_COUNTS = Object.freeze({ terminalEnginePlanCells: 168, corpusCases: 1288, armCasesPerEngine: 4732, workItems: 18928 });
export const EXPECTED_OPTIMIZED_ARM_SUFFIXES = Object.freeze([
  'm31-d6-tower3x2-quadratic-toom3-v1', 'm31-d6-direct-toom6-v1', 'm31-d6-pairwise-d6-v1',
  'm61-d3-toom3-v1', 'm31-d5-toom5-v1', 'm31-d6-tower2x3-six-product-r18-v1',
  'm31-d5-pairwise-d5-v1', 'm89-d2-karatsuba-special-square-v1', 'm61-d3-pairwise-d3-v1', 'm31-d6-tower2x3-outer-toom3-v1'
]);

const HASH = /^[0-9a-f]{64}$/u;
const ARM_ID = /^arm:(canonical|optimized):(.+)$/u;
const PLAN_ID = /^physical-plan:(arm:(?:canonical|optimized):.+):relation:(e-mac|e-square-mac|e-inverse-check):v1$/u;
const REQUIRED_RELATIONS = new Set(RELATION_ORDER);
const REQUIRED_CATEGORIES = new Set(CATEGORY_ORDER);
const clone = (value) => structuredClone(value);

/** Exact source-set canonicalization: sorted object keys, preserved arrays, pretty JSON, LF. */
export const canonicalize = (value) => value === null || typeof value !== 'object'
  ? value
  : Array.isArray(value)
    ? value.map(canonicalize)
    : Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
export const canonicalJson = (value) => `${JSON.stringify(canonicalize(value), null, 2)}\n`;
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export const contentDigestFor = (value, domain = ROOT_DOMAIN) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('content digest input must be an object');
  if (typeof domain !== 'string' || domain.length === 0) throw new TypeError('content digest domain is required');
  const copy = clone(value);
  delete copy.contentDigest;
  return sha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), Buffer.from(canonicalJson(copy), 'utf8')]));
};
export const digestRecord = (value, domain) => ({ algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8', value: contentDigestFor(value, domain) });

const fail = (message) => { throw new Error(`execution epoch contract: ${message}`); };
const requireObject = (value, name) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${name} artifact is required`);
  return value;
};
const requireArray = (value, name) => { if (!Array.isArray(value)) fail(`${name} artifact array is required`); return value; };
const requireDigest = (value, name) => { if (typeof value !== 'string' || !HASH.test(value)) fail(`${name} must be lowercase SHA-256 hex`); return value; };
const nonempty = (value, name) => { if (typeof value !== 'string' || value.length === 0 || value === 'placeholder' || value === 'TODO') fail(`${name} must be non-placeholder provenance`); return value; };
export const fixtureKeyFor = ({ constructionIndex, constructionId, planId, caseKey, caseDigest, vectorAttempt }) => {
  if (!Number.isInteger(constructionIndex) || constructionIndex < 0) fail('fixture key constructionIndex is required');
  nonempty(constructionId, 'fixture key constructionId'); nonempty(planId, 'fixture key planId'); nonempty(caseKey, 'fixture key caseKey'); requireDigest(caseDigest, 'fixture key caseDigest');
  if (!Number.isInteger(vectorAttempt) || vectorAttempt < 0) fail('fixture key vectorAttempt is required');
  const identity = { constructionIndex, constructionId, planId, caseKey, caseDigest, vectorAttempt };
  return `fixture:${sha256(Buffer.concat([Buffer.from(FIXTURE_KEY_DOMAIN, 'utf8'), Buffer.from([0]), Buffer.from(canonicalJson(identity), 'utf8')]))}`;
};

export const armIdFromPlanId = (planId) => {
  const match = PLAN_ID.exec(planId);
  if (!match) fail(`invalid source-set planId: ${String(planId)}`);
  return match[1];
};
export const relationIdFromPlanId = (planId) => {
  const match = PLAN_ID.exec(planId);
  if (!match) fail(`invalid source-set planId: ${String(planId)}`);
  return `relation:${match[2]}`;
};
const armSuffix = (armId) => {
  const match = ARM_ID.exec(armId);
  if (!match) fail(`invalid armId: ${String(armId)}`);
  return match[2];
};
const constructionTag = (id) => {
  const match = /(?:^|:)((?:m31|m61|m89)-d\d+)(?:-|$)/u.exec(id);
  if (!match) fail(`cannot derive construction tag from ${id}`);
  return match[1];
};
const valueFor = (map, key) => map instanceof Map ? map.get(key) : map?.[key];
const descriptorDigest = (descriptors, arm) => {
  const candidates = [arm.armId, `physical-plan:${arm.armId}`, armSuffix(arm.armId), arm.algorithmId, arm.constructionId];
  for (const key of candidates) {
    const value = valueFor(descriptors, key);
    if (typeof value === 'string') return requireDigest(value, `descriptor digest for ${arm.armId}`);
    if (value && typeof value === 'object') return requireDigest(value.contentDigest?.value ?? value.contentDigest, `descriptor digest for ${arm.armId}`);
  }
  fail(`missing exact future descriptor content digest for ${arm.armId}`);
};

/** Derive the 14 arm records and 42 relation plans from source-set-v1. */
export const deriveArmCatalog = (sourceSet) => {
  requireObject(sourceSet, 'source-set');
  const plans = requireArray(sourceSet.planIndex, 'source-set.planIndex');
  if (plans.length !== 42) fail(`source-set must contain exactly 42 plans, got ${plans.length}`);
  const byArm = new Map();
  for (const plan of plans) {
    const armId = armIdFromPlanId(plan.planId);
    const relationId = relationIdFromPlanId(plan.planId);
    if (!REQUIRED_RELATIONS.has(relationId)) fail(`unsupported relation in ${plan.planId}`);
    if (!byArm.has(armId)) byArm.set(armId, { armId, trackId: armId.split(':')[1] === 'canonical' ? 'track:canonical' : 'track:optimized', constructionTag: constructionTag(armId), planIds: [], relationPlanIds: {} });
    const arm = byArm.get(armId);
    arm.planIds.push(plan.planId);
    arm.relationPlanIds[relationId] = plan.planId;
  }
  if (byArm.size !== 14) fail(`source-set must contain exactly 14 arms, got ${byArm.size}`);
  for (const arm of byArm.values()) if (arm.planIds.length !== 3 || Object.keys(arm.relationPlanIds).length !== 3) fail(`arm ${arm.armId} must contain one plan for each relation`);
  return [...byArm.values()];
};

const digestKey = (digest, armId) => Buffer.concat([Buffer.from(digest, 'ascii'), Buffer.from([0]), Buffer.from(armId, 'utf8')]);
export const optimizedOrderKey = (digest, armId) => createHash('sha256').update(digestKey(requireDigest(digest, 'descriptor digest'), nonempty(armId, 'armId'))).digest();
const compareArmEntries = (a, b) => Buffer.compare(a.key, b.key) || Buffer.compare(Buffer.from(a.armId, 'utf8'), Buffer.from(b.armId, 'utf8'));

/** Canonical arms follow source-set construction order; optimized arms sort by exact descriptor digest frame. */
export const resolveArmOrder = (sourceSet, descriptors) => {
  const catalog = deriveArmCatalog(sourceSet);
  const canonical = catalog.filter((arm) => arm.trackId === 'track:canonical');
  const optimized = catalog.filter((arm) => arm.trackId === 'track:optimized').map((arm) => {
    const digest = descriptorDigest(descriptors, arm);
    const key = optimizedOrderKey(digest, arm.armId);
    return { ...arm, descriptorContentDigest: digest, key, keyHex: key.toString('hex') };
  }).sort(compareArmEntries);
  if (canonical.length !== 4 || optimized.length !== 10) fail('arm order requires four canonical and ten optimized arms');
  const expected = EXPECTED_OPTIMIZED_ARM_SUFFIXES.join('|');
  const resolved = optimized.map((arm) => armSuffix(arm.armId)).join('|');
  if (resolved !== expected) fail(`resolved optimized arm order is not the frozen order: ${resolved}`);
  const order = [...canonical, ...optimized];
  return { canonical, optimized, order };
};
export const resolveOptimizedArmOrder = (sourceSet, descriptors) => resolveArmOrder(sourceSet, descriptors).optimized;

const constructionCases = (corpus) => {
  requireObject(corpus, 'corpus');
  const constructions = requireArray(corpus.constructions, 'corpus.constructions');
  if (constructions.length !== 4) fail(`corpus must contain exactly four constructions, got ${constructions.length}`);
  const all = [];
  for (let expectedIndex = 0; expectedIndex < constructions.length; expectedIndex += 1) {
    const construction = constructions[expectedIndex]; requireObject(construction, `corpus.constructions[${expectedIndex}]`);
    if (construction.constructionIndex !== expectedIndex) fail('corpus constructionIndex/order drift');
    const cases = requireArray(construction.cases, `corpus.constructions[${expectedIndex}].cases`);
    const seen = new Set(); let previous = null;
    for (const entry of cases) {
      requireObject(entry, `corpus case ${expectedIndex}`);
      if (entry.constructionIndex !== expectedIndex || entry.constructionId !== construction.constructionId) fail('corpus case construction binding drift');
      if (!REQUIRED_RELATIONS.has(entry.relationId) || !REQUIRED_CATEGORIES.has(entry.categoryId) || !Number.isInteger(entry.caseIndex) || entry.caseIndex < 0 || !Number.isInteger(entry.vectorAttempt) || entry.vectorAttempt < 0) fail('corpus case identity is invalid');
      if (typeof entry.caseKey !== 'string' || entry.caseKey.length === 0) fail('corpus caseKey is required');
      const caseDigestValue = entry.caseDigest?.value ?? entry.caseDigest;
      requireDigest(caseDigestValue, 'corpus caseDigest');
      const identity = `${entry.constructionIndex}|${entry.constructionId}|${entry.caseKey}|${entry.caseDigest}|${entry.vectorAttempt}`;
      if (seen.has(identity)) fail(`duplicate full corpus case identity ${identity}`); seen.add(identity);
      const current = [entry.relationIndex, entry.categoryIndex, entry.caseIndex, entry.vectorAttempt];
      if (!Number.isInteger(entry.relationIndex) || !Number.isInteger(entry.categoryIndex) || entry.relationIndex !== RELATION_ORDER.indexOf(entry.relationId) || entry.categoryIndex !== CATEGORY_ORDER.indexOf(entry.categoryId)) fail('corpus relation/category index binding drift');
      if (previous && current.some((value, index) => { for (let i = 0; i < index; i += 1) if (current[i] !== previous[i]) return false; return value < previous[index]; })) fail('corpus case order drift');
      previous = current;
      all.push({ ...entry, constructionIndex: expectedIndex, constructionId: construction.constructionId, caseDigest: caseDigestValue });
    }
    const degree = construction.degree;
    for (const relationId of RELATION_ORDER) for (const categoryId of CATEGORY_ORDER) {
      const expectedCount = categoryId === 'category:valid' || categoryId === 'category:metamorphic' ? 16 : categoryId === 'category:random' ? 32 : categoryId === 'category:boundary' ? 2 * degree + 6 : relationId === 'relation:e-inverse-check' ? 8 * degree : 7 * degree;
      const selected = cases.filter((entry) => entry.relationId === relationId && entry.categoryId === categoryId);
      if (selected.length !== expectedCount || selected.some((entry, index) => entry.caseIndex !== index)) fail(`corpus missing/reordered cases for ${construction.constructionId}/${relationId}/${categoryId}`);
    }
    if (construction.counts?.total !== cases.length) fail(`corpus construction count drift for ${construction.constructionId}`);
  }
  if (all.length !== EXPECTED_COUNTS.corpusCases || corpus.counts?.total !== all.length) fail(`corpus must contain exactly ${EXPECTED_COUNTS.corpusCases} cases`);
  return all;
};
const caseMatchesArm = (entry, arm) => entry.constructionId.includes(arm.constructionTag);
const caseRelation = (entry) => entry.relationId;
const caseCategory = (entry) => entry.categoryId;
const caseIndex = (entry) => entry.caseIndex;
const planRecord = (plans, planId) => {
  const plan = plans.find((item) => item.planId === planId);
  if (!plan) fail(`missing source-set plan ${planId}`);
  requireDigest(plan.bytecodeSha256, `bytecode digest for ${planId}`);
  return plan;
};

export const buildTerminalCells = (sourceSet, engineRecords) => {
  const plans = requireArray(requireObject(sourceSet, 'source-set').planIndex, 'source-set.planIndex');
  const engines = validateEngineRecords(engineRecords);
  return plans.flatMap((plan) => engines.map((engine) => ({ terminalCellId: `${plan.planId}:${engine.engineId}`, planId: plan.planId, engineId: engine.engineId })));
};

/** Expand corpus cases into the normative arm/relation/category/index/engine roster. */
export const buildWorkItemRoster = ({ sourceSet, corpus, descriptors, engineRecords, schemaSha256 }) => {
  requireObject(sourceSet, 'source-set'); requireObject(corpus, 'corpus');
  const engines = validateEngineRecords(engineRecords);
  if (schemaSha256 !== undefined) requireDigest(schemaSha256, 'work-item roster schemaSha256');
  const { order: arms } = resolveArmOrder(sourceSet, descriptors);
  const cases = constructionCases(corpus);
  const plans = requireArray(sourceSet.planIndex, 'source-set.planIndex');
  const cells = buildTerminalCells(sourceSet, engines);
  const workItems = [];
  const fullIdentities = new Set();
  for (const arm of arms) {
    const armCases = cases.filter((entry) => caseMatchesArm(entry, arm));
    if (!armCases.length) fail(`corpus has no cases for ${arm.armId}`);
    const seen = new Set();
    for (const entry of armCases) {
      const relationId = caseRelation(entry); const categoryId = caseCategory(entry); const index = caseIndex(entry);
      const key = `${entry.constructionIndex}|${entry.constructionId}|${entry.caseKey}|${entry.caseDigest}|${entry.vectorAttempt}`;
      if (seen.has(key)) fail(`duplicate corpus case ${key} for ${arm.armId}`); seen.add(key);
      if (fullIdentities.has(`${arm.armId}|${key}`)) fail(`duplicate full case identity ${key} for ${arm.armId}`); fullIdentities.add(`${arm.armId}|${key}`);
      const planId = arm.relationPlanIds[relationId];
      const plan = planRecord(plans, planId);
      for (const engine of engines) {
        const fixtureKey = fixtureKeyFor({ constructionIndex: entry.constructionIndex, constructionId: entry.constructionId, planId, caseKey: entry.caseKey, caseDigest: entry.caseDigest, vectorAttempt: entry.vectorAttempt });
        workItems.push({ workItemId: `${arm.armId}:${entry.caseKey}:${engine.engineId}`, armId: arm.armId, planId, planBytecodeSha256: plan.bytecodeSha256, constructionIndex: entry.constructionIndex, constructionId: entry.constructionId, relationId, categoryId, caseIndex: index, caseKey: entry.caseKey, caseDigest: entry.caseDigest, vectorAttempt: entry.vectorAttempt, fixtureKey, engineId: engine.engineId, terminalCellId: `${planId}:${engine.engineId}` });
      }
    }
  }
  const normative = new Map(arms.map((arm, i) => [arm.armId, i]));
  const rel = new Map(RELATION_ORDER.map((v, i) => [v, i])); const cat = new Map(CATEGORY_ORDER.map((v, i) => [v, i])); const eng = new Map(ENGINE_ORDER.map((v, i) => [v, i]));
  workItems.sort((a, b) => normative.get(a.armId) - normative.get(b.armId) || a.constructionIndex - b.constructionIndex || rel.get(a.relationId) - rel.get(b.relationId) || cat.get(a.categoryId) - cat.get(b.categoryId) || a.caseIndex - b.caseIndex || a.vectorAttempt - b.vectorAttempt || eng.get(a.engineId) - eng.get(b.engineId));
  if (cells.length !== EXPECTED_COUNTS.terminalEnginePlanCells || cases.length !== EXPECTED_COUNTS.corpusCases || workItems.length !== EXPECTED_COUNTS.workItems || workItems.length / engines.length !== EXPECTED_COUNTS.armCasesPerEngine) fail('work-item roster cardinality drift');
  const roster = { schema: `${SCHEMA}/work-item-roster`, artifactId: 'work-item-roster:gate-b-v2', path: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/work-item-roster.v2.json', status: 'frozen-normative-roster-path-ready', evidenceClassification: 'not-evidence', executionAllowed: false, metricsAllowed: false, ranking: null, selection: null, schemaPath: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/work-item-roster.v2.schema.json', ...(schemaSha256 === undefined ? {} : { schemaSha256 }), counts: { terminalEnginePlanCells: cells.length, corpusCases: cases.length, armCasesPerEngine: workItems.length / engines.length, workItems: workItems.length }, normativeArmOrder: arms.map((arm) => arm.armId), relationOrder: [...RELATION_ORDER], categoryOrder: [...CATEGORY_ORDER], engineOrder: engines.map((engine) => engine.engineId), terminalCells: cells, workItems };
  roster.contentDigest = digestRecord(roster, WORK_ITEM_ROSTER_DOMAIN);
  return roster;
};

export const ENGINE_CAPABILITIES = Object.freeze({
  terminalPolicy: 'supported-or-explicit-unsupported',
  unsupportedCannotCount: true,
  relations: [...RELATION_ORDER], categories: [...CATEGORY_ORDER], preservesCaseIndex: true, parserBeforeArithmetic: true
});
const capabilityEqual = (value) => canonicalJson(value) === canonicalJson(ENGINE_CAPABILITIES);
export const validateEngineRecords = (engineRecords) => {
  const engines = requireArray(engineRecords, 'engine records');
  if (engines.length !== 4) fail(`exactly four engine records are required, got ${engines.length}`);
  for (const [i, engine] of engines.entries()) {
    requireObject(engine, `engine record ${i}`);
    if (engine.engineId !== ENGINE_ORDER[i]) fail(`engine records must be in exact order ${ENGINE_ORDER.join(',')}`);
    nonempty(engine.artifactId, `${engine.engineId} artifactId`); nonempty(engine.path, `${engine.engineId} path`);
    requireDigest(engine.rawSha256, `${engine.engineId} rawSha256`); requireDigest(engine.contentDigest, `${engine.engineId} contentDigest`); requireDigest(engine.schemaSha256, `${engine.engineId} schemaSha256`);
    nonempty(engine.capabilityStatus, `${engine.engineId} capabilityStatus`); nonempty(engine.role, `${engine.engineId} role`);
    if (engine.capabilities !== undefined && !capabilityEqual(engine.capabilities)) fail(`${engine.engineId} capabilities do not exactly match the frozen capability contract`);
  }
  return engines;
};

export const buildPhysicalSchedule = ({ roster, engineRecords }) => {
  requireObject(roster, 'work-item roster');
  const engines = validateEngineRecords(engineRecords);
  if (!Array.isArray(roster.workItems) || !Array.isArray(roster.normativeArmOrder)) fail('roster must contain workItems and normativeArmOrder');
  validateNormativeRosterOrder(roster);
  return { schema: `${SCHEMA}/physical-schedule`, status: 'frozen-physical-policy', policy: { engineMajorBatches: true, maxConcurrency: 1, warmups: 0, oneProcessOrModuleLifecyclePerEngineBatch: true, automaticRetries: false, timeoutMsPerExternalBatch: 600000, cpuAffinity: false, timingMetrics: false, resultDependentScheduling: false, incompleteBatchBlocksEpoch: true, retryWholeIdenticalEpochOnly: true, rawAttemptAccounting: true }, batches: engines.map((engine) => ({ engineId: engine.engineId, workItemIds: roster.workItems.filter((item) => item.engineId === engine.engineId).map((item) => item.workItemId) })) };
};
const validateNormativeRosterOrder = (roster) => {
  const arm = new Map(roster.normativeArmOrder.map((value, index) => [value, index])); const relation = new Map(RELATION_ORDER.map((value, index) => [value, index])); const category = new Map(CATEGORY_ORDER.map((value, index) => [value, index])); const engine = new Map(ENGINE_ORDER.map((value, index) => [value, index]));
  const key = (item) => [arm.get(item.armId), item.constructionIndex, relation.get(item.relationId), category.get(item.categoryId), item.caseIndex, item.vectorAttempt, engine.get(item.engineId)];
  for (let i = 1; i < roster.workItems.length; i += 1) { const previous = key(roster.workItems[i - 1]); const current = key(roster.workItems[i]); for (let j = 0; j < current.length; j += 1) { if (current[j] > previous[j]) break; if (current[j] < previous[j]) fail('work-item roster is not in normative order'); } }
  return true;
};
export const validateWorkItemRosterOrder = validateNormativeRosterOrder;
export const validatePhysicalSchedule = (schedule, roster, engineRecords) => {
  requireObject(schedule, 'physical schedule');
  const expected = buildPhysicalSchedule({ roster, engineRecords });
  if (canonicalJson(schedule) !== canonicalJson(expected)) fail('physical schedule differs from the frozen engine-major policy or normative roster');
  return true;
};

export const validateUnsupportedAccounting = (terminalRecords) => {
  requireArray(terminalRecords, 'terminal records');
  for (const record of terminalRecords) {
    requireObject(record, 'terminal record');
    if (!['supported', 'unsupported'].includes(record.supportStatus)) fail('terminal record must be supported or explicit-unsupported');
    if (record.supportStatus === 'unsupported' && (record.executed === true || record.agreement === true || record.countedAsExecution === true)) fail('unsupported terminal cannot count as execution or agreement');
  }
  return true;
};

const binding = (artifact, name) => {
  requireObject(artifact, name);
  const artifactId = nonempty(artifact.artifactId ?? artifact.campaignId ?? artifact.corpusId ?? artifact.executionProfileId ?? artifact.fixtureId ?? artifact.id, `${name} artifactId`);
  const path = nonempty(artifact.path ?? artifact.artifactPath ?? artifact.file, `${name} path`);
  const rawSha256 = artifact.rawSha256 ?? artifact.rawDigest;
  const schemaSha256 = artifact.schemaSha256 ?? artifact.schemaDigest;
  requireDigest(rawSha256, `${name} rawSha256`); if (schemaSha256 !== undefined) requireDigest(schemaSha256, `${name} schemaSha256`);
  const result = { artifactId, path, rawSha256, ...(schemaSha256 === undefined ? {} : { schemaSha256 }) };
  if (artifact.contentDigest !== undefined) result.contentDigest = artifact.contentDigest?.value ?? artifact.contentDigest;
  if (result.contentDigest !== undefined) requireDigest(result.contentDigest, `${name} contentDigest`);
  if (result.contentDigest !== undefined && result.contentDigest === result.rawSha256) fail(`${name} rawSha256 must not substitute the domain contentDigest`);
  return result;
};
const nullBoundary = (epoch) => {
  if (epoch.execution !== null || epoch.result !== null || epoch.metric !== null || epoch.ranking !== null || epoch.selection !== null) fail('execution/result/metric/ranking/selection must be null before execution');
};

/** Construct the unexecuted epoch; no epoch JSON is generated by this module. */
export const buildExecutionEpoch = ({ sourceSet, campaign, corpus, executionProfile, engineRecords, fixtureDerivation, fixtureRoster, descriptors, workItemRosterRawSha256, workItemRosterSchemaSha256 }) => {
  requireObject(sourceSet, 'source-set'); requireObject(campaign, 'campaign'); requireObject(corpus, 'corpus'); requireObject(executionProfile, 'execution profile'); requireObject(fixtureDerivation, 'fixture derivation'); requireObject(fixtureRoster, 'fixture roster');
  const engines = validateEngineRecords(engineRecords);
  const roster = buildWorkItemRoster({ sourceSet, corpus, descriptors, engineRecords: engines, schemaSha256: workItemRosterSchemaSha256 });
  const schedule = buildPhysicalSchedule({ roster, engineRecords: engines });
  const epoch = { schema: SCHEMA, epochId: 'execution-epoch:gate-b-v2', status: STATUS, evidenceClassification: 'not-evidence', executionAllowed: false, metricsAllowed: false, sourceSet: binding(sourceSet, 'source-set'), campaign: binding(campaign, 'campaign'), corpus: binding(corpus, 'corpus'), executionProfile: binding(executionProfile, 'execution profile'), engineRecords: engines.map((engine) => clone(engine)), fixtureDerivation: binding(fixtureDerivation, 'fixture derivation'), fixtureRoster: binding(fixtureRoster, 'fixture roster'), workItemRoster: { schema: roster.schema, artifactId: roster.artifactId, path: roster.path, status: roster.status, evidenceClassification: roster.evidenceClassification, executionAllowed: roster.executionAllowed, metricsAllowed: roster.metricsAllowed, ranking: roster.ranking, selection: roster.selection, rawSha256: workItemRosterRawSha256, contentDigest: roster.contentDigest, schemaPath: roster.schemaPath, schemaSha256: roster.schemaSha256, counts: roster.counts }, physicalSchedule: schedule, execution: null, result: null, metric: null, ranking: null, selection: null };
  epoch.contentDigest = digestRecord(epoch, ROOT_DOMAIN);
  return epoch;
};

export const validateExecutionEpoch = (epoch, artifacts = {}) => {
  requireObject(epoch, 'execution epoch');
  if (epoch.schema !== SCHEMA || epoch.status !== STATUS) fail('schema or status drift');
  nullBoundary(epoch);
  const sourceSet = artifacts.sourceSet; const corpus = artifacts.corpus;
  if (!sourceSet || !corpus || !artifacts.campaign || !artifacts.executionProfile || !artifacts.fixtureDerivation || !artifacts.fixtureRoster || !artifacts.descriptors || !artifacts.workItemRosterRawSha256 || !artifacts.workItemRosterSchemaSha256) fail('validation requires source-set, campaign, corpus, execution profile, fixture derivation, fixture roster, descriptor artifacts, and roster raw/schema digests');
  const expected = buildExecutionEpoch({ ...artifacts, engineRecords: epoch.engineRecords });
  if (canonicalJson(epoch) !== canonicalJson(expected)) fail('epoch bindings, roster, schedule, capabilities, or content digest are not reproducible');
  return true;
};

export const assertExecutionEpochContract = validateExecutionEpoch;
