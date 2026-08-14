import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDirectExtension } from '../../reference/direct-extension.mjs';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
export const SEED_HEX = '0123456789abcdef';
export const SAMPLE_DOMAIN = 'shieldkit-labs/p2/gate-b/canonical-corpus/v2/sample';
export const RELATIONS = ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check'];
export const CATEGORIES = ['category:valid', 'category:boundary', 'category:random', 'category:metamorphic', 'category:malformed'];
export const CONSTRUCTION_FILES = [
  'm89-d2-x2-plus-1.v2.json', 'm61-d3-x3-minus-5.v2.json',
  'm31-d5-x5-plus-2x-minus-1.v2.json', 'm31-d6-x6-minus-5.v2.json',
];
export const ARM_ORDER = [
  'arm:canonical:m89-d2-canonical-schoolbook-v1', 'arm:canonical:m61-d3-canonical-schoolbook-v1',
  'arm:canonical:m31-d5-canonical-schoolbook-v1', 'arm:canonical:m31-d6-canonical-schoolbook-v1',
  'arm:optimized:m89-d2-karatsuba-special-square-v1', 'arm:optimized:m61-d3-pairwise-d3-v1',
  'arm:optimized:m61-d3-toom3-v1', 'arm:optimized:m31-d5-pairwise-d5-v1',
  'arm:optimized:m31-d5-toom5-v1', 'arm:optimized:m31-d6-pairwise-d6-v1',
  'arm:optimized:m31-d6-direct-toom6-v1', 'arm:optimized:m31-d6-tower2x3-six-product-r18-v1',
  'arm:optimized:m31-d6-tower2x3-outer-toom3-v1', 'arm:optimized:m31-d6-tower3x2-quadratic-toom3-v1',
];
const freeze = {
  schedule: ['p2/schedule-freeze/schedule-freeze.v1.json', 'b96da97b99bcf45f34b77ea66c0e44192533634f10a48af1c889b8d0e1fdb173', '099bfc6ea2b571829985f74d62e5138a948d977c7f00e2a2eec94e7d643fae6c'],
  lowering: ['p2/lowering-freeze/lowering-freeze.v1.json', 'c1953cb003d8a78eb6bba02a5dd1182f5a6063be977c5fcf9dc5833f5322cf1f', '37629c4afdeb967ca2e815345d9f52fb8c53b3a5daea995c6febda1b1b3b295e'],
  armIr: ['p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.json', '95cb8b14117de17bd7d6064cc15b778ad44b0b076b009d81c9515d2748054aeb', '49a1d851812881b3cd58cc64871f5628dd8ab7b76cb11ed2495fe4fc0549db64'],
};
const descriptorDigests = ['e0bcc3d24a19e18e182acb13bde65dc22329eea18c0a0d0ae4002ef0e1b39b4c', '80127288a1d7d69163fb3ff0eb039b2c2543466610319a029a7afb87551027b6', '009b6b147a8267ef9a01390c205b86ccb414ebdc7505dde7ca58b57bce8b985f', 'e3091752aa9fec967b7bc20d454b9b77e9dbc8d36a154bd95900f781b5e89049'];
const descriptorRaw = ['1aec3bbc6de2af76b8a2199e1958dbb1b9a94142e4910f88239068a8055a5c52', 'e844fed91918bc80f86e910f37e9e6d5946d3d93bf9b64fd56d77e79bd6147ad', 'da37dee378f4354c0b024cff9c5335dd36b5bd13303b39893b34473423933af0', '74212333384b58d0841e9f8b7eff21c9c26235724228d66197089e8ffd2c8acc'];
const enc = new TextEncoder();
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const bytes = (hex) => Buffer.from(hex, 'hex');
const canonicalValue = (value) => value === null || typeof value !== 'object' ? value : Array.isArray(value) ? value.map(canonicalValue) : Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
const canonical = (value) => JSON.stringify(canonicalValue(value), null, 2);
export const canonicalBytes = (value) => enc.encode(`${canonical(value)}\n`);
const digestPreimage = (domain, value, field) => { const out = structuredClone(value); delete out[field]; return Buffer.concat([enc.encode(domain), Buffer.from([0]), canonicalBytes(out)]); };
export const digest = (domain, value, field = 'contentDigest') => ({ algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8', value: sha(digestPreimage(domain, value, field)) });
const caseDigestValue = (domain, value) => digest(domain, value, 'caseDigest');
const readJson = (path) => JSON.parse(readFileSync(resolve(ROOT, path), 'utf8'));
const rawSha = (path) => sha(readFileSync(resolve(ROOT, path)));
const descriptorPath = (file) => `p2/algebra-component/descriptors/${file}`;
const sourceRoot = 'p2/source-set-v1';

function u32le(value) { const b = Buffer.alloc(4); b.writeUInt32LE(value, 0); return b; }
export function sampler({ constructionIndex, relationIndex, categoryIndex, operandIndex, limbIndex, caseIndex, vectorAttempt = 0, sampleRetry = 0, p }) {
  for (const [v, max] of [[constructionIndex, 255], [relationIndex, 255], [categoryIndex, 255], [operandIndex, 255], [limbIndex, 65535], [caseIndex, 0xffffffff], [vectorAttempt, 0xffffffff], [sampleRetry, 0xffffffff]]) if (!Number.isInteger(v) || v < 0 || v > max) throw new RangeError('sampler coordinate overflow');
  let retry = sampleRetry;
  const threshold = ((1n << 256n) / p) * p;
  while (true) {
    const frame = Buffer.concat([enc.encode(SAMPLE_DOMAIN), Buffer.from([0]), bytes(SEED_HEX), Buffer.from([constructionIndex, relationIndex, categoryIndex, operandIndex]), (() => { const b = Buffer.alloc(2); b.writeUInt16LE(limbIndex); return b; })(), u32le(caseIndex), u32le(vectorAttempt), u32le(retry)]);
    const h = Buffer.from(sha(frame), 'hex');
    let x = 0n; for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(h[i]);
    if (x < threshold) return { value: x % p, sampleRetry: retry, frameHex: frame.toString('hex') };
    if (retry === 0xffffffff) throw new Error('sampleRetry overflow'); retry += 1;
  }
}
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const clone = (x) => structuredClone(x);
const names = (r) => r === RELATIONS[0] ? ['A', 'B', 'C', 'D'] : r === RELATIONS[1] ? ['A', 'C', 'D'] : ['A', 'H'];
const count = (d) => ({ valid: 16, boundary: 2 * d + 6, random: 32, metamorphic: 16, malformed: d * 7 + (d ? 0 : 0) });

function makeConstruction(file, index) {
  const d = readJson(descriptorPath(file));
  const q = d.directQuotient; const p = BigInt(q.p); const degree = q.degree; const limbBytes = d.canonicalCodec.baseLimbBytes;
  const ext = createDirectExtension({ modulus: p, degree, limbBytes, definingPolynomial: q.definingPolynomialAscending.map(BigInt) });
  const raw = (v) => ext.encodeHex(v);
  const zero = () => ext.zero(); const one = () => ext.one();
  const scalar = (v) => [v, ...Array(degree - 1).fill(0n)];
  const sampleElement = (ri, ci, oi, caseIndex, vectorAttempt) => Array.from({ length: degree }, (_, limbIndex) => sampler({ constructionIndex: index, relationIndex: ri, categoryIndex: ci, operandIndex: oi, limbIndex, caseIndex, vectorAttempt, p }).value);
  const derive = (relation, a, b = one(), c = zero()) => relation === RELATIONS[0] ? { A: a, B: b, C: c, D: ext.add(ext.mul(a, b), c) } : relation === RELATIONS[1] ? { A: a, C: c, D: ext.add(ext.square(a), c) } : ext.isZero(a) ? { A: a, H: zero() } : { A: a, H: ext.inverseForCertifiedField(a) };
  const evaluate = (relation, raws) => {
    const required = names(relation); if (Object.keys(raws).length !== required.length || !required.every((n) => typeof raws[n] === 'string')) return { verdict: 'reject', stage: 'operand-set-check' };
    const values = {};
    for (const n of required) { if (raws[n].length !== degree * limbBytes * 2) return { verdict: 'reject', stage: 'exact-extension-element-length-check-before-limb-decode' }; try { values[n] = ext.decodeHex(raws[n]); } catch (e) { const m = String(e.message); return { verdict: 'reject', stage: /unused high bit/u.test(m) ? 'unused-high-bit-check-before-numeric-decode' : />= p/u.test(m) ? 'coefficient-range-check-before-arithmetic' : 'canonical-parser-reject' }; } }
    if (relation === RELATIONS[0]) return ext.equal(values.D, ext.add(ext.mul(values.A, values.B), values.C)) ? { verdict: 'accept', stage: 'accept' } : { verdict: 'reject', stage: 'relation-check' };
    if (relation === RELATIONS[1]) return ext.equal(values.D, ext.add(ext.square(values.A), values.C)) ? { verdict: 'accept', stage: 'accept' } : { verdict: 'reject', stage: 'relation-check' };
    try { return ext.verifyInverseHint(values.A, values.H) ? { verdict: 'accept', stage: 'accept' } : { verdict: 'reject', stage: 'inverse-relation-check' }; } catch { return { verdict: 'reject', stage: 'inverse-relation-check' }; }
  };
  const stack = (relation, values) => (relation === RELATIONS[0] ? ['D', 'C', 'B', 'A'] : relation === RELATIONS[1] ? ['D', 'C', 'A'] : ['H', 'A']).map((n) => raw(values[n]));
  const mk = (ri, ci, categoryId, caseIndex, vectorAttempt, values, extra = {}) => {
    const raws = Object.fromEntries(Object.entries(values).map(([k, v]) => [k, raw(v)]));
    const item = { constructionIndex: index, constructionId: d.descriptorId, relationIndex: ri, relationId: RELATIONS[ri], categoryIndex: ci, categoryId, caseIndex, vectorAttempt, rawOperands: raws, stackArgsBottomToTop: stack(RELATIONS[ri], values), expected: evaluate(RELATIONS[ri], raws), ...extra };
    item.caseKey = `${d.descriptorId}|${item.relationId}|${categoryId}|${caseIndex}|${vectorAttempt}`;
    item.caseDigest = caseDigestValue(`shieldkit-labs/p2/gate-b/canonical-corpus/v2/case/${item.caseKey}`, item);
    return item;
  };
  const boundary = (ri) => {
    const templates = [{ id: 'zero', value: zero() }, { id: 'one', value: one() }, { id: 'all-p-minus-1', value: Array(degree).fill(p - 1n) }, { id: 'p', value: zero(), patch: p }, { id: 'p-plus-1', value: scalar(1n), patch: p + 1n }, { id: 'sign-alias', value: zero(), sign: true }];
    for (let j = 0; j < degree; j++) { templates.push({ id: `unit-${j}-p-minus-1`, value: Array.from({ length: degree }, (_, i) => i === j ? p - 1n : 0n) }); templates.push({ id: `unit-${j}-p`, value: zero(), patch: p, limb: j }); }
    return templates.map((t, caseIndex) => { let v = derive(RELATIONS[ri], t.value); if (ri === 2 && ext.isZero(t.value)) v = { A: zero(), H: zero() }; const raws = Object.fromEntries(Object.entries(v).map(([k, x]) => [k, raw(x)])); if (t.patch !== undefined) { const h = Buffer.from(raws.A, 'hex'); const b = Buffer.alloc(limbBytes); let x = t.patch; for (let z = 0; z < limbBytes; z++) { b[z] = Number(x & 255n); x >>= 8n; } Buffer.from(b).copy(h, (t.limb ?? 0) * limbBytes); raws.A = h.toString('hex'); } if (t.sign) { const h = Buffer.from(raws.A, 'hex'); h[(limbBytes - 1)] = 0x80; raws.A = h.toString('hex'); } const vals = Object.fromEntries(Object.entries(raws).map(([k, x]) => { try { return [k, ext.decodeHex(x)]; } catch { return [k, v[k]]; } })); return mk(ri, 1, 'category:boundary', caseIndex, 0, vals, { boundaryTemplate: t.id, rawOperands: raws, expected: evaluate(RELATIONS[ri], raws), stackArgsBottomToTop: (RELATIONS[ri] === RELATIONS[0] ? ['D', 'C', 'B', 'A'] : RELATIONS[ri] === RELATIONS[1] ? ['D', 'C', 'A'] : ['H', 'A']).map((n) => raws[n]) }); });
  };
  const randomBase = (ri, ci, caseIndex, attempt) => { const a = sampleElement(ri, ci, 0, caseIndex, attempt); if (ri === 2 && ext.isZero(a)) return null; return ri === 0 ? derive(RELATIONS[ri], a, sampleElement(ri, ci, 1, caseIndex, attempt), sampleElement(ri, ci, 2, caseIndex, attempt)) : ri === 1 ? derive(RELATIONS[ri], a, undefined, sampleElement(ri, ci, 1, caseIndex, attempt)) : derive(RELATIONS[ri], a); };
  const retry = (fn) => { for (let attempt = 0; attempt <= 0xffffffff; attempt++) { const x = fn(attempt); if (x) return x; } throw new Error('vectorAttempt overflow'); };
  const malformed = (ri) => { const families = ri === 2 ? ['wrong-length', 'truncation', 'trailing-bytes', 'out-of-range', 'sign-alias', 'swapped-limb', 'wrong-relation-output', 'zero-inverse-hint'] : ['wrong-length', 'truncation', 'trailing-bytes', 'out-of-range', 'sign-alias', 'swapped-limb', 'wrong-relation-output']; return families.flatMap((family, mi) => Array.from({ length: degree }, (_, j) => retry((attempt) => { const base = randomBase(ri, 4, mi * degree + j, attempt); if (!base || (family === 'swapped-limb' && base.A[j] === base.A[(j + 1) % degree]) || (family === 'zero-inverse-hint' && base.H[j] === 0n)) return null; const values = clone(base); const target = ri === 2 ? 'H' : 'D'; if (family === 'wrong-length') values.A = []; else if (family === 'truncation') { const h = Buffer.from(raw(values.A), 'hex'); values.A = [...h].slice(0, -1); } else if (family === 'trailing-bytes') values.A = [...Buffer.concat([Buffer.from(raw(values.A), 'hex'), Buffer.from([0])])]; else if (family === 'out-of-range') { const h = Buffer.from(raw(values.A), 'hex'); let x = p; for (let z = 0; z < limbBytes; z++) { h[j * limbBytes + z] = Number(x & 255n); x >>= 8n; } values.A = [...h]; } else if (family === 'sign-alias') { const h = Buffer.from(raw(values.A), 'hex'); h.fill(0, j * limbBytes, (j + 1) * limbBytes); h[(j + 1) * limbBytes - 1] = 0x80; values.A = [...h]; } else if (family === 'swapped-limb') { const h = Buffer.from(raw(values.A), 'hex'); const n = (j + 1) % degree; const a = Buffer.from(h.subarray(j * limbBytes, (j + 1) * limbBytes)); const b = Buffer.from(h.subarray(n * limbBytes, (n + 1) * limbBytes)); b.copy(h, j * limbBytes); a.copy(h, n * limbBytes); values.A = [...h]; } else if (family === 'wrong-relation-output') { values[target][j] = (values[target][j] + 1n) % p; } else values.H[j] = 0n; const raws = Object.fromEntries(Object.entries(values).map(([k, v]) => [k, Array.isArray(v) && v.length === degree && v.every((x) => typeof x === 'bigint') ? raw(v) : Buffer.from(v).toString('hex')])); const expected = evaluate(RELATIONS[ri], raws); const wanted = ['wrong-length', 'truncation', 'trailing-bytes'].includes(family) ? 'exact-extension-element-length-check-before-limb-decode' : family === 'out-of-range' ? 'coefficient-range-check-before-arithmetic' : family === 'sign-alias' ? 'unused-high-bit-check-before-numeric-decode' : ri === 2 ? 'inverse-relation-check' : 'relation-check'; return expected.verdict === 'reject' && expected.stage === wanted ? mk(ri, 4, 'category:malformed', mi * degree + j, attempt, base, { rawOperands: raws, expected, mutation: { family, limbIndex: j, transform: 'independent-base; exact per-index mutation; retain all other raw operands', expectedFailureStage: wanted }, stackArgsBottomToTop: (RELATIONS[ri] === RELATIONS[0] ? ['D', 'C', 'B', 'A'] : RELATIONS[ri] === RELATIONS[1] ? ['D', 'C', 'A'] : ['H', 'A']).map((n) => raws[n]) }) : null; }))); };
  const all = [];
  for (let ri = 0; ri < 3; ri++) {
    all.push(...Array.from({ length: 16 }, (_, i) => { const a = scalar(BigInt(i + 1)); return mk(ri, 0, 'category:valid', i, 0, ri === 0 ? derive(RELATIONS[ri], a, scalar(BigInt(i + 2)), scalar(BigInt(i + 3))) : ri === 1 ? derive(RELATIONS[ri], a, undefined, scalar(BigInt(i + 2))) : derive(RELATIONS[ri], a)); }));
    all.push(...boundary(ri));
    all.push(...Array.from({ length: 32 }, (_, i) => { const b = retry((a) => randomBase(ri, 2, i, a)); return mk(ri, 2, 'category:random', i, 0, b); }));
    all.push(...Array.from({ length: 16 }, (_, i) => retry((a) => { const b = randomBase(ri, 3, i, a); if (!b) return null; const v = clone(b); if (ri === 0) { if (ext.equal(v.A, v.B)) return null; [v.A, v.B] = [v.B, v.A]; } else if (ri === 1) { if (ext.isZero(v.A)) return null; v.A = ext.neg(v.A); } else { if (ext.equal(v.A, v.H)) return null; [v.A, v.H] = [v.H, v.A]; } const c = mk(ri, 3, 'category:metamorphic', i, a, v, { mutation: { family: 'metamorphic', transform: ri === 0 ? 'swap-A-B' : ri === 1 ? 'negate-A' : 'swap-A-H' } }); return c.expected.verdict === 'accept' ? c : null; })));
    all.push(...malformed(ri));
  }
  return { descriptor: { id: d.descriptorId, path: descriptorPath(file), rawSha256: descriptorRaw[index], contentDigest: descriptorDigests[index] }, p: p.toString(), degree, limbBytes, ext, cases: all };
}

function sourceBinding() {
  const root = readJson(`${sourceRoot}/source-set.v1.json`); const manifest = readJson(`${sourceRoot}/MANIFEST.json`); const by = Object.fromEntries(manifest.files.map((x) => [x.path, x.fileDigest.value]));
  const plans = root.planIndex.map((x) => ({ orderIndex: x.orderIndex, planId: x.planId, sourcePath: x.asmPath, sourceSha256: by[x.asmPath], mapPath: x.mapPath, mapSha256: x.mapSha256, bytecodeSha256: x.bytecodeSha256 }));
  const armOrder = ARM_ORDER.map((arm) => ({ armId: arm, plans: plans.filter((p) => p.planId.includes(`:${arm}:`)) }));
  return { root: { path: `${sourceRoot}/source-set.v1.json`, rawSha256: '53e9acc311a123ad26908b84cf73149913781c1fe72253cc6cd28fef644751b5', contentDigest: '58e7765b066b1917b1fa0b4b96182010ad7f5c8ce8bce601c083bc764845482e' }, schemas: [{ path: `${sourceRoot}/source-set.v1.schema.json`, rawSha256: '540952606544b83591807a9187e099c7a95730e9dc57f5fef1b1bf4266d506a0' }, { path: `${sourceRoot}/plan-source-map.v1.schema.json`, rawSha256: '9bb5574ed443c39769ecbe485e7b9c8ef836bdb952990e6770f1c6fe36a95714' }], armOrder, planCount: plans.length, plans };
}

export function buildCampaign() {
  const sourceSet = sourceBinding();
  const planRoster = { records: sourceSet.plans, contentDigest: { algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: 'shieldkit-labs/p2/gate-b/campaign/v2/plan-roster', frame: 'utf8(domain)||0x00||canonical-json-utf8', value: '' } };
  const artifact = { schema: 'shieldkit-labs/p2/gate-b/campaign/v2', campaignId: 'campaign:bch-shielded-pool-design-gate-b-v2', status: 'contract-only-unmeasured', evidenceClassification: 'not-evidence', selection: null, executionAllowed: false, metricsAllowed: false, rankingAllowed: false, contentDigest: { algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: 'shieldkit-labs/p2/gate-b/campaign/v2/root', frame: 'utf8(domain)||0x00||canonical-json-utf8', value: '' }, seedHex: SEED_HEX, dag: { predecessor: null, successor: 'canonical-corpus:v2', rule: 'additive-DAG-C-then-K(C)' }, bindings: { scheduleFreeze: { path: freeze.schedule[0], rawSha256: freeze.schedule[1], contentDigest: freeze.schedule[2], armOrder: ARM_ORDER }, loweringFreeze: { path: freeze.lowering[0], rawSha256: freeze.lowering[1], contentDigest: freeze.lowering[2], relationTargets: 42 }, loweringArmIrFreeze: { path: freeze.armIr[0], rawSha256: freeze.armIr[1], contentDigest: freeze.armIr[2], armCount: 14, planCount: 42 }, descriptors: CONSTRUCTION_FILES.map((file, i) => ({ id: readJson(descriptorPath(file)).descriptorId, path: descriptorPath(file), rawSha256: descriptorRaw[i], contentDigest: descriptorDigests[i] })), legacyRelationContract: { path: 'p2/gate-b/equal-relation-experiment.v1.json', rawSha256: 'cd0e657214a108cd6d5dbf753b5739250f640fc13e03de21ec1be26bbf14c10a', schemaPath: 'p2/gate-b/equal-relation-experiment.schema.json', schemaSha256: 'd2d8905fb61ddccb9991ca76d9689de2d60d035e2564c451f5fe0b7244b5c9e5' }, directExtension: { sourcePath: 'p2/reference/direct-extension.mjs', sourceSha256: rawSha('p2/reference/direct-extension.mjs'), testPath: 'p2/reference/direct-extension.test.mjs', testSha256: rawSha('p2/reference/direct-extension.test.mjs') }, executionProfile: { path: 'profiles/bch-current-2026-08-08.json', rawSha256: 'd1ec071c1630d38dc719d5a040f36cc94fa02ac7d7f832769d09788595c80e3f' }, sourceSet, planRoster }, contract: { relationOrder: RELATIONS, categoryOrder: CATEGORIES, constructionOrder: CONSTRUCTION_FILES.map((f) => readJson(descriptorPath(f)).descriptorId), stackAbi: { relationOperandOrder: { 'relation:e-mac': ['D', 'C', 'B', 'A'], 'relation:e-square-mac': ['D', 'C', 'A'], 'relation:e-inverse-check': ['H', 'A'] }, orientation: 'bottom-to-top; push-left-then-right; binary operator consumes-right-then-left' }, countFormulas: { valid: 16, boundary: '2*degree+6', random: 32, metamorphic: 16, malformed: '7*degree for e-mac/e-square-mac; 8*degree for e-inverse-check' }, totalsByDegree: [266, 294, 350, 378], mutationFamilies: ['wrong-length', 'truncation', 'trailing-bytes', 'out-of-range', 'sign-alias', 'swapped-limb', 'wrong-relation-output', 'zero-inverse-hint'], inverseRule: 'inverse hints are generated only by DirectExtension.inverseForCertifiedField and checked by verifyInverseHint' } };
  planRoster.contentDigest = digest(planRoster.contentDigest.domain, planRoster);
  artifact.contentDigest = digest(artifact.contentDigest.domain, artifact);
  return artifact;
}

export function buildCorpus(campaign = buildCampaign()) {
  const constructions = CONSTRUCTION_FILES.map((f, i) => { const c = makeConstruction(f, i); return { constructionIndex: i, constructionId: c.descriptor.id, descriptorBinding: c.descriptor, degree: c.degree, limbBytes: c.limbBytes, counts: { total: c.cases.length }, cases: c.cases }; });
  const artifact = { schema: 'shieldkit-labs/p2/gate-b/canonical-corpus/v2', corpusId: 'corpus:canonical-gate-b-v2', status: 'deterministic-host-reference-corpus-component-only', evidenceClassification: 'deterministic-test-input-not-execution-evidence', selection: null, executionAllowed: false, metricsAllowed: false, rankingAllowed: false, contentDigest: { algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: 'shieldkit-labs/p2/gate-b/canonical-corpus/v2/root', frame: 'utf8(domain)||0x00||canonical-json-utf8', value: '' }, campaign: { id: campaign.campaignId, contentDigest: campaign.contentDigest }, seedHex: SEED_HEX, sampler: { domain: SAMPLE_DOMAIN, frame: 'UTF8(domain)||00||seed[8]||constructionIndex:u8||relationIndex:u8||categoryIndex:u8||operandIndex:u8||limbIndex:u16le||caseIndex:u32le||vectorAttempt:u32le||sampleRetry:u32le', digestInterpretation: 'SHA256 -> unsigned little-endian 256-bit integer', rejection: 'floor(2^256/p)*p; accept x<threshold; value=x mod p' }, counts: { total: constructions.reduce((n, x) => n + x.counts.total, 0), byConstruction: constructions.map((x) => ({ constructionId: x.constructionId, total: x.counts.total })) }, constructions };
  artifact.contentDigest = digest(artifact.contentDigest.domain, artifact);
  return artifact;
}

function writeArtifacts() { const c = buildCampaign(); const k = buildCorpus(c); const dir = dirname(fileURLToPath(import.meta.url)); writeFileSync(resolve(dir, 'campaign.v2.json'), `${JSON.stringify(c, null, 2)}\n`); writeFileSync(resolve(dir, 'canonical-corpus.v2.json'), `${JSON.stringify(k, null, 2)}\n`); }
function checkArtifacts() { const c = buildCampaign(); const k = buildCorpus(c); const dir = dirname(fileURLToPath(import.meta.url)); const gotC = JSON.parse(readFileSync(resolve(dir, 'campaign.v2.json'))); const gotK = JSON.parse(readFileSync(resolve(dir, 'canonical-corpus.v2.json'))); if (canonical(gotC) !== canonical(c) || canonical(gotK) !== canonical(k)) throw new Error('generated artifacts differ from deterministic output'); if (k.counts.total !== 1288) throw new Error(`corpus count ${k.counts.total} != 1288`); return { campaignDigest: c.contentDigest.value, corpusDigest: k.contentDigest.value, counts: k.counts }; }
if (process.argv.includes('--write')) writeArtifacts(); else if (process.argv.includes('--check')) console.log(JSON.stringify(checkArtifacts()));
