/**
 * Closed Native semantic evaluator source.
 *
 * This file intentionally has no module edges and no host capabilities. It consumes
 * only construction/relation identities and raw operand bytes. No external data is
 * an input. The endpoint is inspected but not invoked by package tests.
 */

const CONFIGS = Object.freeze({
  'algebra-component:m89-d2-x2-plus-1-v2': Object.freeze({ modulus: 618970019642690137449562111n, degree: 2, limbBytes: 12, polynomial: Object.freeze([1n, 0n, 1n]) }),
  'algebra-component:m61-d3-x3-minus-5-v2': Object.freeze({ modulus: 2305843009213693951n, degree: 3, limbBytes: 8, polynomial: Object.freeze([2305843009213693946n, 0n, 0n, 1n]) }),
  'algebra-component:m31-d5-x5-plus-2x-minus-1-v2': Object.freeze({ modulus: 2147483647n, degree: 5, limbBytes: 4, polynomial: Object.freeze([2147483646n, 2n, 0n, 0n, 0n, 1n]) }),
  'algebra-component:m31-d6-x6-minus-5-v2': Object.freeze({ modulus: 2147483647n, degree: 6, limbBytes: 4, polynomial: Object.freeze([2147483642n, 0n, 0n, 0n, 0n, 0n, 1n]) }),
});
const RELATIONS = Object.freeze({
  'relation:e-mac': Object.freeze(['D', 'C', 'B', 'A']),
  'relation:e-square-mac': Object.freeze(['D', 'C', 'A']),
  'relation:e-inverse-check': Object.freeze(['H', 'A']),
});
const fail = (stage, message) => { const error = new TypeError(message); error.failureStage = stage; throw error; };
const bytes = (value, label) => { if (!(value instanceof Uint8Array)) fail('canonical-parser-reject', `${label} must be Uint8Array`); return value; };
const element = (value, degree, modulus) => { if (!Array.isArray(value) || value.length !== degree || value.some(x => typeof x !== 'bigint' || x < 0n || x >= modulus)) fail('canonical-parser-reject', 'invalid extension element'); return value; };
const mod = (value, modulus) => ((value % modulus) + modulus) % modulus;
const decode = (input, config) => {
  const raw = bytes(input, 'operand');
  if (raw.length !== config.degree * config.limbBytes) fail('exact-extension-element-length-check-before-limb-decode', 'wrong element length');
  const values = [];
  const unusedMask = config.modulus === 618970019642690137449562111n ? 0xfe : config.modulus === 2305843009213693951n ? 0xe0 : 0x80;
  for (let i = 0; i < config.degree; i += 1) {
    const start = i * config.limbBytes;
    if ((raw[start + config.limbBytes - 1] & unusedMask) !== 0) fail('unused-high-bit-check-before-numeric-decode', 'unused high bit set');
    let value = 0n;
    for (let j = config.limbBytes - 1; j >= 0; j -= 1) value = (value << 8n) | BigInt(raw[start + j]);
    if (value >= config.modulus) fail('coefficient-range-check-before-arithmetic', 'coefficient is not canonical');
    values.push(value);
  }
  return element(values, config.degree, config.modulus);
};
const add = (a, b, p) => a.map((x, i) => mod(x + b[i], p));
const mul = (a, b, config) => {
  const product = Array(2 * config.degree - 1).fill(0n);
  for (let i = 0; i < config.degree; i += 1) for (let j = 0; j < config.degree; j += 1) product[i + j] = mod(product[i + j] + a[i] * b[j], config.modulus);
  for (let k = product.length - 1; k >= config.degree; k -= 1) {
    const high = product[k];
    if (high === 0n) continue;
    for (let i = 0; i < config.degree; i += 1) product[k - config.degree + i] = mod(product[k - config.degree + i] - high * config.polynomial[i], config.modulus);
  }
  return product.slice(0, config.degree).map(x => mod(x, config.modulus));
};
const equal = (a, b) => a.every((x, i) => x === b[i]);
const one = degree => [1n, ...Array(degree - 1).fill(0n)];

/** Evaluate one row from identities and raw operands only. */
function evaluateNativeKernelRow(row) {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) fail('canonical-parser-reject', 'row must be an object');
  const config = CONFIGS[row.constructionId];
  const names = RELATIONS[row.relationId];
  if (!config || !names || typeof row.workItemId !== 'string') fail('canonical-parser-reject', 'unknown row identity');
  if (!Array.isArray(row.operandsBottomToTop) || row.operandsBottomToTop.length !== names.length) fail('canonical-parser-reject', 'operand count mismatch');
  const values = Object.fromEntries(names.map((name, i) => [name, decode(row.operandsBottomToTop[i], config)]));
  let verdict;
  if (row.relationId === 'relation:e-mac') verdict = equal(values.D, add(mul(values.A, values.B, config), values.C, config.modulus));
  else if (row.relationId === 'relation:e-square-mac') verdict = equal(values.D, add(mul(values.A, values.A, config), values.C, config.modulus));
  else { if (values.A.every(x => x === 0n)) fail('inverse-relation-check', 'zero has no inverse'); verdict = equal(mul(values.A, values.H, config), one(config.degree)); }
  return Object.freeze({ workItemId: row.workItemId, verdict: verdict ? 'accept' : 'reject', failureStage: verdict ? 'accept' : row.relationId === 'relation:e-inverse-check' ? 'inverse-relation-check' : 'relation-check', metrics: null, txChecks: 'unsupported', phase: 'semantic-reference', terminalStatus: 'observed' });
}

/* WorkerRow controller boundary. Private B admission is intentionally outside
 * this module: structured clone cannot carry the private WeakSet brand. */
const nativeEndpointFail = message => { throw new TypeError(`native endpoint: ${message}`); };
const nativeRequire = (condition, message) => { if (!condition) nativeEndpointFail(message); };
const nativeExactKeys = (value, keys, label) => nativeRequire(value !== null && typeof value === 'object' && !Array.isArray(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), `${label} shape drift`);
const nativeDigest = value => nativeRequire(typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value), 'row digest');
const nativeToken = (value, label) => nativeRequire(typeof value === 'string' && /^[A-Za-z0-9:._-]+$/u.test(value), `${label} identity`);
const nativeWorkerProjection = row => {
  nativeExactKeys(row, ['byteBindings', 'case', 'endpoint', 'endpointOrdinal', 'fixture', 'inputs', 'plan', 'rowDigest', 'rowIndex', 'work'], 'WorkerRow');
  nativeRequire(row.endpoint === 'engine:native' && row.endpointOrdinal === 0 && Number.isSafeInteger(row.rowIndex) && row.rowIndex >= 0 && row.rowIndex < 4608, 'endpoint/ordinal/index');
  nativeDigest(row.rowDigest);
  nativeExactKeys(row.work, ['caseDigest', 'constructionId', 'fixtureKey', 'planId', 'relationId', 'workItemId'], 'work identity');
  nativeExactKeys(row.fixture, ['fixtureKey'], 'fixture identity'); nativeExactKeys(row.case, ['caseDigest', 'caseKey'], 'case identity'); nativeExactKeys(row.plan, ['planId'], 'plan identity');
  nativeDigest(row.work.caseDigest); nativeDigest(row.case.caseDigest); nativeToken(row.work.constructionId, 'construction'); nativeToken(row.work.fixtureKey, 'fixture'); nativeToken(row.work.planId, 'plan'); nativeToken(row.work.relationId, 'relation'); nativeToken(row.work.workItemId, 'work item'); nativeToken(row.fixture.fixtureKey, 'fixture'); nativeToken(row.case.caseKey, 'case'); nativeToken(row.plan.planId, 'plan');
  nativeRequire(row.work.fixtureKey === row.fixture.fixtureKey && row.work.caseDigest === row.case.caseDigest && row.work.planId === row.plan.planId, 'identity cross-binding');
  nativeExactKeys(row.inputs, ['constructionId', 'operandsBottomToTop', 'relationId'], 'native inputs');
  nativeExactKeys(row.byteBindings, ['operandsBottomToTop'], 'native byte bindings');
  nativeRequire(Array.isArray(row.inputs.operandsBottomToTop) && Array.isArray(row.byteBindings.operandsBottomToTop) && row.inputs.operandsBottomToTop.length === row.byteBindings.operandsBottomToTop.length, 'operand binding cardinality');
  for (const [index, operand] of row.inputs.operandsBottomToTop.entries()) { nativeRequire(operand instanceof Uint8Array, `operand ${index}`); const binding = row.byteBindings.operandsBottomToTop[index]; nativeExactKeys(binding, ['byteLength', 'sha256'], `operand binding ${index}`); nativeRequire(binding.byteLength === operand.length && typeof binding.sha256 === 'string' && /^[0-9a-f]{64}$/u.test(binding.sha256), `operand binding ${index}`); }
  nativeRequire(row.work.workItemId.length > 0 && row.work.constructionId === row.inputs.constructionId && row.work.relationId === row.inputs.relationId, 'work/input identity');
  return Object.freeze({ constructionId: row.inputs.constructionId, relationId: row.inputs.relationId, workItemId: row.work.workItemId, operandsBottomToTop: row.inputs.operandsBottomToTop });
};

/** Evaluate the Native kernel from one private-controller-admitted WorkerRow. */
export function evaluateNativeRow(row) { return evaluateNativeKernelRow(nativeWorkerProjection(row)); }
