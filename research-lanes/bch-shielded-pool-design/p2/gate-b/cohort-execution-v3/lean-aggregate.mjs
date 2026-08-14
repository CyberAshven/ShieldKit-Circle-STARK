const assert = (condition, message) => { if (!condition) throw new TypeError(`cohort-execution-v3 Lean parser: ${message}`); };
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9:|._-]*$/u;
const COUNT = /^(?:0|[1-9][0-9]*)$/u;

export function parseUnquotedLeanList(text, label = 'Lean list') {
  assert(typeof text === 'string' && text.startsWith('[') && text.endsWith(']'), `${label} brackets`);
  const inner = text.slice(1, -1);
  if (inner === '') return [];
  assert(!inner.includes('"') && !inner.includes("'") && !inner.includes('\n') && !inner.includes('\r'), `${label} quoted/control token`);
  const values = inner.split(', ');
  assert(values.join(', ') === inner, `${label} separators must be comma-single-space`);
  for (const value of values) assert(TOKEN.test(value), `${label} token`);
  return values;
}
const number = (text, label) => { assert(COUNT.test(text), `${label} integer`); const value = Number(text); assert(Number.isSafeInteger(value), `${label} safe integer`); return value; };
function expectedRows(rows) {
  assert(Array.isArray(rows) && rows.length > 0, 'rows');
  const byId = new Map();
  for (const row of rows) { const id = row.workItemId ?? row.workItem?.workItemId; assert(typeof id === 'string' && TOKEN.test(id) && !byId.has(id), 'row work item identity'); byId.set(id, row); }
  return byId;
}
function uniqueKnown(values, known, label) {
  const ordinals = new Map([...known.keys()].map((id, ordinal) => [id, ordinal]));
  const seen = new Set(); let previous = -1;
  for (const value of values) { assert(known.has(value) && !seen.has(value), `${label} unknown or duplicate id`); assert(ordinals.get(value) > previous, `${label} row-order drift`); previous = ordinals.get(value); seen.add(value); }
}

/** Parse Lean `List.toString` lists: [] or [id, id], never JSON quoted lists. */
export function parseLeanVmbconfAggregate(stdout, { rows } = {}) {
  assert(typeof stdout === 'string' && stdout.endsWith('\n') && !stdout.includes('\r'), 'stdout LF grammar');
  const expected = expectedRows(rows); const lines = stdout.slice(0, -1).split('\n');
  assert(lines.length === 7, 'seven-line aggregate');
  const oracle = /^ORACLE (reject)$/u.exec(lines[0]);
  const pass = /^PASS ([0-9]+) \/ ([0-9]+)$/u.exec(lines[1]);
  const rejectedValid = /^REJECTED-VALID ([0-9]+): (\[[^\r\n]*\])$/u.exec(lines[2]);
  const acceptedInvalid = /^ACCEPTED-INVALID ([0-9]+): (\[[^\r\n]*\])$/u.exec(lines[3]);
  const standard = /^STD-TRUE ([0-9]+) STD-FALSE ([0-9]+)$/u.exec(lines[4]);
  const trueIds = /^STD-TRUE-IDS: (\[[^\r\n]*\])$/u.exec(lines[5]);
  const falseIds = /^STD-FALSE-IDS: (\[[^\r\n]*\])$/u.exec(lines[6]);
  assert(oracle && pass && rejectedValid && acceptedInvalid && standard && trueIds && falseIds, 'aggregate grammar');
  const result = {
    oracle: oracle[1], passed: number(pass[1], 'pass'), total: number(pass[2], 'total'),
    rejectedValid: number(rejectedValid[1], 'rejected-valid'), acceptedInvalid: number(acceptedInvalid[1], 'accepted-invalid'),
    standardTrue: number(standard[1], 'standard true'), standardFalse: number(standard[2], 'standard false'),
    rejectedValidIds: parseUnquotedLeanList(rejectedValid[2], 'rejected-valid'), acceptedInvalidIds: parseUnquotedLeanList(acceptedInvalid[2], 'accepted-invalid'),
    standardTrueIds: parseUnquotedLeanList(trueIds[1], 'standard-true'), standardFalseIds: parseUnquotedLeanList(falseIds[1], 'standard-false'),
  };
  assert(result.total === expected.size && result.passed + result.rejectedValid + result.acceptedInvalid === result.total, 'aggregate count');
  assert(result.standardTrue + result.standardFalse === result.total, 'standard count');
  assert(result.rejectedValidIds.length === Math.min(result.rejectedValid, 20) && result.acceptedInvalidIds.length === Math.min(result.acceptedInvalid, 20), 'mismatch list truncation');
  assert(result.standardTrueIds.length === Math.min(result.standardTrue, 200) && result.standardFalseIds.length === Math.min(result.standardFalse, 200), 'standard list truncation');
  for (const [list, label] of [[result.rejectedValidIds, 'rejected-valid'], [result.acceptedInvalidIds, 'accepted-invalid'], [result.standardTrueIds, 'standard-true'], [result.standardFalseIds, 'standard-false']]) uniqueKnown(list, expected, label);
  assert(result.rejectedValidIds.every(id => expected.get(id).expected?.verdict === 'accept'), 'rejected-valid expected relation');
  assert(result.acceptedInvalidIds.every(id => expected.get(id).expected?.verdict === 'reject'), 'accepted-invalid expected relation');
  assert(!result.standardTrueIds.some(id => result.standardFalseIds.includes(id)), 'standard list overlap');
  return Object.freeze({ ...result, aggregateOnly: true, perItemAuthority: false, executionClaim: null });
}

/** CostProbe is per-item authority for exactly verifyInput and its six metrics. */
export function parseLeanCostprobeRows(stdout, { rows } = {}) {
  assert(typeof stdout === 'string' && stdout.endsWith('\n') && !stdout.includes('\r'), 'CostProbe stdout LF grammar');
  const expected = expectedRows(rows); const lines = stdout.slice(0, -1).split('\n');
  assert(lines.length === expected.size + 1 && lines[0] === 'ORACLE reject', 'CostProbe cardinality/oracle');
  const out = new Map(); let previousOrdinal = -1;
  for (const line of lines.slice(1)) {
    const match = /^METRICS ([^\s]+) ([01]) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)$/u.exec(line);
    const skip = /^SKIP ([^\s]+) (decode|no-metric-phase)$/u.exec(line);
    assert((match !== null) !== (skip !== null), 'CostProbe metrics/SKIP grammar');
    const id = match?.[1] ?? skip?.[1]; assert(expected.has(id) && !out.has(id), 'CostProbe unknown or duplicate id'); const ordinal = [...expected.keys()].indexOf(id); assert(ordinal > previousOrdinal, 'CostProbe row-order drift'); previousOrdinal = ordinal;
    if (skip) out.set(id, Object.freeze({ workItemId: id, status: 'engine-unsupported-incomplete', verifyInput: null, verdict: null, metrics: null, reason: skip[2], executed: false, countedAsExecution: false, countedAsAgreement: false, agreementEligible: false }));
    else { const verifyInput = match[2] === '1'; out.set(id, Object.freeze({ workItemId: id, status: 'observed-script-engine-only', verifyInput, verdict: verifyInput ? 'accept' : 'reject', perItemAuthority: true, metrics: Object.freeze({ evaluatedInstructionCount: number(match[3], 'instruction count'), signatureCheckCount: number(match[4], 'signature count'), hashDigestIterations: number(match[5], 'hash count'), arithmeticCost: number(match[6], 'arithmetic cost'), stackPushedBytes: number(match[7], 'stack bytes'), nativeConsensus64OperationCost: number(match[8], 'operation cost') }) })); }
  }
  assert(out.size === expected.size, 'CostProbe omitted row');
  return out;
}
