const decimalPattern = /^(?:0|[1-9][0-9]*)$/u;

const gcd = (left, right) => {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
};

const parseRational = (value, label, errors) => {
  if (value === null || typeof value !== 'object') {
    errors.push(`${label} is not an exact rational`);
    return null;
  }
  if (!decimalPattern.test(value.numerator ?? '') || !/^[1-9][0-9]*$/u.test(value.denominator ?? '')) {
    errors.push(`${label} is not canonical unsigned decimal`);
    return null;
  }
  const numerator = BigInt(value.numerator);
  const denominator = BigInt(value.denominator);
  if (numerator > denominator) errors.push(`${label} exceeds probability 1`);
  if (gcd(numerator, denominator) !== 1n) errors.push(`${label} is not reduced`);
  return { numerator, denominator };
};

const reduceRational = ({ numerator, denominator }) => {
  if (numerator === 0n) return { numerator: 0n, denominator: 1n };
  const divisor = gcd(numerator, denominator);
  return { numerator: numerator / divisor, denominator: denominator / divisor };
};

const addRational = (left, right) => reduceRational({
  numerator: left.numerator * right.denominator + right.numerator * left.denominator,
  denominator: left.denominator * right.denominator
});

const capAtOne = (value) => value.numerator >= value.denominator
  ? { numerator: 1n, denominator: 1n }
  : value;

export const exactFloorSecurityBits = ({ numerator, denominator }) => {
  if (numerator <= 0n || denominator <= 0n || numerator > denominator) return null;
  let scaled = numerator;
  let bits = 0;
  while (scaled * 2n <= denominator) {
    scaled *= 2n;
    bits += 1;
  }
  return bits;
};

const sameRational = (left, right) => left.numerator === right.numerator && left.denominator === right.denominator;

const hasPath = (startId, targetId, nodesById, visited = new Set()) => {
  if (startId === targetId) return true;
  if (visited.has(startId)) return false;
  visited.add(startId);
  const node = nodesById.get(startId);
  return (node?.dependsOn ?? []).some((dependencyId) => hasPath(dependencyId, targetId, nodesById, visited));
};

export const validateSoundnessEventDagV2 = (worksheet) => {
  const errors = [];
  if (worksheet.qualificationBoundary !== 'prequalification-only') {
    errors.push('v2 soundness worksheet is restricted to the prequalification-only boundary');
  }
  const assumptions = new Set();
  for (const assumption of worksheet.assumptions ?? []) {
    if (assumptions.has(assumption.assumptionId)) errors.push(`duplicate assumption ${assumption.assumptionId}`);
    assumptions.add(assumption.assumptionId);
  }

  const nodesById = new Map();
  for (const node of worksheet.eventDag?.nodes ?? []) {
    if (nodesById.has(node.eventId)) errors.push(`duplicate event ${node.eventId}`);
    nodesById.set(node.eventId, node);
  }

  for (const node of nodesById.values()) {
    for (const dependencyId of node.dependsOn ?? []) {
      if (!nodesById.has(dependencyId)) errors.push(`event ${node.eventId} has dangling dependency ${dependencyId}`);
      if (dependencyId === node.eventId) errors.push(`event ${node.eventId} depends on itself`);
    }
    for (const assumptionId of node.bound?.assumptionRefs ?? []) {
      if (!assumptions.has(assumptionId)) errors.push(`event ${node.eventId} has dangling assumption ${assumptionId}`);
    }
    if (node.bound?.form === 'exact-rational') parseRational(node.bound.exactUpperBound, `event ${node.eventId} bound`, errors);
  }

  const visiting = new Set();
  const visited = new Set();
  const visit = (eventId) => {
    if (visiting.has(eventId)) {
      errors.push(`event DAG contains a cycle through ${eventId}`);
      return;
    }
    if (visited.has(eventId) || !nodesById.has(eventId)) return;
    visiting.add(eventId);
    for (const dependencyId of nodesById.get(eventId).dependsOn ?? []) visit(dependencyId);
    visiting.delete(eventId);
    visited.add(eventId);
  };
  for (const eventId of nodesById.keys()) visit(eventId);

  const union = worksheet.eventDag?.systemicUnion;
  const summandIds = union?.summandRefs ?? [];
  const summandSet = new Set(summandIds);
  if (summandSet.size !== summandIds.length) errors.push('systemic union contains duplicate summand references');

  const systemicNodes = [...nodesById.values()].filter((node) => node.accounting?.mode === 'systemic-summand');
  for (const node of systemicNodes) {
    if (!summandSet.has(node.eventId)) errors.push(`systemic event ${node.eventId} is omitted from the union`);
  }
  for (const eventId of summandIds) {
    const node = nodesById.get(eventId);
    if (!node) errors.push(`systemic union has dangling summand ${eventId}`);
    else if (node.accounting?.mode !== 'systemic-summand') errors.push(`derivation-only event ${eventId} is included in the union`);
  }

  const eventKeys = new Set();
  const opportunitySets = new Set();
  const samplerOwners = new Map();
  for (const node of systemicNodes) {
    const { eventKey, opportunitySetId, samplerRefs = [] } = node.accounting ?? {};
    if (eventKeys.has(eventKey)) errors.push(`duplicate systemic event key ${eventKey}`);
    eventKeys.add(eventKey);
    if (opportunitySets.has(opportunitySetId)) errors.push(`duplicate systemic opportunity set ${opportunitySetId}`);
    opportunitySets.add(opportunitySetId);
  }
  for (const node of nodesById.values()) {
    for (const samplerRef of node.accounting?.samplerRefs ?? []) {
      if (samplerOwners.has(samplerRef)) {
        errors.push(`sampler ${samplerRef} is owned by both ${samplerOwners.get(samplerRef)} and ${node.eventId}`);
      } else {
        samplerOwners.set(samplerRef, node.eventId);
      }
    }
    if (node.bound?.multiplicity !== 1) {
      errors.push(`event ${node.eventId} must use unit multiplicity in prequalification v2`);
    }
  }

  for (let outerIndex = 0; outerIndex < summandIds.length; outerIndex += 1) {
    for (let innerIndex = outerIndex + 1; innerIndex < summandIds.length; innerIndex += 1) {
      const outer = summandIds[outerIndex];
      const inner = summandIds[innerIndex];
      if (hasPath(outer, inner, nodesById) || hasPath(inner, outer, nodesById)) {
        errors.push(`systemic union counts an ancestor and descendant: ${outer}, ${inner}`);
      }
    }
  }

  if (['derived', 'measured'].includes(union?.status)) {
    let sum = { numerator: 0n, denominator: 1n };
    for (const eventId of summandIds) {
      const node = nodesById.get(eventId);
      if (!node) continue;
      if (!['derived', 'measured'].includes(node.bound?.status)) {
        errors.push(`derived systemic union includes unqualified event ${eventId}`);
        continue;
      }
      if (node.bound?.form !== 'exact-rational') {
        errors.push(`derived systemic union requires exact-rational event ${eventId}`);
        continue;
      }
      const parsed = parseRational(node.bound.exactUpperBound, `event ${eventId} bound`, errors);
      if (parsed) sum = addRational(sum, parsed);
    }
    sum = capAtOne(sum);
    const declared = parseRational(union.exactUpperBound, 'systemic union bound', errors);
    if (declared && !sameRational(sum, declared)) {
      errors.push(`systemic union mismatch: expected ${sum.numerator}/${sum.denominator}, got ${declared.numerator}/${declared.denominator}`);
    }
    const expectedBits = exactFloorSecurityBits(sum);
    if (expectedBits === null) errors.push('derived systemic union must have a nonzero exact upper bound');
    else if (union.floorSecurityBits !== expectedBits) {
      errors.push(`systemic security-bit mismatch: expected ${expectedBits}, got ${union.floorSecurityBits}`);
    }
  }

  if (worksheet.artifactDigests?.candidateTuple !== worksheet.candidateTupleDigest) {
    errors.push('candidate tuple digest disagrees with artifactDigests.candidateTuple');
  }
  if (worksheet.conclusion?.qualification === '128-bit-pass') {
    errors.push('v2 cannot express a qualification pass; use a future provenance-closed worksheet revision');
  }

  return errors;
};

export const assertSoundnessEventDagV2 = (worksheet) => {
  const errors = validateSoundnessEventDagV2(worksheet);
  if (errors.length > 0) throw new Error(errors.join('\n'));
};
