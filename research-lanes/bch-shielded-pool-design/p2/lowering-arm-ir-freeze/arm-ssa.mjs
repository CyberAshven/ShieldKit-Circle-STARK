import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const schedule = JSON.parse(readFileSync(new URL('../schedule-freeze/schedule-freeze.v1.json', import.meta.url), 'utf8'));
const lowering = JSON.parse(readFileSync(new URL('../lowering-freeze/lowering-freeze.v1.json', import.meta.url), 'utf8'));

export const CANONICAL_REDUCE_SEMANTICS = '((x mod p)+p) mod p';
export const SCALAR_NODE_OPS = Object.freeze(['add', 'sub', 'mul', 'square', 'scale', 'reduce']);

const mod = (value, p) => ((value % p) + p) % p;
const canonicalJsonValue = (value) => {
  if (Array.isArray(value)) return value.map(canonicalJsonValue);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJsonValue(value[key])]));
  return value;
};
export const canonicalJson = (value) => `${JSON.stringify(canonicalJsonValue(value), null, 2)}\n`;
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const intervalMul = ([a, b], [c, d]) => {
  const candidates = [a * c, a * d, b * c, b * d];
  return [candidates.reduce((x, y) => x < y ? x : y), candidates.reduce((x, y) => x > y ? x : y)];
};
const intervalSquare = ([a, b]) => {
  const upper = (a * a) > (b * b) ? a * a : b * b;
  if (a <= 0n && b >= 0n) return [0n, upper];
  const lower = (a * a) < (b * b) ? a * a : b * b;
  return [lower, upper];
};

export function recomputeNodeRange(node, ranges, modulus) {
  const p = BigInt(modulus);
  const get = (id) => {
    const range = ranges instanceof Map ? ranges.get(id) : ranges[id];
    if (!range) throw new Error(`range unavailable for ${id}`);
    return range.map(BigInt);
  };
  if (node.op === 'reduce') return [0n, p - 1n];
  if (node.op === 'add') {
    const [a, b] = get(node.args[0]);
    const [c, d] = get(node.args[1]);
    return [a + c, b + d];
  }
  if (node.op === 'sub') {
    const [a, b] = get(node.args[0]);
    const [c, d] = get(node.args[1]);
    return [a - d, b - c];
  }
  if (node.op === 'mul') return intervalMul(get(node.args[0]), get(node.args[1]));
  if (node.op === 'square') return intervalSquare(get(node.args[0]));
  if (node.op === 'scale') return intervalMul(get(node.args[0]), [BigInt(node.scalarCanonical), BigInt(node.scalarCanonical)]);
  throw new Error(`unsupported scalar op ${node.op}`);
}

class GraphBuilder {
  constructor({ arm, construction, kind }) {
    this.arm = arm;
    this.construction = construction;
    this.kind = kind;
    this.p = BigInt(construction.p);
    this.nodes = [];
    this.ranges = new Map();
    this.occurrences = [];
    this.matrixOccurrences = [];
    this.mapOccurrences = [];
    this.formulaOccurrences = [];
    this.inputs = [];
    this.context = [];
    this.nodeCounter = 0;
    this.formulaCounter = 0;
    this.matrixCounter = 0;
    this.mapCounter = 0;
    const names = kind === 'multiply' ? ['a', 'b'] : ['a'];
    for (const name of names) for (let index = 0; index < construction.degree; index += 1) {
      const id = `${name}.c${index}`;
      this.inputs.push({ id, type: 'FpCanonical', representation: 'direct-power-basis-coefficient', element: name, coefficientIndex: index, range: ['0', String(this.p - 1n)] });
      this.ranges.set(id, [0n, this.p - 1n]);
    }
  }

  inputVector(name) { return Array.from({ length: this.construction.degree }, (_, index) => `${name}.c${index}`); }
  withContext(label, callback) {
    this.context.push(label);
    try { return callback(); } finally { this.context.pop(); }
  }
  recordFormula(label, disposition = 'expanded-emitted', extra = {}) {
    this.formulaOccurrences.push({ occurrenceIndex: this.formulaCounter++, label, disposition, context: [...this.context], ...extra });
  }
  recordMap(mapId, direction, from, to, disposition = 'alias-wire') {
    this.mapOccurrences.push({ occurrenceIndex: this.mapCounter++, mapId, direction, from, to, disposition, context: [...this.context] });
  }

  raw(op, args, extra = {}) {
    const id = `n${String(this.nodeCounter++).padStart(5, '0')}`;
    const node = { id, op, type: 'FpInteger', args: [...args], context: [...this.context], ...extra };
    const range = recomputeNodeRange(node, this.ranges, this.p);
    node.range = range.map(String);
    this.nodes.push(node);
    this.ranges.set(id, range);
    if (op === 'mul' || op === 'square') {
      this.occurrences.push({
        occurrenceIndex: this.occurrences.length,
        nodeId: id,
        op,
        operands: [...args],
        classification: 'variable-base-Fp-arithmetic',
        constantsAndScalesExcluded: true,
        context: [...this.context]
      });
    }
    const reduceId = `n${String(this.nodeCounter++).padStart(5, '0')}`;
    const reduce = {
      id: reduceId,
      op: 'reduce',
      type: 'FpCanonical',
      args: [id],
      semantics: CANONICAL_REDUCE_SEMANTICS,
      context: [...this.context],
      range: ['0', String(this.p - 1n)]
    };
    this.nodes.push(reduce);
    this.ranges.set(reduceId, [0n, this.p - 1n]);
    return reduceId;
  }
  add(a, b) { return this.raw('add', [a, b]); }
  sub(a, b) { return this.raw('sub', [a, b]); }
  mul(a, b) { return this.raw('mul', [a, b]); }
  square(a) { return this.raw('square', [a]); }
  scale(value, scalar) {
    const source = BigInt(scalar);
    const canonical = mod(source, this.p);
    return this.raw('scale', [value], {
      scalar: String(canonical),
      scalarSource: String(source),
      scalarCanonical: String(canonical),
      scalarProvenance: 'signed-source-canonicalized-mod-p'
    });
  }
  addVectors(a, b) { return a.map((value, index) => this.add(value, b[index])); }
  subVectors(a, b) { return a.map((value, index) => this.sub(value, b[index])); }
  scaleVector(a, scalar) { return a.map((value) => this.scale(value, scalar)); }

  matrixVector(matrix, vector, application) {
    return matrix.entries.map((row, rowIndex) => this.withContext(`matrix:${matrix.matrixId}:${application}:row${rowIndex}`, () => {
      const terms = [];
      row.forEach((encoded, columnIndex) => {
        const scalar = BigInt(encoded);
        const base = vector[columnIndex];
        let disposition;
        let result = null;
        let scaleNodeId = null;
        if (scalar === 0n) disposition = 'omit-zero';
        else if (scalar === 1n) {
          disposition = 'alias-unit';
          result = base;
        } else {
          disposition = 'scale-unique';
          result = this.scale(base, scalar);
          scaleNodeId = this.nodes[this.nodes.length - 2].id;
        }
        this.matrixOccurrences.push({
          occurrenceIndex: this.matrixCounter++, matrixId: matrix.matrixId, application,
          row: rowIndex, column: columnIndex, scalar: String(scalar), input: base,
          disposition, scaleNodeId, result, traversal: 'row-major-strict-left-fold', context: [...this.context]
        });
        if (result !== null) terms.push(result);
      });
      if (terms.length === 0) throw new Error(`${matrix.matrixId} row ${rowIndex} is all zero`);
      let total = terms[0];
      for (let index = 1; index < terms.length; index += 1) total = this.add(total, terms[index]);
      return total;
    }));
  }

  finish(outputs, extra = {}) {
    const actualByOp = { mul: this.occurrences.filter((entry) => entry.op === 'mul').length, square: this.occurrences.filter((entry) => entry.op === 'square').length };
    const program = {
      programId: `${this.arm.armId}:${this.kind}:scalar-ssa-v1`,
      kind: this.kind,
      modulus: String(this.p),
      degree: this.construction.degree,
      inputRepresentation: 'typed-direct-power-basis-formals',
      inputs: this.inputs,
      nodeVocabulary: [...SCALAR_NODE_OPS],
      nodes: this.nodes,
      outputs: outputs.map((ref, coefficientIndex) => ({ coefficientIndex, type: 'FpCanonical', ref })),
      rangeLedger: this.nodes.map((node) => ({
        nodeId: node.id,
        type: node.type,
        inputRanges: node.args.map((ref) => {
          const range = this.ranges.get(ref);
          return { ref, minInclusive: String(range[0]), maxInclusive: String(range[1]) };
        }),
        outputRange: { minInclusive: node.range[0], maxInclusive: node.range[1] },
        normalizationState: node.op === 'reduce' ? 'canonical-mod-p' : 'raw-integer-awaiting-immediate-reduce',
        modulus: String(this.p),
        reason: node.op === 'reduce' ? CANONICAL_REDUCE_SEMANTICS : `inclusive integer interval propagation for ${node.op}`
      })),
      variableBaseOccurrences: this.occurrences,
      variableBaseCounts: {
        declared: this.arm.declaredVariableBaseCounts[this.kind],
        actual: this.occurrences.length,
        byScalarNodeOp: actualByOp,
        interpretation: this.arm.declaredVariableBaseCounts.interpretation
      },
      formulaOccurrences: this.formulaOccurrences,
      matrixOccurrences: this.matrixOccurrences,
      mapOccurrences: this.mapOccurrences,
      canonicalReduction: { semantics: CANONICAL_REDUCE_SEMANTICS, schedule: 'immediately-after-every-scalar-arithmetic-node' },
      ...extra
    };
    program.programDigest = sha256(canonicalJson(program));
    return program;
  }
}

const directReduction = (g, convolution) => g.withContext('direct-quotient-reduction', () => {
  const d = g.construction.degree;
  const p = g.p;
  const signed = g.construction.definingPolynomialAscending.slice(0, d).map((value) => {
    const canonical = BigInt(value);
    return canonical > p / 2n ? canonical - p : canonical;
  });
  const output = convolution.slice(0, d);
  for (let exponent = d; exponent < convolution.length; exponent += 1) {
    for (let index = 0; index < d; index += 1) {
      const factor = -signed[index];
      if (factor === 0n) {
        g.recordFormula(`C${exponent}->r${exponent - d + index}`, 'omit-zero', { factor: '0' });
        continue;
      }
      const target = exponent - d + index;
      const contribution = factor === 1n ? convolution[exponent] : g.scale(convolution[exponent], factor);
      g.recordFormula(`C${exponent}->r${target}`, factor === 1n ? 'alias-unit' : 'scale-unique', { factor: String(factor), contribution });
      output[target] = g.add(output[target], contribution);
    }
  }
  return output;
});

const schoolbook = (g, left, right, square) => {
  const d = left.length;
  const buckets = Array.from({ length: (2 * d) - 1 }, () => []);
  if (square) {
    for (let i = 0; i < d; i += 1) for (let j = i; j < d; j += 1) g.withContext(`schoolbook-square:${i},${j}`, () => {
      let term = i === j ? g.square(left[i]) : g.mul(left[i], left[j]);
      if (i !== j) term = g.scale(term, 2n);
      buckets[i + j].push(term);
    });
  } else {
    for (let i = 0; i < d; i += 1) for (let j = 0; j < d; j += 1) g.withContext(`schoolbook-mul:${i},${j}`, () => buckets[i + j].push(g.mul(left[i], right[j])));
  }
  return buckets.map((terms, exponent) => g.withContext(`convolution:C${exponent}`, () => {
    let total = terms[0];
    for (let index = 1; index < terms.length; index += 1) total = g.add(total, terms[index]);
    return total;
  }));
};

const pairwise = (g, left, right) => {
  const d = left.length;
  const buckets = Array.from({ length: (2 * d) - 1 }, () => []);
  const diagonal = [];
  for (let i = 0; i < d; i += 1) g.withContext(`pairwise:diagonal:${i}`, () => {
    diagonal[i] = g.mul(left[i], right[i]);
    buckets[2 * i].push(diagonal[i]);
  });
  for (let i = 0; i < d; i += 1) for (let j = i + 1; j < d; j += 1) g.withContext(`pairwise:pair:${i},${j}`, () => {
    const pair = g.mul(g.add(left[i], left[j]), g.add(right[i], right[j]));
    const cross = g.sub(g.sub(pair, diagonal[i]), diagonal[j]);
    buckets[i + j].push(cross);
  });
  return buckets.map((terms, exponent) => g.withContext(`pairwise-convolution:C${exponent}`, () => {
    let total = terms[0];
    for (let index = 1; index < terms.length; index += 1) total = g.add(total, terms[index]);
    return total;
  }));
};

const evaluateToom3 = (g, a, label) => g.withContext(`toom3-evaluate:${label}`, () => [
  a[0],
  g.add(g.add(a[0], a[1]), a[2]),
  g.add(g.sub(a[0], a[1]), a[2]),
  g.add(g.add(a[0], g.scale(a[1], 2n)), g.scale(a[2], 4n)),
  a[2]
]);

const toom3Convolution = (g, left, right, squareProducts = false, label = 'toom3') => g.withContext(label, () => {
  const a = evaluateToom3(g, left, 'left');
  const b = squareProducts ? null : evaluateToom3(g, right, 'right');
  const products = a.map((value, index) => g.withContext(`product:${['0', '1', 'minus1', '2', 'infinity'][index]}`, () => squareProducts ? g.square(value) : g.mul(value, b[index])));
  const [p0, p1, pm, p2, pinf] = products;
  const inv2 = (g.p + 1n) / 2n;
  const inv3 = (() => {
    for (let value = 1n; value < 4n; value += 1n) if ((3n * value) % g.p === 1n) return value;
    return (2n * g.p + 1n) / 3n;
  })();
  const s = g.scale(g.add(p1, pm), inv2);
  const delta = g.scale(g.sub(p1, pm), inv2);
  const c2 = g.sub(g.sub(s, p0), pinf);
  const q = g.scale(g.sub(g.sub(g.sub(p2, p0), g.scale(c2, 4n)), g.scale(pinf, 16n)), inv2);
  const c3 = g.scale(g.sub(q, delta), inv3);
  const c1 = g.sub(delta, c3);
  return [p0, c1, c2, c3, pinf];
});

const highToom = (g, left, right, squareProducts) => {
  const [evaluation, interpolation] = g.arm.formula.matrices;
  const leftEval = g.matrixVector(evaluation, left, squareProducts ? 'value' : 'left');
  const rightEval = squareProducts ? null : g.matrixVector(evaluation, right, 'right');
  const products = leftEval.map((value, index) => g.withContext(`finite-product:${index}`, () => squareProducts ? g.square(value) : g.mul(value, rightEval[index])));
  const top = g.withContext('infinity-product', () => squareProducts ? g.square(left[left.length - 1]) : g.mul(left[left.length - 1], right[right.length - 1]));
  const points = g.arm.formula.dagSteps[0].match(/\[(.*)\]/u)[1].split(',').map((entry) => entry.replaceAll('"', '')).slice(0, -1).map(BigInt);
  const adjusted = products.map((value, index) => g.withContext(`top-term-subtraction:${index}`, () => {
    const factor = mod(points[index] ** BigInt((2 * left.length) - 2), g.p);
    if (factor === 0n) {
      g.recordFormula(`finite-top-term:${index}`, 'omit-zero', { factor: '0', result: value });
      return value;
    }
    const term = factor === 1n ? top : g.scale(top, factor);
    g.recordFormula(`finite-top-term:${index}`, factor === 1n ? 'alias-unit' : 'scale-unique', { factor: String(factor), result: term });
    return g.sub(value, term);
  }));
  return [...g.matrixVector(interpolation, adjusted, 'inverse-interpolation'), top];
};

const fp2Add = (g, a, b) => g.addVectors(a, b);
const fp2Sub = (g, a, b) => g.subVectors(a, b);
const fp2Scale = (g, a, scalar) => g.scaleVector(a, scalar);
const fp2Mul = (g, a, b, label) => g.withContext(`Fp2Mul:${label}`, () => {
  const m0 = g.mul(a[0], b[0]);
  const m1 = g.mul(a[1], b[1]);
  const m2 = g.mul(g.add(a[0], a[1]), g.add(b[0], b[1]));
  return [g.add(m0, g.scale(m1, 5n)), g.sub(g.sub(m2, m0), m1)];
});
const fp2Square = (g, a, label) => g.withContext(`Fp2Square2:${label}`, () => {
  const s0 = g.mul(g.add(a[0], a[1]), g.add(a[0], g.scale(a[1], 5n)));
  const s1 = g.mul(a[0], a[1]);
  return [g.sub(s0, g.scale(s1, 6n)), g.scale(s1, 2n)];
});
const fp2MulXi = (g, a) => [g.scale(a[1], 5n), a[0]];

const map2x3 = (g, value, element) => [[0, 3], [1, 4], [2, 5]].map((indices, outer) => indices.map((index, inner) => {
  const to = `${element}.tower2x3[${outer}].c${inner}`;
  g.recordMap('map:m31-d6-direct-to-tower2x3-v1', 'direct-to-tower', value[index], to);
  return value[index];
}));
const unmap2x3 = (g, value) => {
  const wires = [value[0][0], value[1][0], value[2][0], value[0][1], value[1][1], value[2][1]];
  return wires.map((from, index) => {
    g.recordMap('map:m31-d6-tower2x3-to-direct-v1', 'tower-to-direct', from, `output.c${index}`);
    return from;
  });
};

const tower2Six = (g, left, right, square) => {
  const a = map2x3(g, left, 'a');
  const b = square ? a : map2x3(g, right, 'b');
  const product = (x, y, label) => square ? fp2Square(g, x, label) : fp2Mul(g, x, y, label);
  const t0 = product(a[0], b[0], 't0');
  const t1 = product(a[1], b[1], 't1');
  const t2 = product(a[2], b[2], 't2');
  const combined = (i, j, label) => {
    const x = fp2Add(g, a[i], a[j]);
    const y = square ? x : fp2Add(g, b[i], b[j]);
    return product(x, y, label);
  };
  const d2 = fp2Sub(g, fp2Sub(g, combined(1, 2, 'd2'), t1), t2);
  const d4 = fp2Sub(g, fp2Sub(g, combined(0, 1, 'd4'), t0), t1);
  const d6 = fp2Sub(g, fp2Sub(g, combined(0, 2, 'd6'), t0), t2);
  return unmap2x3(g, [fp2Add(g, t0, fp2MulXi(g, d2)), fp2Add(g, d4, fp2MulXi(g, t2)), fp2Add(g, d6, t1)]);
};

const fp2Toom3 = (g, left, right, square) => {
  const evalRing = (value) => [
    value[0],
    fp2Add(g, fp2Add(g, value[0], value[1]), value[2]),
    fp2Add(g, fp2Sub(g, value[0], value[1]), value[2]),
    fp2Add(g, fp2Add(g, value[0], fp2Scale(g, value[1], 2n)), fp2Scale(g, value[2], 4n)),
    value[2]
  ];
  const a = evalRing(left);
  const b = square ? null : evalRing(right);
  const products = a.map((value, index) => square ? fp2Square(g, value, `outer-product-${index}`) : fp2Mul(g, value, b[index], `outer-product-${index}`));
  const [p0, p1, pm, p2, pinf] = products;
  const inv2 = (g.p + 1n) / 2n;
  const inv3 = (2n * g.p + 1n) / 3n;
  const s = fp2Scale(g, fp2Add(g, p1, pm), inv2);
  const delta = fp2Scale(g, fp2Sub(g, p1, pm), inv2);
  const c2 = fp2Sub(g, fp2Sub(g, s, p0), pinf);
  const q = fp2Scale(g, fp2Sub(g, fp2Sub(g, fp2Sub(g, p2, p0), fp2Scale(g, c2, 4n)), fp2Scale(g, pinf, 16n)), inv2);
  const c3 = fp2Scale(g, fp2Sub(g, q, delta), inv3);
  return [p0, fp2Sub(g, delta, c3), c2, c3, pinf];
};

const tower2Toom = (g, left, right, square) => {
  const a = map2x3(g, left, 'a');
  const b = square ? a : map2x3(g, right, 'b');
  const c = fp2Toom3(g, a, b, square);
  return unmap2x3(g, [fp2Add(g, c[0], fp2MulXi(g, c[3])), fp2Add(g, c[1], fp2MulXi(g, c[4])), c[2]]);
};

const map3x2 = (g, value, element) => [[0, 2, 4], [1, 3, 5]].map((indices, outer) => indices.map((index, inner) => {
  const to = `${element}.tower3x2[${outer}].c${inner}`;
  g.recordMap('map:m31-d6-direct-to-tower3x2-v1', 'direct-to-tower', value[index], to);
  return value[index];
}));
const unmap3x2 = (g, value) => {
  const wires = [value[0][0], value[1][0], value[0][1], value[1][1], value[0][2], value[1][2]];
  return wires.map((from, index) => {
    g.recordMap('map:m31-d6-tower3x2-to-direct-v1', 'tower-to-direct', from, `output.c${index}`);
    return from;
  });
};
const fp3MulV = (g, value) => [g.scale(value[2], 5n), value[0], value[1]];
const fp3MulToom = (g, left, right, label) => {
  const c = toom3Convolution(g, left, right, false, `general-inner-Fp3-Toom3:${label}`);
  return [g.add(c[0], g.scale(c[3], 5n)), g.add(c[1], g.scale(c[4], 5n)), c[2]];
};
const tower3 = (g, left, right, square) => {
  const a = map3x2(g, left, 'a');
  const b = square ? a : map3x2(g, right, 'b');
  if (!square) {
    const m0 = fp3MulToom(g, a[0], b[0], 'M0');
    const m1 = fp3MulToom(g, a[1], b[1], 'M1');
    const m2 = fp3MulToom(g, g.addVectors(a[0], a[1]), g.addVectors(b[0], b[1]), 'M2');
    return unmap3x2(g, [g.addVectors(m0, fp3MulV(g, m1)), g.subVectors(g.subVectors(m2, m0), m1)]);
  }
  g.recordFormula('inner-Fp3Square prose declaration', 'recorded-non-emitted', { reason: 'square contract requires exactly two GENERAL inner Fp3-Toom3 multiplications with no equal-input substitution' });
  g.recordFormula('inner-Fp3Mul exact Toom3 declaration', 'expanded-emitted-twice-general', { instances: ['P0-general', 'P1-general'] });
  const p0 = fp3MulToom(g, a[0], a[1], 'P0-general');
  const p1 = fp3MulToom(g, g.addVectors(a[0], a[1]), g.addVectors(a[0], fp3MulV(g, a[1])), 'P1-general');
  return unmap3x2(g, [g.subVectors(p1, g.addVectors(fp3MulV(g, p0), p0)), g.scaleVector(p0, 2n)]);
};

const m89Optimized = (g, left, right, square) => {
  if (square) {
    const s0 = g.mul(g.add(left[0], left[1]), g.sub(left[0], left[1]));
    const s1 = g.mul(left[0], left[1]);
    return [s0, g.scale(s1, 2n)];
  }
  const m0 = g.mul(left[0], right[0]);
  const m1 = g.mul(left[1], right[1]);
  const m2 = g.mul(g.add(left[0], left[1]), g.add(right[0], right[1]));
  return [g.sub(m0, m1), g.sub(g.sub(m2, m0), m1)];
};

const buildProgram = (arm, construction, kind) => {
  const g = new GraphBuilder({ arm, construction, kind });
  const left = g.inputVector('a');
  const right = kind === 'multiply' ? g.inputVector('b') : left;
  const square = kind === 'square';
  let outputs;
  let directReductionDisposition = 'emitted-once';
  if (arm.formula.family === 'canonical-schoolbook') outputs = directReduction(g, schoolbook(g, left, right, square));
  else if (arm.formula.family === 'pairwise') outputs = directReduction(g, pairwise(g, left, right));
  else if (arm.formula.family === 'toom3') outputs = directReduction(g, toom3Convolution(g, left, right, square));
  else if (arm.formula.family === 'toom5' || arm.formula.family === 'toom6') outputs = directReduction(g, highToom(g, left, right, square));
  else if (arm.formula.family === 'karatsuba-quadratic') {
    outputs = m89Optimized(g, left, right, square);
    directReductionDisposition = 'not-emitted-result-already-reduced';
  } else if (arm.formula.family === 'tower2x3-six-product') {
    outputs = tower2Six(g, left, right, square);
    directReductionDisposition = 'not-emitted-result-already-reduced-and-unmapped';
  } else if (arm.formula.family === 'tower2x3-toom3') {
    outputs = tower2Toom(g, left, right, square);
    directReductionDisposition = 'not-emitted-result-already-reduced-and-unmapped';
  } else if (arm.formula.family === 'tower3x2-karatsuba-toom3') {
    outputs = tower3(g, left, right, square);
    directReductionDisposition = 'not-emitted-result-already-reduced-and-unmapped';
  } else throw new Error(`unsupported formula family ${arm.formula.family}`);
  for (const [index, dagStep] of arm.formula.dagSteps.entries()) {
    const disposition = square && arm.formula.family === 'tower3x2-karatsuba-toom3' && index === 0
      ? 'split-disposition-see-specific-inner-Fp3-occurrences'
      : 'expanded-emitted';
    g.recordFormula(`upstream-dag-step:${index}`, disposition, { source: dagStep });
  }
  return g.finish(outputs, { directReductionDisposition });
};

export function generateArmSsa() {
  const constructionById = new Map(schedule.fieldConstructions.map((entry) => [entry.constructionId, entry]));
  const loweringByArm = new Map(lowering.arms.map((entry) => [entry.armId, entry]));
  return schedule.arms.map((arm, orderIndex) => {
    const construction = constructionById.get(arm.constructionId);
    const binding = loweringByArm.get(arm.armId);
    if (!construction || !binding) throw new Error(`missing upstream binding for ${arm.armId}`);
    return {
      orderIndex,
      armId: arm.armId,
      constructionId: arm.constructionId,
      fieldSpecRef: construction.fieldSpecRef,
      trackId: arm.trackId,
      algorithmId: arm.algorithmId,
      formulaId: arm.formula.formulaId,
      formulaFamily: arm.formula.family,
      armDigest: binding.armDigest,
      formulaDigest: binding.formulaDigest,
      modulus: construction.p,
      degree: construction.degree,
      programs: {
        multiply: buildProgram(arm, construction, 'multiply'),
        square: buildProgram(arm, construction, 'square')
      }
    };
  });
}

export function evaluateArmSsa(program, suppliedInputs) {
  if (program === null || typeof program !== 'object') throw new TypeError('program must be an object');
  const p = BigInt(program.modulus);
  const values = new Map();
  for (const formal of program.inputs) {
    if (!(formal.id in suppliedInputs)) throw new Error(`missing input ${formal.id}`);
    const value = BigInt(suppliedInputs[formal.id]);
    if (value < 0n || value >= p) throw new RangeError(`${formal.id} is not canonical`);
    values.set(formal.id, value);
  }
  const read = (id) => {
    if (!values.has(id)) throw new Error(`use before definition or unknown reference ${id}`);
    return values.get(id);
  };
  for (const node of program.nodes) {
    if (values.has(node.id)) throw new Error(`duplicate SSA id ${node.id}`);
    let value;
    if (node.op === 'add') value = read(node.args[0]) + read(node.args[1]);
    else if (node.op === 'sub') value = read(node.args[0]) - read(node.args[1]);
    else if (node.op === 'mul') value = read(node.args[0]) * read(node.args[1]);
    else if (node.op === 'square') value = read(node.args[0]) ** 2n;
    else if (node.op === 'scale') value = read(node.args[0]) * BigInt(node.scalarCanonical);
    else if (node.op === 'reduce') value = mod(read(node.args[0]), p);
    else throw new Error(`opaque or unsupported node op ${node.op}`);
    values.set(node.id, value);
  }
  return program.outputs.map((output) => read(output.ref));
}

const digestWithoutOwnDigest = (program) => {
  const copy = structuredClone(program);
  delete copy.programDigest;
  return sha256(canonicalJson(copy));
};

/** Static validation for the scalar/flat arm layer. It intentionally performs no VM execution. */
export function validateArmSsaProgram(program) {
  const errors = [];
  if (program === null || typeof program !== 'object') return ['program must be an object'];
  let p;
  try { p = BigInt(program.modulus); } catch { return ['program modulus is not an integer']; }
  const ranges = new Map();
  const definitions = new Map();
  for (const input of program.inputs ?? []) {
    if (definitions.has(input.id)) errors.push(`duplicate input ${input.id}`);
    definitions.set(input.id, input);
    ranges.set(input.id, (input.range ?? []).map(BigInt));
    if (input.type !== 'FpCanonical' || input.representation !== 'direct-power-basis-coefficient') errors.push(`input ${input.id} is not a typed direct formal`);
    if (input.range?.[0] !== '0' || input.range?.[1] !== String(p - 1n)) errors.push(`input ${input.id} canonical range mismatch`);
  }
  const nodes = program.nodes ?? [];
  for (let index = 0; index < nodes.length; index += 1) {
    const node = nodes[index];
    if (definitions.has(node.id)) errors.push(`duplicate SSA id ${node.id}`);
    if (!SCALAR_NODE_OPS.includes(node.op)) errors.push(`opaque node op ${node.op}`);
    for (const ref of node.args ?? []) if (!definitions.has(ref)) errors.push(`node ${node.id} uses undefined or later ${ref}`);
    if (node.op === 'reduce') {
      const previous = nodes[index - 1];
      if (!previous || previous.op === 'reduce' || node.args?.[0] !== previous.id) errors.push(`reduce ${node.id} is not paired with immediately preceding arithmetic`);
      if (node.semantics !== CANONICAL_REDUCE_SEMANTICS) errors.push(`reduce ${node.id} semantics mismatch`);
    } else {
      const next = nodes[index + 1];
      if (!next || next.op !== 'reduce' || next.args?.[0] !== node.id) errors.push(`arithmetic ${node.id} lacks immediate distinct reduce`);
      if (node.op === 'scale') {
        let source;
        let canonical;
        try {
          source = BigInt(node.scalarSource);
          canonical = BigInt(node.scalarCanonical);
        } catch { errors.push(`scale ${node.id} lacks integer scalar provenance`); }
        if (source !== undefined && (node.scalarProvenance !== 'signed-source-canonicalized-mod-p' || canonical !== mod(source, p) || node.scalar !== node.scalarCanonical)) {
          errors.push(`scale ${node.id} canonical scalar provenance mismatch`);
        }
      }
    }
    try {
      const range = recomputeNodeRange(node, ranges, p);
      if (node.range?.[0] !== String(range[0]) || node.range?.[1] !== String(range[1])) errors.push(`node ${node.id} range mismatch`);
      ranges.set(node.id, range);
    } catch (error) { errors.push(`node ${node.id} range error: ${error.message}`); }
    definitions.set(node.id, node);
  }
  if ((program.outputs ?? []).length !== program.degree) errors.push('output vector degree mismatch');
  for (const output of program.outputs ?? []) {
    if (!definitions.has(output.ref)) errors.push(`output ${output.coefficientIndex} unknown ref ${output.ref}`);
    const definition = definitions.get(output.ref);
    if (definition?.type !== 'FpCanonical') errors.push(`output ${output.coefficientIndex} is not canonical`);
  }
  const expectedLedger = nodes.map((node) => ({
    nodeId: node.id,
    type: node.type,
    inputRanges: node.args.map((ref) => {
      const range = ranges.get(ref);
      return range
        ? { ref, minInclusive: String(range[0]), maxInclusive: String(range[1]) }
        : { ref, minInclusive: null, maxInclusive: null };
    }),
    outputRange: { minInclusive: node.range[0], maxInclusive: node.range[1] },
    normalizationState: node.op === 'reduce' ? 'canonical-mod-p' : 'raw-integer-awaiting-immediate-reduce',
    modulus: String(p),
    reason: node.op === 'reduce' ? CANONICAL_REDUCE_SEMANTICS : `inclusive integer interval propagation for ${node.op}`
  }));
  if (JSON.stringify(program.rangeLedger) !== JSON.stringify(expectedLedger)) errors.push('range ledger mismatch');

  const arithmetic = nodes.filter((node) => node.op === 'mul' || node.op === 'square');
  const occurrenceIds = (program.variableBaseOccurrences ?? []).map((entry) => entry.nodeId);
  if (JSON.stringify(occurrenceIds) !== JSON.stringify(arithmetic.map((node) => node.id))) errors.push('variable-base occurrence list mismatch');
  if (program.variableBaseCounts?.actual !== arithmetic.length || program.variableBaseCounts?.declared !== arithmetic.length) errors.push('variable-base count mismatch');
  for (const occurrence of program.variableBaseOccurrences ?? []) {
    const node = definitions.get(occurrence.nodeId);
    if (node?.op !== occurrence.op || JSON.stringify(node?.args) !== JSON.stringify(occurrence.operands)) errors.push(`occurrence ${occurrence.occurrenceIndex} metadata mismatch`);
  }

  const reachable = new Set();
  const visit = (ref) => {
    const definition = definitions.get(ref);
    if (!definition || !('op' in definition) || reachable.has(ref)) return;
    reachable.add(ref);
    for (const arg of definition.args) visit(arg);
  };
  for (const output of program.outputs ?? []) visit(output.ref);
  for (const node of nodes) if (!reachable.has(node.id)) errors.push(`dead node ${node.id}`);

  const scaleOwners = new Set();
  for (const occurrence of program.matrixOccurrences ?? []) {
    const scalar = BigInt(occurrence.scalar);
    const expected = scalar === 0n ? 'omit-zero' : scalar === 1n ? 'alias-unit' : 'scale-unique';
    if (occurrence.disposition !== expected) errors.push(`matrix occurrence ${occurrence.occurrenceIndex} disposition mismatch`);
    if (expected === 'omit-zero' && (occurrence.result !== null || occurrence.scaleNodeId !== null)) errors.push(`matrix zero cell ${occurrence.occurrenceIndex} was not omitted`);
    if (expected === 'alias-unit' && (occurrence.result !== occurrence.input || occurrence.scaleNodeId !== null)) errors.push(`matrix unit cell ${occurrence.occurrenceIndex} was not aliased`);
    if (expected === 'scale-unique') {
      const scale = definitions.get(occurrence.scaleNodeId);
      const reduction = nodes[nodes.findIndex((node) => node.id === occurrence.scaleNodeId) + 1];
      if (scale?.op !== 'scale' || scale.scalarCanonical !== occurrence.scalar || scale.args?.[0] !== occurrence.input || reduction?.id !== occurrence.result) errors.push(`matrix scale cell ${occurrence.occurrenceIndex} node mismatch`);
      if (scaleOwners.has(occurrence.scaleNodeId)) errors.push(`matrix scale ${occurrence.scaleNodeId} is shared`);
      scaleOwners.add(occurrence.scaleNodeId);
    }
  }

  const mapIds = new Set((program.mapOccurrences ?? []).map((entry) => entry.mapId));
  const mapKind = [...mapIds].find((id) => id.includes('tower2x3')) ? 'tower2x3' : [...mapIds].find((id) => id.includes('tower3x2')) ? 'tower3x2' : null;
  if (mapKind !== null) {
    const directMapId = `map:m31-d6-direct-to-${mapKind}-v1`;
    const inverseMapId = `map:m31-d6-${mapKind}-to-direct-v1`;
    const elements = program.kind === 'multiply' ? ['a', 'b'] : ['a'];
    const groups = mapKind === 'tower2x3' ? [[0, 3], [1, 4], [2, 5]] : [[0, 2, 4], [1, 3, 5]];
    const expectedDirect = elements.flatMap((element) => groups.flatMap((indices, outer) => indices.map((coefficient, inner) => ({
      mapId: directMapId, direction: 'direct-to-tower', from: `${element}.c${coefficient}`, to: `${element}.${mapKind}[${outer}].c${inner}`
    }))));
    const actualDirect = program.mapOccurrences.filter((entry) => entry.direction === 'direct-to-tower').map(({ mapId, direction, from, to }) => ({ mapId, direction, from, to }));
    if (JSON.stringify(actualDirect) !== JSON.stringify(expectedDirect)) errors.push(`${mapKind} direct map wiring mismatch`);
    const actualInverse = program.mapOccurrences.filter((entry) => entry.direction === 'tower-to-direct');
    if (actualInverse.length !== program.degree || actualInverse.some((entry, index) => entry.mapId !== inverseMapId || entry.to !== `output.c${index}` || entry.from !== program.outputs[index]?.ref)) errors.push(`${mapKind} inverse map wiring mismatch`);
  } else if ((program.mapOccurrences ?? []).length !== 0) errors.push('unrecognized map occurrences');

  if (program.programDigest !== digestWithoutOwnDigest(program)) errors.push('program digest mismatch');
  return errors;
}
