/**
 * Host-only reference for a direct-polynomial finite extension.
 *
 * The configuration is deliberately separate from values: an instance owns
 * one immutable modulus/polynomial/codec configuration and all element
 * operations go through that instance.  This is arithmetic reference code,
 * not a protocol field selection or an on-chain implementation.
 */

export class DirectExtensionError extends TypeError {}

const fail = (message) => { throw new DirectExtensionError(message); };

const assertSafePositiveInteger = (value, name) => {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${name} must be a positive safe integer`);
  return value;
};

const assertBigInt = (value, name) => {
  if (typeof value !== 'bigint') fail(`${name} must be a BigInt`);
  return value;
};

const assertBytes = (value, name) => {
  if (!(value instanceof Uint8Array)) fail(`${name} must be a Uint8Array`);
  return value;
};

const assertOffset = (offset, name = 'offset') => {
  if (!Number.isSafeInteger(offset) || offset < 0) fail(`${name} must be a nonnegative safe integer`);
  return offset;
};

const bitLength = (value) => {
  let bits = 0;
  for (let current = value; current > 0n; current >>= 1n) bits += 1;
  return bits;
};

const mod = (value, modulus) => ((value % modulus) + modulus) % modulus;

const selectConfigValue = (input, primary, alias, name) => {
  if (input[primary] !== undefined && input[alias] !== undefined && input[primary] !== input[alias]) {
    fail(`config.${primary} and config.${alias} disagree`);
  }
  return input[primary] ?? input[alias];
};

/** Convert strictly lowercase, even-length hexadecimal text to bytes. */
export function hexToBytesStrict(hex, name = 'hex') {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hex)) {
    fail(`${name} must be lowercase even-length hex`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes, name = 'bytes') {
  assertBytes(bytes, name);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Require two offsets to describe one completely consumed input. */
export function assertFullConsumption(offset, length, name = 'input') {
  const consumed = assertOffset(offset, `${name} offset`);
  const total = assertOffset(length, `${name} length`);
  if (consumed !== total) fail(`${name} has trailing or unconsumed bytes: ${total - consumed}`);
  return true;
}

const normalizeConfig = (input) => {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) fail('direct-extension config must be an object');

  const modulus = selectConfigValue(input, 'modulus', 'p', 'modulus');
  assertBigInt(modulus, 'config.modulus');
  if (modulus < 2n) fail('config.modulus must be at least 2');

  const degree = selectConfigValue(input, 'degree', 'extensionDegree', 'degree');
  assertSafePositiveInteger(degree, 'config.degree');

  const limbBytes = selectConfigValue(input, 'limbBytes', 'baseLimbBytes', 'limbBytes');
  assertSafePositiveInteger(limbBytes, 'config.limbBytes');

  const polynomial = selectConfigValue(input, 'definingPolynomial', 'polynomial', 'definingPolynomial');
  if (!Array.isArray(polynomial) || polynomial.length !== degree + 1) {
    fail(`config.definingPolynomial must have exactly degree+1 (${degree + 1}) coefficients`);
  }
  const coefficients = polynomial.map((coefficient, index) => {
    assertBigInt(coefficient, `config.definingPolynomial[${index}]`);
    if (coefficient < 0n || coefficient >= modulus) {
      fail(`config.definingPolynomial[${index}] must be in [0, ${modulus - 1n}]`);
    }
    return coefficient;
  });
  if (coefficients[degree] !== 1n) fail('config.definingPolynomial must be monic (leading coefficient 1)');

  const modulusBitLength = bitLength(modulus);
  const minimumLimbBytes = Math.ceil(modulusBitLength / 8);
  if (limbBytes !== minimumLimbBytes) {
    fail(`config.limbBytes ${limbBytes} must equal the minimum fixed width ${minimumLimbBytes} for modulus bit length ${modulusBitLength}`);
  }
  const unusedHighBits = limbBytes * 8 - modulusBitLength;
  const unusedHighBitMask = unusedHighBits === 0 ? 0 : (0xff << (8 - unusedHighBits)) & 0xff;

  return Object.freeze({
    modulus,
    degree,
    limbBytes,
    definingPolynomial: Object.freeze(coefficients),
    modulusBitLength,
    unusedHighBits,
    unusedHighBitMask,
    elementBytes: degree * limbBytes,
  });
};

/**
 * A direct-polynomial extension context.
 *
 * The defining polynomial is f0 + ... + f(d-1)x^(d-1) + x^d.  Reduction uses
 * x^d = -sum(f_i*x^i), with coefficient arithmetic reduced modulo p after
 * every schoolbook update.  No irreducibility claim is made by this module;
 * inverseForCertifiedField requires an external irreducibility certificate as
 * a precondition and verifies its returned result before accepting it.
 */
export class DirectExtension {
  #config;

  constructor(config) {
    this.#config = normalizeConfig(config);
  }

  get config() { return this.#config; }
  get modulus() { return this.#config.modulus; }
  get degree() { return this.#config.degree; }
  get limbBytes() { return this.#config.limbBytes; }
  get elementBytes() { return this.#config.elementBytes; }
  get definingPolynomial() { return this.#config.definingPolynomial; }
  get unusedHighBits() { return this.#config.unusedHighBits; }
  get unusedHighBitMask() { return this.#config.unusedHighBitMask; }

  assertElement(value, name = 'extension element') {
    if (!Array.isArray(value) || value.length !== this.degree) {
      fail(`${name} must have exactly ${this.degree} coefficients`);
    }
    return value.map((coefficient, index) => {
      assertBigInt(coefficient, `${name}.c${index}`);
      if (coefficient < 0n || coefficient >= this.modulus) {
        fail(`${name}.c${index} must be in [0, ${this.modulus - 1n}]`);
      }
      return coefficient;
    });
  }

  zero() { return Array(this.degree).fill(0n); }
  one() { return [1n, ...Array(this.degree - 1).fill(0n)]; }
  isZero(value) { return this.assertElement(value).every((coefficient) => coefficient === 0n); }

  /** Encode one canonical coefficient as exactly limbBytes unsigned LE bytes. */
  encodeCoefficient(value, name = 'coefficient') {
    assertBigInt(value, name);
    if (value < 0n || value >= this.modulus) fail(`${name} must be in [0, ${this.modulus - 1n}]`);
    let current = value;
    const bytes = new Uint8Array(this.limbBytes);
    for (let index = 0; index < this.limbBytes; index += 1) {
      bytes[index] = Number(current & 0xffn);
      current >>= 8n;
    }
    return bytes;
  }

  /** Decode one exact-width canonical coefficient; high bits are checked first. */
  decodeCoefficient(input, name = 'coefficient input') {
    const bytes = assertBytes(input, name);
    if (bytes.length !== this.limbBytes) {
      fail(`${name} must be exactly ${this.limbBytes} bytes; got ${bytes.length}`);
    }
    if ((bytes[this.limbBytes - 1] & this.unusedHighBitMask) !== 0) {
      fail(`${name} has a set unused high bit`);
    }
    let value = 0n;
    for (let index = this.limbBytes - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]);
    if (value >= this.modulus) fail(`${name} wire value ${value} is not canonical (>= p)`);
    return value;
  }

  encode(value) {
    const coefficients = this.assertElement(value);
    const bytes = new Uint8Array(this.elementBytes);
    for (let index = 0; index < this.degree; index += 1) bytes.set(this.encodeCoefficient(coefficients[index], `element.c${index}`), index * this.limbBytes);
    return bytes;
  }

  decode(input) {
    const bytes = assertBytes(input, 'extension input');
    if (bytes.length !== this.elementBytes) {
      fail(`extension input must be exactly ${this.elementBytes} bytes; got ${bytes.length}`);
    }
    const coefficients = [];
    for (let index = 0; index < this.degree; index += 1) {
      const start = index * this.limbBytes;
      coefficients.push(this.decodeCoefficient(bytes.slice(start, start + this.limbBytes), `extension coefficient ${index}`));
    }
    assertFullConsumption(this.elementBytes, bytes.length, 'extension input');
    return coefficients;
  }

  encodeHex(value) { return bytesToHex(this.encode(value)); }

  decodeHex(hex) {
    if (typeof hex !== 'string' || hex.length !== this.elementBytes * 2) {
      fail(`extension hex input must be exactly ${this.elementBytes * 2} lowercase hex characters`);
    }
    return this.decode(hexToBytesStrict(hex, 'extension hex input'));
  }

  read(input, offset = 0) {
    const bytes = assertBytes(input, 'extension input');
    const start = assertOffset(offset);
    if (start + this.elementBytes > bytes.length) fail(`extension input ends before offset ${start + this.elementBytes}`);
    return { value: this.decode(bytes.slice(start, start + this.elementBytes)), nextOffset: start + this.elementBytes };
  }

  decodeSequence(input) {
    const bytes = assertBytes(input, 'extension sequence');
    const values = [];
    let offset = 0;
    while (offset < bytes.length) {
      const read = this.read(bytes, offset);
      values.push(read.value);
      offset = read.nextOffset;
    }
    assertFullConsumption(offset, bytes.length, 'extension sequence');
    return values;
  }

  add(left, right) {
    const a = this.assertElement(left, 'left');
    const b = this.assertElement(right, 'right');
    return a.map((coefficient, index) => mod(coefficient + b[index], this.modulus));
  }

  sub(left, right) {
    const a = this.assertElement(left, 'left');
    const b = this.assertElement(right, 'right');
    return a.map((coefficient, index) => mod(coefficient - b[index], this.modulus));
  }

  neg(value) {
    const coefficients = this.assertElement(value);
    return coefficients.map((coefficient) => coefficient === 0n ? 0n : this.modulus - coefficient);
  }

  /** Deterministic schoolbook multiply followed by descending naive reduction. */
  mul(left, right) {
    const a = this.assertElement(left, 'left');
    const b = this.assertElement(right, 'right');
    const product = Array(2 * this.degree - 1).fill(0n);
    for (let i = 0; i < this.degree; i += 1) {
      for (let j = 0; j < this.degree; j += 1) {
        product[i + j] = mod(product[i + j] + a[i] * b[j], this.modulus);
      }
    }
    for (let k = product.length - 1; k >= this.degree; k -= 1) {
      const high = product[k];
      product[k] = 0n;
      if (high === 0n) continue;
      for (let i = 0; i < this.degree; i += 1) {
        product[k - this.degree + i] = mod(product[k - this.degree + i] - high * this.definingPolynomial[i], this.modulus);
      }
    }
    return product.slice(0, this.degree).map((coefficient) => mod(coefficient, this.modulus));
  }

  square(value) { return this.mul(value, value); }

  /** Deterministic square-and-multiply for a nonnegative BigInt exponent. */
  pow(value, exponent) {
    const input = this.assertElement(value, 'value');
    assertBigInt(exponent, 'exponent');
    if (exponent < 0n) fail('exponent must be a nonnegative BigInt');
    let result = this.one();
    let base = input;
    let remaining = exponent;
    while (remaining !== 0n) {
      if ((remaining & 1n) !== 0n) result = this.mul(result, base);
      remaining >>= 1n;
      if (remaining !== 0n) base = this.square(base);
    }
    return result;
  }

  equal(left, right) {
    const a = this.assertElement(left, 'left');
    const b = this.assertElement(right, 'right');
    return a.every((coefficient, index) => coefficient === b[index]);
  }

  /** Verify, but do not calculate, a prover-supplied inverse hint. */
  verifyInverseHint(value, hint) {
    const input = this.assertElement(value, 'value');
    const candidate = this.assertElement(hint, 'inverse hint');
    if (this.isZero(input)) fail('zero has no inverse hint');
    return this.equal(this.mul(input, candidate), this.one());
  }

  inverseWithHint(value, hint) {
    if (!this.verifyInverseHint(value, hint)) fail('inverse hint does not verify');
    return this.assertElement(hint, 'inverse hint');
  }

  /**
   * Calculate a^(p^d-2) under an externally certified field assumption.
   * The quotient's irreducibility is not checked here. The final product
   * check only rejects an invalid inverse for this input; it is not a
   * substitute for the external irreducibility certificate.
   */
  inverseForCertifiedField(value) {
    const input = this.assertElement(value, 'value');
    if (this.isZero(input)) fail('zero has no inverse in a certified field');
    const exponent = (this.modulus ** BigInt(this.degree)) - 2n;
    const candidate = this.pow(input, exponent);
    if (!this.equal(this.mul(input, candidate), this.one())) {
      fail('certified-field inverse does not verify; check the external irreducibility precondition and arithmetic configuration');
    }
    return candidate;
  }
}

export function createDirectExtension(config) {
  return new DirectExtension(config);
}
