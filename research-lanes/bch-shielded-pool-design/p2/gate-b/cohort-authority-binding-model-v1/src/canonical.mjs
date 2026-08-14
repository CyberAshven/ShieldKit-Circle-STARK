function fail(message) {
  throw new TypeError(`canonical-json-utf8-lf-v1: ${message}`);
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) fail('lone high surrogate');
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail('lone low surrogate');
    }
  }
}

function assertEnumerableDataKeys(value, label, allowLength = false) {
  for (const key of Reflect.ownKeys(value)) {
    if (allowLength && key === 'length') continue;
    if (typeof key !== 'string') fail(`${label} has a symbol key`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(`${label} has a non-data or non-enumerable property`);
    }
  }
}

function encode(value, stack) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    assertScalarString(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail('non-canonical number');
    return JSON.stringify(value);
  }
  if (typeof value === 'undefined' || typeof value === 'bigint' || typeof value === 'function' || typeof value === 'symbol') {
    fail(`unsupported ${typeof value}`);
  }
  if (typeof value !== 'object') fail(`unsupported ${typeof value}`);
  if (stack.has(value)) fail('cyclic input');
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) fail('nonplain array');
      assertEnumerableDataKeys(value, 'array', true);
      if (Object.keys(value).length !== value.length) fail('sparse or extended array');
      const members = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) fail('sparse array');
        members.push(encode(value[index], stack));
      }
      return `[${members.join(',')}]`;
    }
    if (!isPlainRecord(value)) fail('nonplain object');
    assertEnumerableDataKeys(value, 'object');
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => {
      assertScalarString(key);
      return `${JSON.stringify(key)}:${encode(value[key], stack)}`;
    }).join(',')}}`;
  } finally {
    stack.delete(value);
  }
}

function utf8Encode(value) {
  if (typeof value !== 'string') fail('UTF-8 input must be a string');
  assertScalarString(value);
  const bytes = [];
  for (let index = 0; index < value.length; index += 1) {
    let codePoint = value.charCodeAt(index);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (value.charCodeAt(index + 1) - 0xdc00);
      index += 1;
    }
    if (codePoint <= 0x7f) bytes.push(codePoint);
    else if (codePoint <= 0x7ff) bytes.push(0xc0 | (codePoint >>> 6), 0x80 | (codePoint & 0x3f));
    else if (codePoint <= 0xffff) bytes.push(0xe0 | (codePoint >>> 12), 0x80 | ((codePoint >>> 6) & 0x3f), 0x80 | (codePoint & 0x3f));
    else bytes.push(0xf0 | (codePoint >>> 18), 0x80 | ((codePoint >>> 12) & 0x3f), 0x80 | ((codePoint >>> 6) & 0x3f), 0x80 | (codePoint & 0x3f));
  }
  return Uint8Array.from(bytes);
}

function canonicalJson(value) {
  return encode(value, new Set());
}

export { canonicalJson, utf8Encode };
