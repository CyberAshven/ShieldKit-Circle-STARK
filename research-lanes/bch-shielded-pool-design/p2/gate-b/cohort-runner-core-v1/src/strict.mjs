import { createHash } from 'node:crypto';

export class StaticContractError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.name = 'StaticContractError';
    this.code = code;
  }
}

export function fail(code, detail) {
  throw new StaticContractError(code, detail);
}

export function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function requireRecord(value, label) {
  if (!isPlainRecord(value)) fail('K_RECORD', `${label} must be a plain record`);
  return value;
}

export function requireExactKeys(value, required, label) {
  requireRecord(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...required].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail('K_KEYS', `${label} has an unclosed key set`);
  }
  return value;
}

export function requireIdentifier(value, label) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{2,63}$/.test(value)) {
    fail('K_IDENTIFIER', `${label} has invalid grammar`);
  }
  return value;
}

export function requireRoot(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail('K_ROOT', `${label} must be lower-case SHA-256`);
  }
  return value;
}

export function requireUint32(value, label) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    fail('K_UINT32', `${label} is outside uint32`);
  }
  return value;
}

export function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail('K_CANONICAL', 'number is not canonical');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  requireRecord(value, 'canonical value');
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function domainHash(domain, value) {
  if (typeof domain !== 'string' || !/^[A-Z0-9/_-]{3,80}$/.test(domain)) {
    fail('K_DOMAIN', 'domain is outside K grammar');
  }
  const body = Buffer.from(canonicalJson(value), 'utf8');
  const head = Buffer.from(`${domain}\u0000`, 'utf8');
  return createHash('sha256').update(head).update(body).digest('hex');
}

export function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}

export function opaque() {
  return Object.freeze(Object.create(null));
}
