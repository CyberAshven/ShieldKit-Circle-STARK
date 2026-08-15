import { createHash, timingSafeEqual } from 'node:crypto';

const fail = (message) => {
  throw new TypeError(message);
};

export const assertBytes = (value, name = 'bytes') => {
  if (!(value instanceof Uint8Array)) fail(`${name} must be a Uint8Array`);
  return value;
};

export const concatBytes = (...chunks) => {
  let length = 0;
  for (let index = 0; index < chunks.length; index += 1) {
    length += assertBytes(chunks[index], `chunks[${index}]`).length;
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
};

export const utf8 = (value, name = 'text') => {
  if (typeof value !== 'string') fail(`${name} must be a string`);
  return new TextEncoder().encode(value);
};

export const u16le = (value) => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) fail('u16 value is out of range');
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff);
};

export const u32le = (value) => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) fail('u32 value is out of range');
  return Uint8Array.of(
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  );
};

export const readU32le = (bytes, offset = 0) => {
  const input = assertBytes(bytes);
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + 4 > input.length) {
    fail('u32 read is out of bounds');
  }
  return (
    input[offset]
    + input[offset + 1] * 0x100
    + input[offset + 2] * 0x1_0000
    + input[offset + 3] * 0x100_0000
  );
};

export const sha256 = (bytes) => new Uint8Array(
  createHash('sha256').update(assertBytes(bytes)).digest(),
);

export const hash256 = (bytes) => sha256(sha256(bytes));

export const equalBytes = (left, right) => {
  const a = assertBytes(left, 'left');
  const b = assertBytes(right, 'right');
  return a.length === b.length && timingSafeEqual(a, b);
};

export const frameBytes = (label, payload) => {
  const labelBytes = utf8(label, 'label');
  const data = assertBytes(payload, 'payload');
  if (labelBytes.length > 0xffff) fail('label is too long');
  if (data.length > 0xffff_ffff) fail('payload is too long');
  return concatBytes(u16le(labelBytes.length), labelBytes, u32le(data.length), data);
};
