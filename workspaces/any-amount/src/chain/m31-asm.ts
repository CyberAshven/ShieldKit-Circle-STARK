/** M31 field snippets for the 2026 VM. Intermediates fit VM BigInt; reduce with OP_MOD. */
export const M31_P = 2147483647;

export const M31_MUL = `OP_MUL <${M31_P}> OP_MOD`;
export const M31_ADD = `OP_ADD <${M31_P}> OP_MOD`;
/** a b → (a − b) mod p  (add p before MOD so a < b is safe). */
export const M31_SUB = `OP_SUB <${M31_P}> OP_ADD <${M31_P}> OP_MOD`;

export function pushM31(n: bigint | number): string {
  return `<${typeof n === "bigint" ? n.toString() : n}>`;
}

/** Concatenate 4-byte LE felts (high bit clear for M31). */
export function encodeFeltBlob(vals: readonly bigint[]): Uint8Array {
  const out = new Uint8Array(vals.length * 4);
  for (let i = 0; i < vals.length; i += 1) {
    let n = vals[i]!;
    if (n < 0n || n >= 2147483647n) throw new Error(`felt ${n}`);
    const o = i * 4;
    out[o] = Number(n & 0xffn);
    out[o + 1] = Number((n >> 8n) & 0xffn);
    out[o + 2] = Number((n >> 16n) & 0xffn);
    out[o + 3] = Number((n >> 24n) & 0xffn);
  }
  return out;
}

export function decodeFeltBlob(bytes: Uint8Array): bigint[] {
  if (bytes.length % 4 !== 0) throw new Error("felt blob");
  const out: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 4) {
    out.push(
      BigInt(bytes[i]!) |
        (BigInt(bytes[i + 1]!) << 8n) |
        (BigInt(bytes[i + 2]!) << 16n) |
        (BigInt(bytes[i + 3]!) << 24n),
    );
  }
  return out;
}
