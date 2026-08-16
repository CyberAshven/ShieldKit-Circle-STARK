import { bytesToHex, concatBytes, sha256, writeI64BE, writeU256BE, ZERO32 } from "./bytes.ts";
import { encodeState, type AnyAmountState } from "./state.ts";

export type ActionKind = "DEPOSIT" | "WITHDRAW";

export type PoolStatement = {
  profile: "any-amount-v0";
  action: ActionKind;
  publicAmountSats: bigint;
  oldState: AnyAmountState;
  newState: AnyAmountState;
  noteCommitment: Uint8Array;
  nullifier: Uint8Array;
  payoutLockingDigest: Uint8Array;
  /** Pedersen-style amount commits (BCR 1570), 32-byte BE scalars. */
  amountCommitIn: Uint8Array;
  amountCommitOut: Uint8Array;
};

export function encodeStatement(s: PoolStatement): Uint8Array {
  const actionByte = Uint8Array.of(s.action === "DEPOSIT" ? 1 : 2);
  return concatBytes(
    new TextEncoder().encode("PAA1STMT"),
    actionByte,
    writeI64BE(s.publicAmountSats),
    encodeState(s.oldState),
    encodeState(s.newState),
    s.noteCommitment,
    s.nullifier,
    s.payoutLockingDigest,
    s.amountCommitIn.length === 32 ? s.amountCommitIn : writeU256BE(0n),
    s.amountCommitOut.length === 32 ? s.amountCommitOut : writeU256BE(0n),
  );
}

export function statementDigest(s: PoolStatement): Uint8Array {
  return sha256(encodeStatement(s));
}

export function statementHex(s: PoolStatement): string {
  return bytesToHex(encodeStatement(s));
}
