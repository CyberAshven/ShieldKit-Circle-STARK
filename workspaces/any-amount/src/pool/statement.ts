import { bytesToHex, concatBytes, sha256, writeU256BE } from "./bytes.ts";
import { commitPublicNet } from "../amounts/hash-commit.ts";
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
  /** Tagged SHA-256 amount commits (32 bytes). Not Pedersen. */
  amountCommitIn: Uint8Array;
  amountCommitOut: Uint8Array;
};

export function encodeStatement(s: PoolStatement): Uint8Array {
  const actionByte = Uint8Array.of(s.action === "DEPOSIT" ? 1 : 2);
  return concatBytes(
    new TextEncoder().encode("PAA1STMT"),
    actionByte,
    commitPublicNet(s.publicAmountSats, s.payoutLockingDigest),
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
