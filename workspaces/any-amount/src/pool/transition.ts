import { IncrementalMerkle, NullifierSet, commitNote, freshRho, nullifierOf, type Note } from "./notes.ts";
import { type AnyAmountState } from "./state.ts";
import type { ActionKind, PoolStatement } from "./statement.ts";
import { commitAmount } from "../amounts/pedersen.ts";
import { isZero32, writeU256BE, ZERO32 } from "./bytes.ts";

function blindOf(note: Note): bigint {
  let n = 0n;
  for (const b of note.rho) n = (n << 8n) | BigInt(b);
  return n;
}

export type PoolMachine = {
  state: AnyAmountState;
  notes: IncrementalMerkle;
  nullifiers: NullifierSet;
};

export function applyDeposit(
  machine: PoolMachine,
  note: Note,
): { machine: PoolMachine; statement: PoolStatement; index: number } {
  if (note.amountSats <= 0n) throw new Error("deposit amount must be > 0");
  const leaf = commitNote(note);
  const oldState = machine.state;
  const { index, root } = machine.notes.append(leaf);
  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats + note.amountSats,
    depositCount: oldState.depositCount + 1n,
    noteRoot: root,
  };
  const statement: PoolStatement = {
    profile: "any-amount-v0",
    action: "DEPOSIT",
    publicAmountSats: note.amountSats,
    oldState,
    newState,
    noteCommitment: leaf,
    nullifier: new Uint8Array(32),
    payoutLockingDigest: new Uint8Array(32),
    amountCommitIn: new Uint8Array(ZERO32),
    amountCommitOut: writeU256BE(commitAmount(note.amountSats, blindOf(note))),
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState }, statement, index };
}

export function applyWithdraw(
  machine: PoolMachine,
  note: Note,
  index: number,
  payoutLockingDigest: Uint8Array,
  withdrawSats: bigint,
): { machine: PoolMachine; statement: PoolStatement; change?: Note; changeIndex?: number } {
  if (withdrawSats <= 0n) throw new Error("withdraw amount must be > 0");
  if (withdrawSats > note.amountSats) throw new Error("withdraw exceeds note");
  const leaf = commitNote(note);
  const path = machine.notes.authPath(index);
  if (!IncrementalMerkle.verify(leaf, index, path, machine.state.noteRoot)) {
    throw new Error("note not in tree");
  }
  const nf = nullifierOf(note, machine.state.poolInstanceId);
  const oldState = machine.state;
  const nullifierRoot = machine.nullifiers.add(nf);

  let change: Note | undefined;
  let changeIndex: number | undefined;
  const leftover = note.amountSats - withdrawSats;
  let noteRoot = oldState.noteRoot;
  if (leftover > 0n) {
    change = {
      amountSats: leftover,
      rho: freshRho(),
      ownerSecret: note.ownerSecret,
    };
    const inserted = machine.notes.append(commitNote(change));
    noteRoot = inserted.root;
    changeIndex = inserted.index;
  }

  const newState: AnyAmountState = {
    ...oldState,
    sequence: oldState.sequence + 1n,
    reserveSats: oldState.reserveSats - withdrawSats,
    withdrawalCount: oldState.withdrawalCount + 1n,
    noteRoot,
    nullifierRoot,
  };
  const statement: PoolStatement = {
    profile: "any-amount-v0",
    action: "WITHDRAW",
    publicAmountSats: -withdrawSats,
    oldState,
    newState,
    noteCommitment: leftover > 0n ? commitNote(change!) : new Uint8Array(32),
    nullifier: nf,
    payoutLockingDigest,
    amountCommitIn: writeU256BE(commitAmount(note.amountSats, blindOf(note))),
    amountCommitOut:
      leftover > 0n && change
        ? writeU256BE(commitAmount(change.amountSats, blindOf(change)))
        : new Uint8Array(ZERO32),
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState }, statement, change, changeIndex };
}

export function checkPublicTransition(s: PoolStatement): void {
  if (s.oldState.poolInstanceId.some((b, i) => b !== s.newState.poolInstanceId[i])) {
    throw new Error("poolInstanceId mutated");
  }
  if (s.newState.sequence !== s.oldState.sequence + 1n) throw new Error("sequence");
  const expectedReserve = s.oldState.reserveSats + s.publicAmountSats;
  if (s.newState.reserveSats !== expectedReserve) throw new Error("reserve");
  if (s.action === "DEPOSIT") {
    if (s.publicAmountSats <= 0n) throw new Error("deposit delta");
    if (s.newState.depositCount !== s.oldState.depositCount + 1n) throw new Error("depositCount");
  } else {
    if (s.publicAmountSats >= 0n) throw new Error("withdraw delta");
    if (s.newState.withdrawalCount !== s.oldState.withdrawalCount + 1n) {
      throw new Error("withdrawalCount");
    }
  }
  if (s.newState.reserveSats < 0n) throw new Error("over-withdraw");
  if (s.amountCommitIn.length !== 32 || s.amountCommitOut.length !== 32) {
    throw new Error("amount commit width");
  }
  if (s.action === "DEPOSIT" && isZero32(s.amountCommitOut)) {
    throw new Error("deposit amount commit");
  }
  if (s.action === "WITHDRAW" && isZero32(s.amountCommitIn)) {
    throw new Error("withdraw amount commit");
  }
}

export function actionOf(delta: bigint): ActionKind {
  return delta > 0n ? "DEPOSIT" : "WITHDRAW";
}
