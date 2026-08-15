import { IncrementalMerkle, NullifierSet, commitNote, nullifierOf, type Note } from "./notes.ts";
import { type AnyAmountState } from "./state.ts";
import type { ActionKind, PoolStatement } from "./statement.ts";

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
): { machine: PoolMachine; statement: PoolStatement; change?: Note } {
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
  const leftover = note.amountSats - withdrawSats;
  let noteRoot = oldState.noteRoot;
  if (leftover > 0n) {
    change = {
      amountSats: leftover,
      rho: note.rho,
      ownerSecret: note.ownerSecret,
    };
    const inserted = machine.notes.append(commitNote(change));
    noteRoot = inserted.root;
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
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState }, statement, change };
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
  if (s.newState.withdrawalCount > s.newState.depositCount) throw new Error("over-withdraw");
}

export function actionOf(delta: bigint): ActionKind {
  return delta > 0n ? "DEPOSIT" : "WITHDRAW";
}
