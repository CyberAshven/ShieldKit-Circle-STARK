import { IncrementalMerkle, NullifierSet, commitNote, freshRho, nullifierOf, type Note } from "./notes.ts";
import { type AnyAmountState } from "./state.ts";
import type { ActionKind, PoolStatement } from "./statement.ts";
import { commitAmount } from "../amounts/hash-commit.ts";
import { isZero32, ZERO32 } from "./bytes.ts";

export type PoolMachine = {
  state: AnyAmountState;
  notes: IncrementalMerkle;
  nullifiers: NullifierSet;
};

export function applyDeposit(
  machine: PoolMachine,
  note: Note,
): { machine: PoolMachine; statement: PoolStatement; index: number; path: Uint8Array[] } {
  if (note.amountSats <= 0n) throw new Error("deposit amount must be > 0");
  const hash = machine.notes.hash;
  const leaf = commitNote(note, hash);
  const oldState = machine.state;
  const { index, root, path } = machine.notes.append(leaf);
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
    amountCommitOut: commitAmount(note.amountSats, note.rho, hash),
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState }, statement, index, path };
}

export function applyWithdraw(
  machine: PoolMachine,
  note: Note,
  index: number,
  payoutLockingDigest: Uint8Array,
  withdrawSats: bigint,
): {
  machine: PoolMachine;
  statement: PoolStatement;
  change?: Note;
  changeIndex?: number;
  path: Uint8Array[];
  created?: { note: Note; index: number; path: Uint8Array[] };
} {
  if (withdrawSats <= 0n) throw new Error("withdraw amount must be > 0");
  if (withdrawSats > note.amountSats) throw new Error("withdraw exceeds note");
  const hash = machine.notes.hash;
  const leaf = commitNote(note, hash);
  const path = machine.notes.authPath(index);
  if (!IncrementalMerkle.verify(leaf, index, path, machine.state.noteRoot, hash)) {
    throw new Error("note not in tree");
  }
  const nf = nullifierOf(note, machine.state.poolInstanceId, hash);
  const oldState = machine.state;
  const nullifierRoot = machine.nullifiers.add(nf);

  let change: Note | undefined;
  let changeIndex: number | undefined;
  let created: { note: Note; index: number; path: Uint8Array[] } | undefined;
  const leftover = note.amountSats - withdrawSats;
  let noteRoot = oldState.noteRoot;
  if (leftover > 0n) {
    change = {
      amountSats: leftover,
      rho: freshRho(),
      ownerSecret: note.ownerSecret,
    };
    const inserted = machine.notes.append(commitNote(change, hash));
    noteRoot = inserted.root;
    changeIndex = inserted.index;
    created = { note: change, index: inserted.index, path: inserted.path };
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
    noteCommitment: leftover > 0n ? commitNote(change!, hash) : new Uint8Array(32),
    nullifier: nf,
    payoutLockingDigest,
    amountCommitIn: commitAmount(note.amountSats, note.rho, hash),
    amountCommitOut:
      leftover > 0n && change
        ? commitAmount(change.amountSats, change.rho, hash)
        : new Uint8Array(ZERO32),
  };
  checkPublicTransition(statement);
  return { machine: { ...machine, state: newState }, statement, change, changeIndex, path, created };
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

/**
 * One-set mix: many notes in, many notes out, one public net delta.
 * Individual amounts stay in hash-committed leaves — only the net hits the UTXO.
 */
export function applyAggregate(
  machine: PoolMachine,
  deposits: Note[],
  withdraws: Array<{ note: Note; index: number; amount: bigint }>,
): {
  machine: PoolMachine;
  statement: PoolStatement;
  deposited: Array<{ note: Note; index: number }>;
  change: Array<{ note: Note; index: number }>;
} {
  let next = machine;
  const deposited: Array<{ note: Note; index: number }> = [];
  for (const note of deposits) {
    const d = applyDeposit(next, note);
    next = d.machine;
    deposited.push({ note, index: d.index });
  }
  const change: Array<{ note: Note; index: number }> = [];
  let last = undefined as ReturnType<typeof applyWithdraw> | undefined;
  for (const w of withdraws) {
    last = applyWithdraw(next, w.note, w.index, new Uint8Array(32), w.amount);
    next = last.machine;
    if (last.change && last.changeIndex !== undefined) {
      change.push({ note: last.change, index: last.changeIndex });
    }
  }
  const net = next.state.reserveSats - machine.state.reserveSats;
  const statement: PoolStatement = {
    profile: "any-amount-v0",
    action: net >= 0n ? "DEPOSIT" : "WITHDRAW",
    publicAmountSats: net,
    oldState: machine.state,
    newState: next.state,
    noteCommitment: next.state.noteRoot,
    nullifier: last?.statement.nullifier ?? new Uint8Array(32),
    payoutLockingDigest: new Uint8Array(32),
    amountCommitIn: last?.statement.amountCommitIn ?? new Uint8Array(ZERO32),
    amountCommitOut: deposited[0]
      ? commitAmount(deposited[0].note.amountSats, deposited[0].note.rho, next.notes.hash)
      : new Uint8Array(ZERO32),
  };
  return { machine: next, statement, deposited, change };
}
