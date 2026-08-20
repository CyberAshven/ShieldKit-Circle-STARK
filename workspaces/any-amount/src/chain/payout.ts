/**
 * Withdraw payout lock. HASH256 of this bytecode is `payoutLockingDigest`.
 * Distinct from the fee-funder P2PKH so feeUtxo−change is not the payout.
 */
import { hash256 } from "@bitauth/libauth";

const HASH160_FIXTURE = new Uint8Array(20).fill(0x11);

/** Standard P2PKH template used as the lab withdraw payout locking bytecode. */
export const LAB_PAYOUT_LOCKING = Uint8Array.of(
  0x76,
  0xa9,
  0x14,
  ...HASH160_FIXTURE,
  0x88,
  0xac,
);

export function hashPayoutLocking(locking: Uint8Array): Uint8Array {
  return hash256(locking);
}

export const LAB_PAYOUT_DIGEST = hashPayoutLocking(LAB_PAYOUT_LOCKING);
