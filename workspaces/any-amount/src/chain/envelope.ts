/**
 * BCH size envelopes. Relay policy ≠ consensus.
 * One tx: standard 100 KB, consensus 1 MB.
 * Chained / anchored txs (standard or not) can go much larger (user: 32 MB).
 * After Velma, **both** script/redeem size **and** input bytecode are 10 KB
 * (the old ~1650-byte input-bytecode box is gone). Chunk the verifier across inputs.
 * Chipnet + a miner can include nonstandard txs. Never mainnet from this lab.
 */
export const RELAY_STANDARD_TX_BYTES = 100_000;
export const CONSENSUS_TX_BYTES = 1_000_000;
export const CHAINED_TX_BYTES = 32_000_000;
export const UNLOCKING_MAX_BYTES = 10_000;

export type TxEnvelope = "standard" | "consensus";

export function txLimitBytes(envelope: TxEnvelope): number {
  return envelope === "consensus" ? CONSENSUS_TX_BYTES : RELAY_STANDARD_TX_BYTES;
}
