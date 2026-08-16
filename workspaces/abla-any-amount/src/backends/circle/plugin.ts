import { encodeFriProof, proveFri, verifyFri, decodeFriProof } from "./fri.ts";
import type { PluginVerifyResult, ZkpPlugin } from "../../pool/plugin.ts";
import type { PoolStatement } from "../../pool/statement.ts";

/** Kept so old tests still name the closed *sound* verifier. */
export const CIRCLE_FRI_NOT_SOUND_YET = "CIRCLE_FRI_NOT_SOUND_YET";

/**
 * Hash-based Circle FRI plugin. Post-quantum as a *family* (no pairings / no
 * discrete log). Not 128-bit sound: n=32, 8 queries. Addresses stay Schnorr.
 */
export const circleFriPlugin: ZkpPlugin = {
  family: "circle-fri-m31",
  vkId: "circle-fri-m31-bench-n32-q8",
  sound: false,
  async prove(statement: PoolStatement) {
    return encodeFriProof(proveFri(statement));
  },
  verify(statement: PoolStatement, proof: Uint8Array): PluginVerifyResult {
    try {
      return verifyFri(statement, decodeFriProof(proof));
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : String(e) };
    }
  },
};
