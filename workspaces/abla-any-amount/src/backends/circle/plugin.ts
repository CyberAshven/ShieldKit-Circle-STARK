import type { PluginVerifyResult, ZkpPlugin } from "../../pool/plugin.ts";
import type { PoolStatement } from "../../pool/statement.ts";

export const CIRCLE_FRI_NOT_SOUND_YET = "CIRCLE_FRI_NOT_SOUND_YET";

/**
 * First backend *identity*. Prove/verify stay closed until fold + Merkle +
 * queries + false-statement tests exist. Do not accept a dummy proof.
 */
export const circleFriPlugin: ZkpPlugin = {
  family: "circle-fri-m31",
  vkId: "circle-fri-m31-unspecified-vk",
  sound: false,
  async prove() {
    throw new Error(CIRCLE_FRI_NOT_SOUND_YET);
  },
  verify(_statement: PoolStatement, _proof: Uint8Array): PluginVerifyResult {
    return { ok: false, reason: CIRCLE_FRI_NOT_SOUND_YET };
  },
};
