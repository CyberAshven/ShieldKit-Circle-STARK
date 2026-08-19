import { circleFriPlugin } from "../backends/circle/plugin.ts";
import { hashLabPlugin } from "../backends/hash-lab.ts";
import type { ZkpPlugin } from "../pool/plugin.ts";

/** Separate from ZKP. See DESIGN.md. */
export type SidePlugin = {
  family: string;
  layer: "amount-hiding" | "delivery" | "key-path" | "bus";
  requiredForPool: false;
  status: "slot" | "lab";
};

/** Production amount-hiding: tagged SHA-256. Not a discrete-log Pedersen. */
export const hashAmountPlugin: SidePlugin = {
  family: "sha256-tagged-amount",
  layer: "amount-hiding",
  requiredForPool: false,
  status: "lab",
};

/** Comparison-only EC profile. Not the production note commit. */
export const pedersenAmountPlugin: SidePlugin = {
  family: "pedersen-secp-profile",
  layer: "amount-hiding",
  requiredForPool: false,
  status: "slot",
};

export const mlkemDeliveryPlugin: SidePlugin = {
  family: "ml-kem-768",
  layer: "delivery",
  requiredForPool: false,
  status: "slot",
};

export const quantumrootKeyPath: SidePlugin = {
  family: "quantumroot-lmots",
  layer: "key-path",
  requiredForPool: false,
  status: "slot",
};

export const nostrBusPlugin: SidePlugin = {
  family: "nostr-nip44-59-17",
  layer: "bus",
  requiredForPool: false,
  status: "lab",
};

export const zkpPlugins: ZkpPlugin[] = [circleFriPlugin, hashLabPlugin];

/** Production default. Circle FRI is the first backend, not the pool identity. */
export const DEFAULT_ZKP_FAMILY = circleFriPlugin.family;

export function defaultZkpPlugin(): ZkpPlugin {
  return circleFriPlugin;
}

export function zkpPluginByFamily(family: string): ZkpPlugin {
  const p = zkpPlugins.find((x) => x.family === family);
  if (!p) throw new Error(`unknown zkp family ${family}`);
  return p;
}

export function describePlugins(): unknown {
  return {
    covenant: "P2S (2026) / P2SH32 (P1 shells) — not P2PKH",
    userLock: "P2PKH today; Quantumroot later",
    defaultZkp: DEFAULT_ZKP_FAMILY,
    zkp: zkpPlugins.map((p) => ({ family: p.family, sound: p.sound, vkId: p.vkId })),
    side: [hashAmountPlugin, pedersenAmountPlugin, mlkemDeliveryPlugin, quantumrootKeyPath, nostrBusPlugin],
  };
}
