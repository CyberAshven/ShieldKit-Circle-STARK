import {
  assertSoundParams,
  BLOWUP,
  COMMITTED_LAYERS,
  CONJECTURAL_BITS,
  conjecturalBits,
  FRI_FINAL,
  FRI_N,
  FRI_QUERIES,
  GRIND_BITS,
  RATE,
  SOUNDNESS_FLOOR,
  SOUNDNESS_TARGET,
  TRACE_LEN,
  VK_ID,
} from "./params.ts";

export type SoundnessWorksheet = {
  family: "circle-fri-m31";
  field: "M31";
  domain: "circle x^2+y^2=1";
  traceLen: number;
  blowup: number;
  friN: number;
  queries: number;
  grind: number;
  finalLayer: number;
  committedLayers: number;
  rate: "1/B" | "2/B";
  conjecturalBits: number;
  floor: number;
  target: number;
  sound: boolean;
  vkId: string;
  note: string;
};

export function soundnessWorksheet(): SoundnessWorksheet {
  assertSoundParams();
  const bits = conjecturalBits({
    queries: FRI_QUERIES,
    blowup: BLOWUP,
    grind: GRIND_BITS,
    rate: RATE,
  });
  return {
    family: "circle-fri-m31",
    field: "M31",
    domain: "circle x^2+y^2=1",
    traceLen: TRACE_LEN,
    blowup: BLOWUP,
    friN: FRI_N,
    queries: FRI_QUERIES,
    grind: GRIND_BITS,
    finalLayer: FRI_FINAL,
    committedLayers: COMMITTED_LAYERS,
    rate: RATE,
    conjecturalBits: bits,
    floor: SOUNDNESS_FLOOR,
    target: SOUNDNESS_TARGET,
    sound: bits >= SOUNDNESS_FLOOR,
    vkId: VK_ID,
    note:
      "ethSTARK-style conjectural query bits (2021/582): q*(log2(B)-1)+grind at rate 2/B. " +
      "Not a Lean/paper theorem. Note tree is SHA-256 + Pedersen; AIR binds public reserves/digest.",
  };
}

export { CONJECTURAL_BITS, assertSoundParams };
