import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { hexToBin } from "@bitauth/libauth";
import { FRI_VERSION, RULES_SHA256, VK_ID } from "../src/backends/circle/params.ts";

const here = dirname(fileURLToPath(import.meta.url));
const pack = join(here, "../survey/artifacts/qm31-fri10");

const SIBLING_OCCUPANCY_RULES =
  "de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22";
const SIBLING_OCCUPANCY_VK =
  "circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22";

describe("QM31 occupancy pack (starting artifact; packed vk is occupancy RULES)", () => {
  it("frozen pack pins sibling RULES sha256; live RULES is this lane", () => {
    assert.equal(existsSync(pack), true, "occupancy pack must travel with the lab copy");
    const vk = readFileSync(join(pack, "vk.txt"), "utf8").trim();
    const meta = JSON.parse(readFileSync(join(pack, "meta.json"), "utf8")) as {
      vkId: string;
      rulesSha256: string;
      rulesSha256OfPackedRules: string;
      completeness: { friVersion: number; dummyPad: boolean; leftoverBound: boolean };
      doesNotClaim: string[];
      chipnet: { successor: string; txBytes: number };
    };
    const packedRules = sha(readFileSync(join(pack, "RULES.md")));
    const liveRules = sha(readFileSync(join(here, "../RULES.md")));
    assert.equal(vk, SIBLING_OCCUPANCY_VK);
    assert.equal(meta.vkId, SIBLING_OCCUPANCY_VK);
    assert.equal(VK_ID.endsWith(RULES_SHA256), true);
    assert.equal(VK_ID.includes("qm31"), true);
    assert.equal(VK_ID.includes("fri11"), true);
    assert.notEqual(liveRules, packedRules);
    assert.equal(liveRules, RULES_SHA256);
    assert.equal(packedRules, SIBLING_OCCUPANCY_RULES);
    assert.equal(meta.rulesSha256, SIBLING_OCCUPANCY_RULES);
    assert.equal(meta.rulesSha256OfPackedRules, SIBLING_OCCUPANCY_RULES);
    assert.equal(FRI_VERSION, 11);
    assert.equal(meta.completeness.friVersion, 10);
    assert.equal(meta.completeness.dummyPad, false);
    assert.equal(meta.completeness.leftoverBound, true);
    assert.equal(meta.doesNotClaim.includes("named end"), true);
    assert.equal(meta.doesNotClaim.some((s) => s.includes("§6")), true);
    assert.equal(meta.doesNotClaim.some((s) => s.includes("§7")), true);
    assert.equal(meta.chipnet.successor, "60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4");
    assert.equal(meta.chipnet.txBytes, 99043);
    const argument = readFileSync(join(pack, "ARGUMENT.md"), "utf8");
    assert.equal(argument.includes(SIBLING_OCCUPANCY_VK), true);
  });

  it("packed Chipnet hex is the named successor", () => {
    const hexPath = join(pack, "chipnet-successor.hex");
    assert.equal(existsSync(hexPath), true);
    const hex = readFileSync(hexPath, "utf8").trim();
    const raw = hexToBin(hex);
    if (typeof raw === "string") throw new Error(raw);
    assert.equal(raw.length, 99043);
  });
});

function sha(buf: Uint8Array): string {
  return createHash("sha256").update(buf).digest("hex");
}
