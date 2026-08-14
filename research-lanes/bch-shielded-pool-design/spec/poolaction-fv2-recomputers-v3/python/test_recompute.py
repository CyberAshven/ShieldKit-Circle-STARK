import copy
import json
import unittest

from recompute import (
    MAX_RUNTIME,
    Manifest,
    RecomputeError,
    TICKET,
    anchor_digest,
    genesis_ancestry_digest,
    hash160,
    minimal_push,
    parse_minimal_push,
    parse_raw,
    parse_state,
    pool_instance_id,
    protocol_template_digest,
    recompute,
    role_instance_bytes,
    structural_lock,
    structural_redeem,
    u16be,
    u16le,
    u32be,
    u64le,
    u8,
)


def manifest_fixture(n=1):
    anchor = bytes.fromhex("11" * 32)
    protocol = protocol_template_digest()
    pre_anchor = anchor_digest(anchor, 0)
    layout = tuple({"ordinal": i, "inputIndex": i + 1, "outputIndex": i + 1, "expectedValueSats": 1000 + i} for i in range(n))
    dep = {"stateInputIndex": 0, "externalInputIndex": n + 1, "stateOutputIndex": 0, "payoutPresent": 0, "payoutOutputIndex": 0, "changeOptional": 1, "changeOutputIndex": n + 1}
    wd = {"stateInputIndex": 0, "externalInputIndex": n + 1, "stateOutputIndex": 0, "payoutPresent": 1, "payoutOutputIndex": n + 1, "changeOptional": 1, "changeOutputIndex": n + 2}
    provisional = Manifest(b"", 0, protocol, bytes(32), pre_anchor, bytes(32), anchor, 100_000_000, 10, 1_000, 0, bytes(32), n, layout, dep, wd)
    pool_id = pool_instance_id(provisional)
    ancestry = genesis_ancestry_digest(pre_anchor, pool_id, anchor)
    core = b"P3DM" + u16be(3) + u8(0) + b"\x00" + protocol + pool_id + pre_anchor + ancestry + anchor
    core += u64le(TICKET) + u64le(100_000_000) + u64le(10) + u64le(1_000) + u8(0) + bytes(32) + b"\x01" + u32be(n)
    for item in layout:
        core += u32be(item["ordinal"]) + u32be(item["inputIndex"]) + u32be(item["outputIndex"]) + u64le(item["expectedValueSats"])
    for role_map in (dep, wd):
        core += u32be(role_map["stateInputIndex"]) + u32be(role_map["externalInputIndex"]) + u32be(role_map["stateOutputIndex"])
        core += u8(role_map["payoutPresent"]) + u32be(role_map["payoutOutputIndex"])
        core += u8(role_map["changeOptional"]) + u32be(role_map["changeOutputIndex"])
    return core, pool_id, anchor


def state_bytes(sequence, deposits, withdrawals, pool_id, note, nullifier):
    return b"PAF1" + u16le(1) + b"\x00\x00" + u64le(sequence) + u64le(deposits) + u64le(withdrawals) + pool_id + note + nullifier


def lehex(value):
    return u64le(value).hex()


def token_none():
    return {"extendedCategoryHex": "", "commitmentHex": "", "amountLeHex": lehex(0)}


def token_state(category, commitment):
    return {"extendedCategoryHex": (category + b"\x01").hex(), "commitmentHex": commitment.hex(), "amountLeHex": lehex(0)}


def full_deposit_fixture():
    core, pool_id, anchor = manifest_fixture()
    manifest = Manifest.from_core(core)
    state_role = role_instance_bytes("state", 0, 1)
    carrier_role = role_instance_bytes("carrier", 0, 1)
    state_redeem = structural_redeem(manifest, state_role)
    carrier_redeem = structural_redeem(manifest, carrier_role)
    carrier_lock = structural_lock(carrier_redeem)
    frame = b"P3SG" + u16be(3) + u32be(0) + u32be(1) + u32be(1) + b"\xaa"
    carrier_unlock = minimal_push(frame, structural=True) + minimal_push(carrier_redeem, structural=True)
    old = state_bytes(0, 0, 0, pool_id, b"\x01" + bytes(31), bytes(32))
    new = state_bytes(1, 1, 0, pool_id, b"\x02" + bytes(31), bytes(32))
    state_category = token_state(anchor, old)
    state_category_new = token_state(anchor, new)
    predecessor = bytes.fromhex("22" * 32).hex()
    external = bytes.fromhex("33" * 32).hex()
    input_common = {"outpointIndexLeHex": lehex(1), "sequenceLeHex": lehex(0xFFFFFFFF), "sourceValueLeHex": lehex(1000), "sourceLockingBytecode": carrier_lock.hex(), "unlockingBytecode": carrier_unlock.hex(), "tokenObservation": token_none()}
    raw = {
        "lockSelectedManifestCoreHex": core.hex(),
        "stateActiveRedeemHex": state_redeem.hex(),
        "transaction": {"versionLeHex": lehex(2), "locktimeLeHex": lehex(0), "inputs": [
            {"outpointTxHashOpcodeOrder": predecessor, "outpointIndexLeHex": lehex(0), "sequenceLeHex": lehex(0xFFFFFFFF), "sourceValueLeHex": lehex(100_000_000), "sourceLockingBytecode": structural_lock(state_redeem).hex(), "unlockingBytecode": "", "tokenObservation": state_category},
            {"outpointTxHashOpcodeOrder": predecessor, **input_common},
            {"outpointTxHashOpcodeOrder": external, "outpointIndexLeHex": lehex(2), "sequenceLeHex": lehex(0xFFFFFFFF), "sourceValueLeHex": lehex(TICKET + 100), "sourceLockingBytecode": "51", "unlockingBytecode": "", "tokenObservation": token_none()},
        ], "outputs": [
            {"valueLeHex": lehex(110_000_000), "lockingBytecode": structural_lock(state_redeem).hex(), "tokenObservation": state_category_new},
            {"valueLeHex": lehex(1000), "lockingBytecode": carrier_lock.hex(), "tokenObservation": token_none()},
        ]},
        "anchor": {"txHashOpcodeOrder": anchor.hex(), "outputIndexBeHex": "00000000"},
        "genesisInitialStateValueLeHex": lehex(100_000_000),
        "sourceTable": {"leaves": [{"leaf": "raw.anchorHash", "sourceClass": "INTROSPECTED"}]},
        "dependencyGraph": {"edges": [["manifest+transaction", "deploymentCommitment+TxViewV3Bytes"], ["contextDigest", "proofPublicInput"]]},
    }
    return raw


class PrimitiveTests(unittest.TestCase):
    def test_runtime_boundaries(self):
        self.assertEqual(u16le(1), bytes.fromhex("0100"))
        self.assertNotEqual(u16le(1), u16be(1))
        self.assertEqual(parse_state(state_bytes(0, 0, 0, bytes(32), bytes(32), bytes(32)), "x")["sequence"], 0)
        maximum = (MAX_RUNTIME).to_bytes(8, "little")
        self.assertEqual(int.from_bytes(maximum, "little"), MAX_RUNTIME)
        with self.assertRaises(RecomputeError) as ctx:
            parse_state(b"PAF1" + u16le(1) + b"\x00\x00" + (1 << 63).to_bytes(8, "little") + bytes(112), "x")
        self.assertEqual(ctx.exception.code, "E_RUNTIME_INTEGER")
        with self.assertRaises(RecomputeError) as ctx:
            parse_state(b"PAF1" + u16be(1) + b"\x00\x00" + bytes(120), "wrong-version")
        self.assertEqual(ctx.exception.code, "E_VERSION")

    def test_structural_push_rejects_alias_and_roundtrips(self):
        self.assertEqual(minimal_push(b"\x01", structural=True), b"\x01\x01")
        with self.assertRaises(RecomputeError):
            parse_minimal_push(b"\x51", 0, "alias", structural=True)
        payload = b"abc"
        encoded = minimal_push(payload, structural=True)
        self.assertEqual(parse_minimal_push(encoded, 0, "push", structural=True), (payload, len(encoded)))

    def test_full_structural_recompute_is_unselected_only(self):
        result = recompute(full_deposit_fixture())
        self.assertEqual(result["verdict"], "REJECT_UNSELECTED_PROOF_SUITE")
        self.assertEqual(result["action"], {"kind": "DEPOSIT", "tag": 0, "feeSatsLeHex": lehex(100)})
        self.assertTrue(result["txViewHex"].startswith("50335456000300"))
        self.assertIn(u64le(TICKET).hex(), result["txViewHex"])
        self.assertEqual(len(result["contextDigest"]), 64)

    def test_sequence_max_boundary_is_admitted_but_increment_from_max_rejects(self):
        value = full_deposit_fixture()
        manifest = Manifest.from_core(bytes.fromhex(value["lockSelectedManifestCoreHex"]))
        old = state_bytes(MAX_RUNTIME - 1, 0, 0, manifest.pool_instance_id, b"\x01" + bytes(31), bytes(32))
        new = state_bytes(MAX_RUNTIME, 1, 0, manifest.pool_instance_id, b"\x02" + bytes(31), bytes(32))
        value["transaction"]["inputs"][0]["tokenObservation"]["commitmentHex"] = old.hex()
        value["transaction"]["outputs"][0]["tokenObservation"]["commitmentHex"] = new.hex()
        self.assertEqual(recompute(value)["verdict"], "REJECT_UNSELECTED_PROOF_SUITE")
        bad = full_deposit_fixture()
        old = state_bytes(MAX_RUNTIME, 0, 0, manifest.pool_instance_id, b"\x01" + bytes(31), bytes(32))
        new = state_bytes(MAX_RUNTIME + 1, 1, 0, manifest.pool_instance_id, b"\x02" + bytes(31), bytes(32))
        bad["transaction"]["inputs"][0]["tokenObservation"]["commitmentHex"] = old.hex()
        bad["transaction"]["outputs"][0]["tokenObservation"]["commitmentHex"] = new.hex()
        with self.assertRaises(RecomputeError) as ctx:
            recompute(bad)
        self.assertEqual(ctx.exception.code, "E_RUNTIME_INTEGER")

    def test_raw_parser_rejects_unknown_field(self):
        value = full_deposit_fixture()
        value["unexpected"] = True
        with self.assertRaises(RecomputeError) as ctx:
            parse_raw(value)
        self.assertEqual(ctx.exception.code, "E_JSON_SHAPE")
        value = full_deposit_fixture()
        value["transaction"]["inputs"][0]["tokenObservation"]["tag"] = 1
        with self.assertRaises(RecomputeError) as ctx:
            parse_raw(value)
        self.assertEqual(ctx.exception.code, "E_JSON_SHAPE")
        value = full_deposit_fixture()
        value["lockSelectedRoleInstancesHex"] = {"state": "", "carriers": []}
        with self.assertRaises(RecomputeError) as ctx:
            parse_raw(value)
        self.assertEqual(ctx.exception.code, "E_JSON_SHAPE")
        value = full_deposit_fixture()
        value["stateActiveRedeemHex"] = "00"
        with self.assertRaises(RecomputeError) as ctx:
            recompute(value)
        self.assertEqual(ctx.exception.code, "E_ROLE")

    def test_source_and_dependency_fail_closed(self):
        value = full_deposit_fixture()
        value["sourceTable"]["leaves"][0]["leaf"] = "*"
        with self.assertRaises(RecomputeError) as ctx:
            recompute(value)
        self.assertEqual(ctx.exception.code, "E_SOURCE_TABLE")
        value = full_deposit_fixture()
        value["dependencyGraph"]["edges"] = [["a", "b"], ["b", "a"]]
        with self.assertRaises(RecomputeError) as ctx:
            recompute(value)
        self.assertEqual(ctx.exception.code, "E_DEPENDENCY_CYCLE")
        value = full_deposit_fixture()
        value["provenanceClaim"] = {"genesisTransactionHashOpcodeOrder": "44" * 32, "genesisOutpointIndexLeHex": lehex(0)}
        with self.assertRaises(RecomputeError) as ctx:
            recompute(value)
        self.assertEqual(ctx.exception.code, "E_PROVENANCE")


if __name__ == "__main__":
    unittest.main()
