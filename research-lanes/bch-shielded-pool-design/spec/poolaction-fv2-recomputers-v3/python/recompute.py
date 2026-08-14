#!/usr/bin/env python3
"""Independent, structural PoolActionFv2 ABI-v3 recomputer.

This module intentionally has no relation-fixture, Node-recomputer, BCH-node,
VM, or proof dependency.  It consumes only raw/source evidence, emits all
derived byte preimages as lowercase hexadecimal, and fails closed with stable
codes.  A structurally valid input with an unselected proof suite is still
reported as REJECT_UNSELECTED_PROOF_SUITE; that is the only positive result
available in this phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MAX_MONEY = 2_100_000_000_000_000
TICKET = 10_000_000
MAX_RUNTIME = (1 << 63) - 1
MAX_SCRIPT_SIZE = 10_000
MAX_CARRIER_COUNT = 483


class RecomputeError(Exception):
    """Stable fail-closed error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def fail(code: str, message: str) -> None:
    raise RecomputeError(code, message)


def ensure_dict(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("E_JSON_SHAPE", f"{where}: object required")
    return value


def ensure_keys(value: dict[str, Any], required: Iterable[str], optional: Iterable[str] = (), where: str = "object") -> None:
    required_set = set(required)
    optional_set = set(optional)
    actual = set(value)
    missing = required_set - actual
    unknown = actual - required_set - optional_set
    if missing:
        fail("E_JSON_SHAPE", f"{where}: missing keys {sorted(missing)}")
    if unknown:
        fail("E_JSON_SHAPE", f"{where}: unknown keys {sorted(unknown)}")


HEX_RE = re.compile(r"^[0-9a-f]*$")


def hx(value: Any, where: str, exact: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or not HEX_RE.fullmatch(value):
        fail("E_HEX", f"{where}: lowercase even-length hex required")
    out = bytes.fromhex(value)
    if exact is not None and len(out) != exact:
        fail("E_LENGTH", f"{where}: expected {exact} bytes, got {len(out)}")
    return out


def hxs(value: bytes) -> str:
    return value.hex()


def uint(value: Any, where: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail("E_INTEGER", f"{where}: nonnegative integer required")
    if maximum is not None and value > maximum:
        fail("E_RANGE", f"{where}: value exceeds {maximum}")
    return value


def money(value: Any, where: str) -> int:
    return uint(value, where, MAX_MONEY)


def u8(value: int, where: str = "u8") -> bytes:
    return uint(value, where, 0xFF).to_bytes(1, "big")


def u16be(value: int, where: str = "u16be") -> bytes:
    return uint(value, where, 0xFFFF).to_bytes(2, "big")


def u16le(value: int, where: str = "u16le") -> bytes:
    return uint(value, where, 0xFFFF).to_bytes(2, "little")


def u32be(value: int, where: str = "u32be") -> bytes:
    return uint(value, where, 0xFFFFFFFF).to_bytes(4, "big")


def u64le(value: int, where: str = "u64le") -> bytes:
    return uint(value, where, 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def lp(value: bytes) -> bytes:
    return u32be(len(value), "LP length") + value


def runtime_hex(value: Any, where: str) -> tuple[int, bytes]:
    if not isinstance(value, str) or len(value) != 16 or not HEX_RE.fullmatch(value):
        fail("E_RUNTIME_INTEGER", f"{where}: exact 16-digit lowercase LE8 required")
    raw = bytes.fromhex(value)
    number = int.from_bytes(raw, "little")
    if number > MAX_RUNTIME:
        fail("E_RUNTIME_INTEGER", f"{where}: 2^63 and larger are forbidden")
    return number, raw


def sha_domain(domain: str, value: bytes) -> bytes:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + value).digest()


def sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def hash160(value: bytes) -> bytes:
    try:
        ripemd = hashlib.new("ripemd160")
    except ValueError:
        fail("E_HASH", "RIPEMD160 unavailable in this Python runtime")
    ripemd.update(hashlib.sha256(value).digest())
    return ripemd.digest()


def minimal_push(value: bytes, structural: bool = False) -> bytes:
    length = len(value)
    if length == 0:
        return b"\x00"
    if length <= 75:
        # Structural objects explicitly do not use small-integer aliases.
        return bytes([length]) + value
    if length <= 255:
        return b"\x4c" + bytes([length]) + value
    if length <= 65535:
        return b"\x4d" + length.to_bytes(2, "little") + value
    fail("E_LENGTH", "push exceeds u16 length")


def parse_minimal_push(data: bytes, offset: int, where: str, structural: bool = False) -> tuple[bytes, int]:
    if offset >= len(data):
        fail("E_PUSH", f"{where}: missing push")
    opcode = data[offset]
    offset += 1
    if opcode == 0:
        return b"", offset
    if 1 <= opcode <= 75:
        length = opcode
    elif opcode == 0x4C:
        if offset + 1 > len(data):
            fail("E_PUSH", f"{where}: truncated OP_PUSHDATA1")
        length = data[offset]
        offset += 1
        if length < 76:
            fail("E_PUSH", f"{where}: non-minimal OP_PUSHDATA1")
    elif opcode == 0x4D:
        if offset + 2 > len(data):
            fail("E_PUSH", f"{where}: truncated OP_PUSHDATA2")
        length = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2
        if length < 256:
            fail("E_PUSH", f"{where}: non-minimal OP_PUSHDATA2")
    else:
        fail("E_PUSH", f"{where}: opcode is not a push")
    end = offset + length
    if end > len(data):
        fail("E_PUSH", f"{where}: truncated payload")
    payload = data[offset:end]
    if structural and len(payload) == 1 and payload[0] in set(range(1, 17)) | {0x81}:
        fail("E_PUSH", f"{where}: small-integer alias forbidden")
    return payload, end


@dataclass(frozen=True)
class TokenObservation:
    tag: int
    category: bytes
    commitment: bytes
    amount: int

    @classmethod
    def from_json(cls, value: Any, where: str, role: str) -> "TokenObservation":
        obj = ensure_dict(value, where)
        ensure_keys(obj, ("extendedCategoryHex", "commitmentHex", "amountLeHex"), where=where)
        category = hx(obj["extendedCategoryHex"], f"{where}.extendedCategoryHex")
        commitment = hx(obj["commitmentHex"], f"{where}.commitmentHex")
        amount, _ = runtime_hex(obj["amountLeHex"], f"{where}.amountLeHex")
        tag = 1 if role == "state" else 0
        out = cls(tag, category, commitment, amount)
        out.to_bytes(where)
        return out

    def to_bytes(self, where: str = "token observation") -> bytes:
        if self.tag == 0:
            if self.category or self.commitment or self.amount != 0:
                fail("E_TOKEN", f"{where}: NONE projection is not zero")
        elif self.tag == 1:
            if len(self.category) != 33 or self.category[-1:] != b"\x01":
                fail("E_TOKEN", f"{where}: state category must be Cwire||01")
            if len(self.commitment) != 128 or self.amount != 0:
                fail("E_TOKEN", f"{where}: state token shape invalid")
        else:
            fail("E_TOKEN", f"{where}: only NONE and STATE_MUTABLE_NFT_ZERO are admitted")
        return u8(self.tag) + u16be(len(self.category)) + self.category + u16be(len(self.commitment)) + self.commitment + u64le(self.amount)

    def is_none(self) -> bool:
        return self.tag == 0 and not self.category and not self.commitment and self.amount == 0


@dataclass(frozen=True)
class Manifest:
    core: bytes
    network_tag: int
    protocol_template_digest: bytes
    pool_instance_id: bytes
    pre_existing_anchor_digest: bytes
    genesis_ancestry_digest: bytes
    state_category_wire: bytes
    state_base: int
    max_lifetime: int
    fee_cap: int
    suite_status: int
    suite_digest: bytes
    carrier_count: int
    carrier_layout: tuple[dict[str, int], ...]
    deposit_map: dict[str, int]
    withdrawal_map: dict[str, int]

    @classmethod
    def from_core(cls, core: bytes) -> "Manifest":
        if len(core) > MAX_SCRIPT_SIZE:
            fail("E_LENGTH", "manifest core exceeds script limit")
        pos = 0

        def take(n: int, where: str) -> bytes:
            nonlocal pos
            if pos + n > len(core):
                fail("E_LENGTH", f"manifest {where}: truncated")
            out = core[pos:pos + n]
            pos += n
            return out

        def be(n: int, where: str) -> int:
            return int.from_bytes(take(n, where), "big")

        def le(n: int, where: str) -> int:
            return int.from_bytes(take(n, where), "little")

        if take(4, "magic") != b"P3DM":
            fail("E_MAGIC", "manifest magic must be P3DM")
        if be(2, "version") != 3:
            fail("E_VERSION", "manifest ABI version must be 3")
        network = be(1, "network tag")
        if network not in (0, 1, 2):
            fail("E_MANIFEST", "unknown network tag")
        if be(1, "reserved") != 0:
            fail("E_RESERVED", "manifest reserved byte must be zero")
        protocol = take(32, "protocol template digest")
        pool_id = take(32, "pool instance id")
        anchor = take(32, "pre-existing anchor digest")
        ancestry = take(32, "genesis ancestry digest")
        category = take(32, "state category wire")
        ticket = le(8, "ticket")
        if ticket != TICKET:
            fail("E_MANIFEST", "ticket literal is not 10000000")
        state_base = le(8, "state base")
        max_lifetime = le(8, "max lifetime")
        fee_cap = le(8, "fee cap")
        status = be(1, "proof suite status")
        suite_digest = take(32, "proof suite digest")
        if status == 0 and suite_digest != bytes(32):
            fail("E_SUITE", "unselected suite must carry zero digest")
        if status == 1 and suite_digest == bytes(32):
            fail("E_SUITE", "selected suite must carry nonzero digest")
        if status not in (0, 1):
            fail("E_SUITE", "unknown proof suite status")
        if be(1, "no-upgrade") != 1:
            fail("E_RESERVED", "noUpgrade must be 01")
        count = be(4, "carrier count")
        if not 1 <= count <= MAX_CARRIER_COUNT:
            fail("E_RANGE", "carrier count must be 1..483")
        layout: list[dict[str, int]] = []
        for i in range(count):
            ordinal, input_index, output_index = be(4, "ordinal"), be(4, "input index"), be(4, "output index")
            value = le(8, "carrier value")
            if (ordinal, input_index, output_index) != (i, i + 1, i + 1):
                fail("E_ROLE", f"carrier layout {i} is not canonical")
            layout.append({"ordinal": i, "inputIndex": input_index, "outputIndex": output_index, "expectedValueSats": value})

        def role_map(withdrawal: bool) -> dict[str, int]:
            out = {
                "stateInputIndex": be(4, "state input index"),
                "externalInputIndex": be(4, "external input index"),
                "stateOutputIndex": be(4, "state output index"),
                "payoutPresent": be(1, "payout present"),
                "payoutOutputIndex": be(4, "payout output index"),
                "changeOptional": be(1, "change optional"),
                "changeOutputIndex": be(4, "change output index"),
            }
            expected = {
                "stateInputIndex": 0,
                "externalInputIndex": count + 1,
                "stateOutputIndex": 0,
                "payoutPresent": 1 if withdrawal else 0,
                "payoutOutputIndex": count + 1 if withdrawal else 0,
                "changeOptional": 1,
                "changeOutputIndex": count + (2 if withdrawal else 1),
            }
            if out != expected:
                fail("E_ROLE", f"{'withdrawal' if withdrawal else 'deposit'} role map is not canonical")
            return out

        deposit = role_map(False)
        withdrawal = role_map(True)
        if pos != len(core):
            fail("E_TRAILING", "manifest core has trailing bytes")
        for val, where in ((state_base, "state base"), (fee_cap, "fee cap")):
            money(val, where)
        if max_lifetime < 1:
            fail("E_RANGE", "maxLifetimeDeposits must be at least one")
        if state_base + max_lifetime * TICKET > MAX_MONEY:
            fail("E_MONEY", "manifest lifetime capacity exceeds MoneyRange")
        for entry in layout:
            money(entry["expectedValueSats"], "carrier value")

        manifest = cls(core, network, protocol, pool_id, anchor, ancestry, category, state_base, max_lifetime, fee_cap, status, suite_digest, count, tuple(layout), deposit, withdrawal)
        if manifest.pool_instance_id != pool_instance_id(manifest):
            fail("E_IDENTITY", "manifest poolInstanceId does not match P3PI recomputation")
        return manifest


def pool_identity_bytes(manifest: Manifest) -> bytes:
    out = bytearray(b"P3PI" + u16be(3) + u8(manifest.network_tag) + b"\x00")
    out += manifest.protocol_template_digest + manifest.pre_existing_anchor_digest + manifest.state_category_wire
    out += u64le(TICKET) + u64le(manifest.state_base) + u64le(manifest.max_lifetime) + u64le(manifest.fee_cap)
    out += u8(manifest.suite_status) + manifest.suite_digest + b"\x01" + u32be(manifest.carrier_count)
    for item in manifest.carrier_layout:
        out += u32be(item["ordinal"]) + u32be(item["inputIndex"]) + u32be(item["outputIndex"]) + u64le(item["expectedValueSats"])
    for role_map in (manifest.deposit_map, manifest.withdrawal_map):
        out += u32be(role_map["stateInputIndex"]) + u32be(role_map["externalInputIndex"]) + u32be(role_map["stateOutputIndex"])
        out += u8(role_map["payoutPresent"]) + u32be(role_map["payoutOutputIndex"])
        out += u8(role_map["changeOptional"]) + u32be(role_map["changeOutputIndex"])
    return bytes(out)


def pool_instance_id(manifest: Manifest) -> bytes:
    return sha_domain("PoolActionFv2/pool-instance/v3", lp(pool_identity_bytes(manifest)))


def deployment_commitment(manifest: Manifest) -> bytes:
    return sha_domain("PoolActionFv2/deployment/v3", lp(manifest.core))


def role_instance_bytes(role: str, ordinal: int, count: int) -> bytes:
    if role == "state":
        expected = (0, 0, 0)
    elif role == "carrier" and 0 <= ordinal < count:
        expected = (1, ordinal, ordinal + 1)
    else:
        fail("E_ROLE", "invalid role instance")
    return b"P3RI" + u16be(3) + u8(expected[0]) + u32be(ordinal) + u32be(expected[1]) + u32be(expected[2])


def parse_role_instance(raw: bytes, role: str, ordinal: int, count: int) -> bytes:
    expected = role_instance_bytes(role, ordinal, count)
    if raw != expected:
        fail("E_ROLE", f"{role} role instance bytes do not match fixed topology")
    return raw


def structural_redeem(manifest: Manifest, role_instance: bytes) -> bytes:
    return minimal_push(manifest.core, structural=True) + b"\x75" + minimal_push(role_instance, structural=True) + b"\x75\x00"


def structural_lock(redeem: bytes) -> bytes:
    return b"\xa9\x14" + hash160(redeem) + b"\x87"


def template_set() -> bytes:
    program = bytes.fromhex("00000175020001750100")
    state = b"P3RT" + u16be(3) + b"\x00\x05" + program
    carrier = b"P3RT" + u16be(3) + b"\x01\x05" + program
    return b"P3TS" + u16be(3) + lp(b"poolaction-fv2-structural-compiler-v3") + lp(state) + lp(carrier)


def protocol_template_digest() -> bytes:
    return sha_domain("PoolActionFv2/protocol-template/v3", lp(template_set()))


def anchor_digest(tx_hash: bytes, output_index: int) -> bytes:
    return sha_domain("PoolActionFv2/pre-existing-anchor/v3", lp(tx_hash) + lp(u32be(output_index)))


def genesis_ancestry_digest(pre_anchor: bytes, pool_id: bytes, category: bytes) -> bytes:
    return sha_domain("PoolActionFv2/genesis-ancestry/v3", lp(pre_anchor) + lp(pool_id) + lp(category))


def parse_state(commitment: bytes, where: str) -> dict[str, Any]:
    if len(commitment) != 128:
        fail("E_STATE", f"{where}: PoolStateFv1 must be 128 bytes")
    if commitment[:4] != b"PAF1":
        fail("E_MAGIC", f"{where}: state magic must be PAF1")
    if commitment[4:6] != u16le(1):
        fail("E_VERSION", f"{where}: state codec version must be u16le(1)")
    if commitment[6:8] != b"\x00\x00":
        fail("E_RESERVED", f"{where}: state reserved bytes must be zero")
    vals = [int.from_bytes(commitment[i:i + 8], "little") for i in (8, 16, 24)]
    if any(v > MAX_RUNTIME for v in vals):
        fail("E_RUNTIME_INTEGER", f"{where}: state integer exceeds signed runtime domain")
    return {"sequence": vals[0], "depositCount": vals[1], "withdrawalCount": vals[2], "poolInstanceId": commitment[32:64], "noteRoot": commitment[64:96], "nullifierRoot": commitment[96:128], "bytes": commitment}


def encode_state(state: dict[str, Any]) -> bytes:
    return b"PAF1" + u16le(1) + b"\x00\x00" + u64le(state["sequence"]) + u64le(state["depositCount"]) + u64le(state["withdrawalCount"]) + state["poolInstanceId"] + state["noteRoot"] + state["nullifierRoot"]


def parse_input(value: Any, index: int) -> dict[str, Any]:
    obj = ensure_dict(value, f"transaction.inputs[{index}]")
    ensure_keys(obj, ("outpointTxHashOpcodeOrder", "outpointIndexLeHex", "sequenceLeHex", "sourceValueLeHex", "sourceLockingBytecode", "unlockingBytecode", "tokenObservation"), where=f"transaction.inputs[{index}]")
    outpoint_index, _ = runtime_hex(obj["outpointIndexLeHex"], f"input {index} outpointIndexLeHex")
    sequence, _ = runtime_hex(obj["sequenceLeHex"], f"input {index} sequenceLeHex")
    value, _ = runtime_hex(obj["sourceValueLeHex"], f"input {index} sourceValueLeHex")
    if value > MAX_MONEY:
        fail("E_MONEY", f"input {index} value exceeds MoneyRange")
    return {"txHash": hx(obj["outpointTxHashOpcodeOrder"], f"input {index} tx hash", 32), "outpointIndex": outpoint_index, "sequence": sequence, "value": value, "lock": hx(obj["sourceLockingBytecode"], f"input {index} lock"), "unlock": hx(obj["unlockingBytecode"], f"input {index} unlock"), "token": TokenObservation.from_json(obj["tokenObservation"], f"input {index} token", "state" if index == 0 else "none")}


def parse_output(value: Any, index: int) -> dict[str, Any]:
    obj = ensure_dict(value, f"transaction.outputs[{index}]")
    ensure_keys(obj, ("valueLeHex", "lockingBytecode", "tokenObservation"), where=f"transaction.outputs[{index}]")
    value, _ = runtime_hex(obj["valueLeHex"], f"output {index} valueLeHex")
    if value > MAX_MONEY:
        fail("E_MONEY", f"output {index} value exceeds MoneyRange")
    return {"value": value, "lock": hx(obj["lockingBytecode"], f"output {index} lock"), "token": TokenObservation.from_json(obj["tokenObservation"], f"output {index} token", "state" if index == 0 else "none")}


def parse_raw(value: Any) -> dict[str, Any]:
    obj = ensure_dict(value, "raw evidence")
    ensure_keys(obj, ("lockSelectedManifestCoreHex", "stateActiveRedeemHex", "transaction", "anchor", "genesisInitialStateValueLeHex", "sourceTable", "dependencyGraph"), optional=("provenanceClaim",), where="raw evidence")
    core = hx(obj["lockSelectedManifestCoreHex"], "lockSelectedManifestCoreHex")
    state_redeem = hx(obj["stateActiveRedeemHex"], "stateActiveRedeemHex")
    transaction = ensure_dict(obj["transaction"], "transaction")
    ensure_keys(transaction, ("versionLeHex", "locktimeLeHex", "inputs", "outputs"), where="transaction")
    version, _ = runtime_hex(transaction["versionLeHex"], "transaction versionLeHex")
    locktime, _ = runtime_hex(transaction["locktimeLeHex"], "transaction locktimeLeHex")
    inputs = [parse_input(item, i) for i, item in enumerate(transaction["inputs"])] if isinstance(transaction["inputs"], list) else fail("E_JSON_SHAPE", "transaction.inputs must be an array")
    outputs = [parse_output(item, i) for i, item in enumerate(transaction["outputs"])] if isinstance(transaction["outputs"], list) else fail("E_JSON_SHAPE", "transaction.outputs must be an array")
    anchor = ensure_dict(obj["anchor"], "anchor")
    ensure_keys(anchor, ("txHashOpcodeOrder", "outputIndexBeHex"), where="anchor")
    anchor_hash = hx(anchor["txHashOpcodeOrder"], "anchor tx hash", 32)
    anchor_index_raw = hx(anchor["outputIndexBeHex"], "anchor outputIndexBeHex", 4)
    anchor_index = int.from_bytes(anchor_index_raw, "big")
    source_table = ensure_dict(obj["sourceTable"], "sourceTable")
    ensure_keys(source_table, ("leaves",), where="sourceTable")
    graph = ensure_dict(obj["dependencyGraph"], "dependencyGraph")
    ensure_keys(graph, ("edges",), where="dependencyGraph")
    genesis_value, _ = runtime_hex(obj["genesisInitialStateValueLeHex"], "genesisInitialStateValueLeHex")
    if genesis_value > MAX_MONEY:
        fail("E_MONEY", "genesis initial state value exceeds MoneyRange")
    out = {"core": core, "stateRedeem": state_redeem, "version": version, "locktime": locktime, "inputs": inputs, "outputs": outputs, "anchorHash": anchor_hash, "anchorIndex": anchor_index, "sourceTable": source_table, "dependencyGraph": graph, "genesisInitialStateValueSats": genesis_value}
    if "provenanceClaim" in obj:
        claim = ensure_dict(obj["provenanceClaim"], "provenanceClaim")
        ensure_keys(claim, ("genesisTransactionHashOpcodeOrder", "genesisOutpointIndexLeHex"), where="provenanceClaim")
        genesis_index, _ = runtime_hex(claim["genesisOutpointIndexLeHex"], "provenanceClaim genesis outpointIndexLeHex")
        out["provenanceClaim"] = {"txHash": hx(claim["genesisTransactionHashOpcodeOrder"], "provenanceClaim genesis tx hash", 32), "outpointIndex": genesis_index}
    return out


def validate_source_table(raw: dict[str, Any], manifest: Manifest) -> dict[str, Any]:
    leaves = raw["sourceTable"].get("leaves")
    if not isinstance(leaves, list):
        fail("E_SOURCE_TABLE", "sourceTable.leaves must be an array")
    seen: set[str] = set()
    allowed = {"CODEC_CONSTANT", "LOCK_SELECTED_EMBEDDED", "INTROSPECTED", "DERIVED_AND_CHECKED"}
    for i, item in enumerate(leaves):
        obj = ensure_dict(item, f"sourceTable.leaves[{i}]")
        ensure_keys(obj, ("leaf", "sourceClass"), where=f"sourceTable.leaves[{i}]")
        leaf, source_class = obj["leaf"], obj["sourceClass"]
        if not isinstance(leaf, str) or not leaf or any(w in leaf.lower() for w in ("*", "all", "any")):
            fail("E_SOURCE_TABLE", f"sourceTable leaf {i} is empty or wildcarded")
        if leaf in seen:
            fail("E_SOURCE_TABLE", f"duplicate source leaf {leaf}")
        seen.add(leaf)
        if source_class not in allowed:
            fail("E_SOURCE_TABLE", f"unknown source class for {leaf}")
    if not seen:
        fail("E_SOURCE_TABLE", "source table cannot be empty")
    return {"status": "PASS_EXACT_SHAPE_DEFERRED", "leafCount": len(seen), "carrierCount": manifest.carrier_count}


def validate_dependency_graph(graph: dict[str, Any]) -> dict[str, Any]:
    edges = graph.get("edges")
    if not isinstance(edges, list):
        fail("E_DEPENDENCY", "dependencyGraph.edges must be an array")
    adjacency: dict[str, list[str]] = {}
    for i, edge in enumerate(edges):
        if not isinstance(edge, list) or len(edge) != 2 or not all(isinstance(v, str) and v for v in edge):
            fail("E_DEPENDENCY", f"edge {i} must be [source,target]")
        src, dst = edge
        adjacency.setdefault(src, []).append(dst)
        src_l, dst_l = src.lower(), dst.lower()
        outer = any(token in src_l for token in ("session", "carrierroot", "enveloperoot", "schedule", "unlocking", "provenance"))
        proof_or_payload = any(token in dst_l for token in ("proof", "payload"))
        if outer and proof_or_payload:
            fail("E_DEPENDENCY_CYCLE", f"forbidden outer-root-to-proof edge {src}->{dst}")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            fail("E_DEPENDENCY_CYCLE", f"dependency cycle at {node}")
        if node in visited:
            return
        visiting.add(node)
        for nxt in adjacency.get(node, []):
            visit(nxt)
        visiting.remove(node)
        visited.add(node)

    for node in adjacency:
        visit(node)
    return {"status": "PASS_ACYCLIC_NO_FORBIDDEN_OUTER_EDGE", "edgeCount": len(edges)}


def expect_money_sums(inputs: list[dict[str, Any]], outputs: list[dict[str, Any]]) -> tuple[int, int]:
    in_sum = 0
    for item in inputs:
        in_sum += item["value"]
        if in_sum > MAX_MONEY:
            fail("E_MONEY", "aggregate input value exceeds MAX_MONEY")
    out_sum = 0
    for item in outputs:
        out_sum += item["value"]
        if out_sum > MAX_MONEY:
            fail("E_MONEY", "aggregate output value exceeds MAX_MONEY")
    return in_sum, out_sum


def parse_carrier_frame(data: bytes, index: int, manifest: Manifest) -> tuple[bytes, bytes, dict[str, int]]:
    if len(data) > MAX_SCRIPT_SIZE:
        fail("E_LENGTH", f"carrier {index}: full unlocking bytecode exceeds 10000")
    frame, pos = parse_minimal_push(data, 0, f"carrier {index} frame", structural=True)
    redeem, pos = parse_minimal_push(data, pos, f"carrier {index} redeem", structural=True)
    if pos != len(data):
        fail("E_CARRIER_FRAME", f"carrier {index}: trailing unlocking bytes")
    if len(frame) > MAX_SCRIPT_SIZE or len(redeem) > MAX_SCRIPT_SIZE:
        fail("E_LENGTH", f"carrier {index}: frame or redeem exceeds 10000")
    if len(lp(frame)) > MAX_SCRIPT_SIZE or len(lp(redeem)) > MAX_SCRIPT_SIZE or len(lp(data)) > MAX_SCRIPT_SIZE:
        fail("E_LENGTH", f"carrier {index}: encoded push or LP exceeds 10000")
    if frame[:6] != b"P3SG\x00\x03":
        fail("E_MAGIC", f"carrier {index}: frame magic/version invalid")
    if len(frame) < 18:
        fail("E_CARRIER_FRAME", f"carrier {index}: frame truncated")
    ordinal = int.from_bytes(frame[6:10], "big")
    input_index = int.from_bytes(frame[10:14], "big")
    payload_length = int.from_bytes(frame[14:18], "big")
    if len(frame) != 18 + payload_length or payload_length == 0:
        fail("E_CARRIER_FRAME", f"carrier {index}: frame payload length/emptiness invalid")
    if ordinal != index or input_index != index + 1:
        fail("E_ROLE", f"carrier {index}: frame ordinal/index mismatch")
    expected_role = role_instance_bytes("carrier", index, manifest.carrier_count)
    expected_redeem = structural_redeem(manifest, expected_role)
    if redeem != expected_redeem:
        fail("E_CARRIER_FRAME", f"carrier {index}: redeem substitution or noncanonical bytes")
    return frame, redeem, {"ordinal": ordinal, "inputIndex": input_index, "payloadLength": payload_length}


def recompute(raw_value: Any) -> dict[str, Any]:
    raw = parse_raw(raw_value)
    manifest = Manifest.from_core(raw["core"])
    state_role = role_instance_bytes("state", 0, manifest.carrier_count)
    carrier_roles = [role_instance_bytes("carrier", i, manifest.carrier_count) for i in range(manifest.carrier_count)]
    if manifest.protocol_template_digest != protocol_template_digest():
        fail("E_PROVENANCE", "protocolTemplateDigest does not match P3RT/P3TS compiler")
    if manifest.state_category_wire != raw["anchorHash"]:
        fail("E_PROVENANCE", "stateCategoryWire does not equal anchor transaction hash")
    actual_anchor_digest = anchor_digest(raw["anchorHash"], raw["anchorIndex"])
    if manifest.pre_existing_anchor_digest != actual_anchor_digest:
        fail("E_PROVENANCE", "preExistingAnchorDigest mismatch")
    actual_ancestry = genesis_ancestry_digest(actual_anchor_digest, manifest.pool_instance_id, manifest.state_category_wire)
    if manifest.genesis_ancestry_digest != actual_ancestry:
        fail("E_PROVENANCE", "genesisAncestryDigest mismatch")
    source_table_result = validate_source_table(raw, manifest)
    dependency_result = validate_dependency_graph(raw["dependencyGraph"])
    inputs, outputs = raw["inputs"], raw["outputs"]
    n = manifest.carrier_count
    if len(inputs) != n + 2:
        fail("E_TOPOLOGY", "input count must be N+2")
    if len(outputs) not in (n + 1, n + 2, n + 3):
        fail("E_TOPOLOGY", "output count is not a permitted topology")
    if raw["version"] != 2 or raw["locktime"] != 0:
        fail("E_TXVIEW", "transaction version must be 2 and locktime 0")
    if any(item["sequence"] != 0xFFFFFFFF for item in inputs):
        fail("E_TXVIEW", "every transaction input sequence must be 4294967295")
    predecessor = inputs[0]["txHash"]
    if inputs[0]["outpointIndex"] != 0:
        fail("E_TOPOLOGY", "state source outpoint index must be zero")
    if any(item["txHash"] != predecessor or item["outpointIndex"] != i + 1 for i, item in enumerate(inputs[1:n + 1])):
        fail("E_TOPOLOGY", "carrier predecessor hash/index mismatch")
    expected_state_redeem = structural_redeem(manifest, state_role)
    if raw["stateRedeem"] != expected_state_redeem:
        fail("E_ROLE", "stateActiveRedeemHex does not match derived state redeem")
    expected_state_lock = structural_lock(expected_state_redeem)
    if inputs[0]["lock"] != expected_state_lock or outputs[0]["lock"] != expected_state_lock:
        fail("E_ROLE", "state source/successor lock mismatch")
    if "provenanceClaim" in raw:
        claim = raw["provenanceClaim"]
        if claim["txHash"] != inputs[0]["txHash"] or claim["outpointIndex"] != inputs[0]["outpointIndex"]:
            fail("E_PROVENANCE", "direct-genesis claim does not equal current state source")
    state_old = parse_state(inputs[0]["token"].commitment, "state source")
    state_new = parse_state(outputs[0]["token"].commitment, "state successor")
    if inputs[0]["token"].tag != 1 or outputs[0]["token"].tag != 1 or inputs[0]["token"].category != manifest.state_category_wire + b"\x01" or outputs[0]["token"].category != manifest.state_category_wire + b"\x01":
        fail("E_TOKEN", "state source/successor token language mismatch")
    if state_old["poolInstanceId"] != manifest.pool_instance_id or state_new["poolInstanceId"] != manifest.pool_instance_id:
        fail("E_IDENTITY", "state poolInstanceId mismatch")
    for state, where in ((state_old, "state source"), (state_new, "state successor")):
        if not (0 <= state["withdrawalCount"] <= state["depositCount"] <= manifest.max_lifetime):
            fail("E_STATE", f"{where}: count invariant failed")
        reserve = (state["depositCount"] - state["withdrawalCount"]) * TICKET
        if manifest.state_base + reserve > MAX_MONEY:
            fail("E_MONEY", f"{where}: state value equation exceeds MAX_MONEY")
    expected_old_value = manifest.state_base + (state_old["depositCount"] - state_old["withdrawalCount"]) * TICKET
    expected_new_value = manifest.state_base + (state_new["depositCount"] - state_new["withdrawalCount"]) * TICKET
    if inputs[0]["value"] != expected_old_value or outputs[0]["value"] != expected_new_value:
        fail("E_ECONOMICS", "state source/successor values violate B+C*T equation")
    for i in range(n):
        expected_lock = structural_lock(structural_redeem(manifest, carrier_roles[i]))
        if inputs[i + 1]["lock"] != expected_lock or outputs[i + 1]["lock"] != expected_lock:
            fail("E_ROLE", f"carrier {i}: source/successor lock mismatch")
        if inputs[i + 1]["token"].to_bytes() != TokenObservation(0, b"", b"", 0).to_bytes() or outputs[i + 1]["token"].to_bytes() != TokenObservation(0, b"", b"", 0).to_bytes():
            fail("E_TOKEN", f"carrier {i}: token observation is not NONE")
        value = manifest.carrier_layout[i]["expectedValueSats"]
        if inputs[i + 1]["value"] != value or outputs[i + 1]["value"] != value:
            fail("E_ECONOMICS", f"carrier {i}: value continuity mismatch")
    delta = (manifest.state_base + (state_new["depositCount"] - state_new["withdrawalCount"]) * TICKET) - (manifest.state_base + (state_old["depositCount"] - state_old["withdrawalCount"]) * TICKET)
    if delta == TICKET:
        action_tag, action = 0, "DEPOSIT"
        if not (state_new["sequence"] == state_old["sequence"] + 1 and state_new["depositCount"] == state_old["depositCount"] + 1 and state_new["withdrawalCount"] == state_old["withdrawalCount"]):
            fail("E_STATE", "deposit transition fields invalid")
        if state_new["noteRoot"] == state_old["noteRoot"] or state_new["noteRoot"] == bytes(32) or state_new["nullifierRoot"] != state_old["nullifierRoot"]:
            fail("E_STATE", "deposit note/nullifier transition invalid")
        if state_old["depositCount"] >= manifest.max_lifetime:
            fail("E_STATE", "deposit exceeds lifetime capacity")
    elif delta == -TICKET:
        action_tag, action = 1, "WITHDRAWAL"
        if not (state_new["sequence"] == state_old["sequence"] + 1 and state_new["depositCount"] == state_old["depositCount"] and state_new["withdrawalCount"] == state_old["withdrawalCount"] + 1):
            fail("E_STATE", "withdrawal transition fields invalid")
        if state_new["nullifierRoot"] == state_old["nullifierRoot"] or state_new["nullifierRoot"] == bytes(32) or state_new["noteRoot"] != state_old["noteRoot"]:
            fail("E_STATE", "withdrawal note/nullifier transition invalid")
    else:
        fail("E_STATE", "state value delta is not plus/minus ticket")
    if state_old["sequence"] >= MAX_RUNTIME:
        fail("E_RUNTIME_INTEGER", "old sequence cannot increment from runtime maximum")
    in_sum, out_sum = expect_money_sums(inputs, outputs)
    fee = in_sum - out_sum
    if fee < 0 or fee > manifest.fee_cap:
        fail("E_ECONOMICS", "fee is negative or exceeds policy cap")
    payout_index = n + 1 if action == "WITHDRAWAL" else 0
    if action == "WITHDRAWAL":
        if len(outputs) not in (n + 2, n + 3) or outputs[payout_index]["value"] != TICKET or not outputs[payout_index]["token"].is_none():
            fail("E_TOPOLOGY", "withdrawal payout topology invalid")
        if inputs[n + 1]["value"] != fee + (outputs[n + 2]["value"] if len(outputs) == n + 3 else 0):
            fail("E_ECONOMICS", "withdrawal external fee equation invalid")
    else:
        if len(outputs) not in (n + 1, n + 2):
            fail("E_TOPOLOGY", "deposit output topology invalid")
        if inputs[n + 1]["value"] != TICKET + fee + (outputs[n + 1]["value"] if len(outputs) == n + 2 else 0):
            fail("E_ECONOMICS", "deposit external funding equation invalid")
    if not inputs[n + 1]["token"].is_none():
        fail("E_TOKEN", "external funding input must be token-free")
    change_present = (len(outputs) == n + (2 if action == "DEPOSIT" else 3))
    change_index = n + (1 if action == "DEPOSIT" else 2) if change_present else 0
    if change_present and not outputs[change_index]["token"].is_none():
        fail("E_TOKEN", "transparent change must be token-free")
    frames: list[dict[str, Any]] = []
    payloads: list[bytes] = []
    for i in range(n):
        frame, redeem, frame_meta = parse_carrier_frame(inputs[i + 1]["unlock"], i, manifest)
        frames.append(frame_meta)
        payloads.append(frame[18:])
    carrier_session = u32be(n)
    cumulative = 0
    schedule = u32be(n)
    for i, (item, frame_meta) in enumerate(zip(inputs[1:n + 1], frames)):
        carrier_session += u32be(i) + u32be(i + 1) + lp(item["unlock"])
        schedule += u32be(i) + u32be(i + 1) + u32be(cumulative) + u32be(frame_meta["payloadLength"])
        cumulative += frame_meta["payloadLength"]
        if cumulative > MAX_SCRIPT_SIZE:
            fail("E_LENGTH", "carrier schedule offset exceeds 10000")
    reconstructed = b"".join(payloads)
    carrier_root = sha_domain("PoolActionFv2/carrier-session/v3", lp(carrier_session))
    envelope_root = sha_domain("PoolActionFv2/envelope/v3", lp(reconstructed))
    tx_view = build_tx_view(raw, manifest, action_tag, action, fee, payout_index, change_present, change_index)
    context = sha_domain("PoolActionFv2/context/v3", lp(deployment_commitment(manifest)) + lp(tx_view))
    session = sha_domain("PoolActionFv2/session/v3", lp(context) + lp(carrier_root) + lp(envelope_root) + lp(schedule) + lp(manifest.suite_digest))
    if manifest.suite_status != 0:
        fail("E_SUITE", "selected proof suite execution is intentionally unavailable")
    return {"status": "STRUCTURAL_RECOMPUTE", "verdict": "REJECT_UNSELECTED_PROOF_SUITE", "manifest": {"coreHex": hxs(manifest.core), "poolIdentityConfigHex": hxs(pool_identity_bytes(manifest)), "poolInstanceId": hxs(manifest.pool_instance_id), "deploymentCommitment": hxs(deployment_commitment(manifest))}, "provenance": {"templateSetHex": hxs(template_set()), "protocolTemplateDigest": hxs(protocol_template_digest()), "preExistingAnchorDigest": hxs(actual_anchor_digest), "genesisAncestryDigest": hxs(actual_ancestry), "genesisInitialStateValueLeHex": u64le(raw["genesisInitialStateValueSats"]).hex()}, "action": {"kind": action, "tag": action_tag, "feeSatsLeHex": u64le(fee).hex()}, "state": {"sourceHex": hxs(state_old["bytes"]), "successorHex": hxs(state_new["bytes"])}, "txViewHex": hxs(tx_view), "carriers": {"sessionBytesHex": hxs(carrier_session), "carrierSessionRoot": hxs(carrier_root), "envelopeBytesHex": hxs(reconstructed), "envelopeRoot": hxs(envelope_root), "scheduleBytesHex": hxs(schedule)}, "contextDigest": hxs(context), "sessionDigest": hxs(session), "sourceTableVerdict": source_table_result, "dependencyVerdict": dependency_result, "nonClaims": ["proof selection", "proof acceptance", "BCH VM/node execution", "complete transaction", "standardness", "measurement", "qualification", "deployment", "activation"]}


def build_tx_view(raw: dict[str, Any], manifest: Manifest, action_tag: int, action: str, fee: int, payout_index: int, change_present: bool, change_index: int) -> bytes:
    inputs, outputs, n = raw["inputs"], raw["outputs"], manifest.carrier_count
    out = bytearray(b"P3TV" + u16be(3) + u8(action_tag) + b"\x00" + u64le(raw["version"]) + u64le(raw["locktime"]) + u32be(n) + u32be(len(inputs)))
    for i, item in enumerate(inputs):
        if i == 0:
            role, ordinal, disposition = 0, 0, 0
        elif i <= n:
            role, ordinal, disposition = 1, i - 1, 1
        else:
            role, ordinal, disposition = (2 if action == "DEPOSIT" else 3), 0, 2
        out += u32be(i) + u8(role) + u32be(ordinal) + item["txHash"] + u64le(item["outpointIndex"]) + u64le(item["sequence"]) + u64le(item["value"]) + lp(item["lock"]) + item["token"].to_bytes() + u8(disposition)
    out += u32be(len(outputs))
    for i, item in enumerate(outputs):
        if i == 0:
            role, ordinal = 0x10, 0
        elif i <= n:
            role, ordinal = 0x11, i - 1
        elif action == "WITHDRAWAL" and i == n + 1:
            role, ordinal = 0x12, 0
        else:
            role, ordinal = 0x13, 0
        out += u32be(i) + u8(role) + u32be(ordinal) + u64le(item["value"]) + lp(item["lock"]) + item["token"].to_bytes()
    out += u64le(TICKET) + u8(0 if action == "DEPOSIT" else 1) + u64le(fee) + u64le(manifest.fee_cap) + u8(1 if action == "WITHDRAWAL" else 0) + u32be(payout_index) + u8(1 if change_present else 0) + u32be(change_index)
    return bytes(out)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args(argv)
    try:
        value = json.loads(args.input.read_text(encoding="utf-8"))
        result = recompute(value)
        text = canonical_json(result)
        code = 0
    except (OSError, json.JSONDecodeError) as exc:
        text = canonical_json({"status": "REJECTED", "code": "E_JSON", "message": str(exc)})
        code = 2
    except RecomputeError as exc:
        text = canonical_json({"status": "REJECTED", "code": exc.code, "message": exc.message})
        code = 2
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
