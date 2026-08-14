#!/usr/bin/env python3
"""Inert PoolActionFv1 pre-refreeze falsifier reference model.

This file imports only the Python standard library. It does not import or run
P1/project code and does not access BCH, a VM, Libauth, Node, a network, a
proof system, or a prover. SHA-256 is used only as a deterministic test oracle;
it is not selected for a deployment or protocol by this package.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import stat
import struct
import sys
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
LANE_ROOT = HERE.parent.parent
PACKAGE_ID = "evidence:poolactionfv1-refreeze-falsifiers-v1"
STATUS = "BLOCKED_VERSION_PIVOT_NO_REFREEZE"
EVIDENCE_TIER = "INERT_DETERMINISTIC_OFFLINE_REFERENCE_MODEL_ONLY"
TEST_HASH = "sha256-test-only-not-selected"
ZERO32 = "00" * 32
TICKET = 10_000_000
MAX_SCRIPT_BYTES = 10_000
MAX_ELEMENT_BYTES = 10_000
MAX_TX_BYTES = 100_000

NETWORK_TAGS = {"mainnet": 0, "chipnet": 1, "regtest": 2}
ACTION_TAGS = {"DEPOSIT": 0, "WITHDRAWAL": 1}
INPUT_ROLE_TAGS = {
    "STATE": 0,
    "VERIFIER_CARRIER": 1,
    "DEPOSIT_FUNDING": 2,
    "FEE_FUNDING": 3,
}
OUTPUT_ROLE_TAGS = {
    "STATE_SUCCESSOR": 0x10,
    "VERIFIER_CARRIER_SUCCESSOR": 0x11,
    "PAYOUT": 0x12,
    "TRANSPARENT_CHANGE": 0x13,
}
TOKEN_KIND_TAGS = {
    "none": 0,
    "fungible-only": 1,
    "immutable": 2,
    "mutable": 3,
    "minting": 4,
}
INPUT_ROLE_NAMES = {value: key for key, value in INPUT_ROLE_TAGS.items()}
OUTPUT_ROLE_NAMES = {value: key for key, value in OUTPUT_ROLE_TAGS.items()}
TOKEN_KIND_NAMES = {value: key for key, value in TOKEN_KIND_TAGS.items()}
NETWORK_NAMES = {value: key for key, value in NETWORK_TAGS.items()}
ACTION_NAMES = {value: key for key, value in ACTION_TAGS.items()}

INDEX_FILE = "index.v1.json"
VECTORS_FILE = "vectors.v1.json"
RECEIPT_FILE = "receipt.v1.json"
INDEX_SCHEMA_FILE = "index.v1.schema.json"
VECTORS_SCHEMA_FILE = "vectors.v1.schema.json"
RECEIPT_SCHEMA_FILE = "receipt.v1.schema.json"
README_FILE = "README.md"
ORACLE_FILE = "oracle.py"
MANIFEST_FILE = "MANIFEST.json"
SUMS_FILE = "SHA256SUMS"
NON_ENVELOPE_FILES = (
    README_FILE,
    INDEX_FILE,
    INDEX_SCHEMA_FILE,
    ORACLE_FILE,
    RECEIPT_FILE,
    RECEIPT_SCHEMA_FILE,
    VECTORS_FILE,
    VECTORS_SCHEMA_FILE,
)


class Reject(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def reject(code: str, message: str) -> None:
    raise Reject(code, message)


def exact_keys(value: Any, keys: set[str], code: str, label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        reject(code, f"{label} keys are not exact")


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_bytes(canonical_json_bytes(value))


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(path: pathlib.Path, display: str | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "bytes": len(data),
        "path": display if display is not None else path.name,
        "rawSha256": sha256_bytes(data),
    }


def h(byte_hex: str) -> str:
    return byte_hex * 32


def require_hex(value: Any, byte_length: int | None, code: str, label: str, allow_empty: bool = False) -> bytes:
    if not isinstance(value, str) or value.lower() != value or len(value) % 2 or any(c not in "0123456789abcdef" for c in value):
        reject(code, f"{label} is not canonical lowercase hex")
    if value == "" and not allow_empty:
        reject(code, f"{label} is empty")
    data = bytes.fromhex(value)
    if byte_length is not None and len(data) != byte_length:
        reject(code, f"{label} has wrong length")
    return data


def require_uint(value: Any, bits: int, code: str, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value >= (1 << bits):
        reject(code, f"{label} is not uint{bits}")
    return value


def require_decimal(value: Any, signed: bool, code: str, label: str) -> int:
    if not isinstance(value, str):
        reject(code, f"{label} is not a decimal string")
    if value == "0":
        return 0
    if signed and value.startswith("-"):
        body = value[1:]
        if not body or body.startswith("0") or not body.isdigit():
            reject(code, f"{label} is not canonical")
    elif value.startswith("0") or not value.isdigit():
        reject(code, f"{label} is not canonical")
    result = int(value)
    lower = -(1 << 63) if signed else 0
    upper = (1 << 63) - 1 if signed else (1 << 64) - 1
    if result < lower or result > upper:
        reject(code, f"{label} is out of range")
    return result


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def i64(value: int) -> bytes:
    return struct.pack("<q", value)


class Reader:
    def __init__(self, data: bytes, label: str):
        self.data = data
        self.offset = 0
        self.label = label

    def take(self, length: int, code: str = "FULL_CONSUMPTION") -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            reject(code, f"{self.label} truncated at {self.offset}")
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result

    def read_u8(self) -> int:
        return self.take(1)[0]

    def read_u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def read_u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def read_u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def read_i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def finish(self) -> None:
        if self.offset != len(self.data):
            reject("FULL_CONSUMPTION", f"{self.label} has trailing bytes")


NONE_TOKEN = {"amount": "0", "capability": "none", "categoryHex": "", "commitmentHex": ""}


def validate_token(token: Any, code: str = "CONTEXT_CANONICAL") -> None:
    exact_keys(token, {"categoryHex", "capability", "commitmentHex", "amount"}, code, "token")
    kind = token["capability"]
    if kind not in TOKEN_KIND_TAGS:
        reject(code, "unknown token kind")
    amount = require_decimal(token["amount"], False, code, "token.amount")
    if kind == "none":
        if token != NONE_TOKEN:
            reject(code, "none token alias")
        return
    require_hex(token["categoryHex"], 32, code, "token.categoryHex")
    commitment = require_hex(token["commitmentHex"], None, code, "token.commitmentHex", allow_empty=True)
    if len(commitment) > 128:
        reject(code, "token commitment too large")
    if kind == "fungible-only" and (commitment or amount == 0):
        reject(code, "non-canonical fungible-only token")


def encode_token(token: dict[str, Any]) -> bytes:
    validate_token(token)
    kind = TOKEN_KIND_TAGS[token["capability"]]
    out = bytearray((kind,))
    if kind == 0:
        return bytes(out)
    out += bytes.fromhex(token["categoryHex"])
    out += u64(int(token["amount"]))
    commitment = bytes.fromhex(token["commitmentHex"])
    out.append(len(commitment))
    out += commitment
    return bytes(out)


def decode_token(reader: Reader) -> dict[str, Any]:
    kind_tag = reader.read_u8()
    if kind_tag not in TOKEN_KIND_NAMES:
        reject("CONTEXT_CANONICAL", "reserved token kind")
    kind = TOKEN_KIND_NAMES[kind_tag]
    if kind == "none":
        return copy.deepcopy(NONE_TOKEN)
    category = reader.take(32).hex()
    amount = str(reader.read_u64())
    commitment_length = reader.read_u8()
    if commitment_length > 128:
        reject("CONTEXT_CANONICAL", "token commitment length")
    commitment = reader.take(commitment_length).hex()
    token = {"amount": amount, "capability": kind, "categoryHex": category, "commitmentHex": commitment}
    validate_token(token)
    return token


CONTEXT_KEYS = {
    "codecVersion", "networkId", "poolInstanceIdHex", "actionKind",
    "transactionVersion", "locktime", "carrierManifestDigestHex",
    "proofSecurityProfileDigestHex", "inputs", "outputs",
}
INPUT_KEYS = {
    "index", "role", "roleOrdinal", "outpointTxidWireHex", "outpointIndex",
    "sequence", "sourceValueSats", "sourceLockingBytecodeHex", "sourceToken",
}
OUTPUT_KEYS = {"index", "role", "roleOrdinal", "valueSats", "lockingBytecodeHex", "token"}


def validate_context(context: Any) -> None:
    code = "CONTEXT_CANONICAL"
    exact_keys(context, CONTEXT_KEYS, code, "TxContextFv1")
    if context["codecVersion"] != 1 or context["transactionVersion"] != 2 or context["locktime"] != 0:
        reject(code, "fixed context header differs")
    if context["networkId"] not in NETWORK_TAGS or context["actionKind"] not in ACTION_TAGS:
        reject(code, "context domain tag unsupported")
    require_hex(context["poolInstanceIdHex"], 32, code, "poolInstanceId")
    require_hex(context["carrierManifestDigestHex"], 32, code, "manifestDigest")
    require_hex(context["proofSecurityProfileDigestHex"], 32, code, "profileDigest")
    inputs = context["inputs"]
    outputs = context["outputs"]
    if not isinstance(inputs, list) or not isinstance(outputs, list) or len(inputs) < 3 or len(outputs) < 2:
        reject(code, "context arrays/counts invalid")
    carrier_count = len(inputs) - 2
    expected_external = "DEPOSIT_FUNDING" if context["actionKind"] == "DEPOSIT" else "FEE_FUNDING"
    for position, item in enumerate(inputs):
        exact_keys(item, INPUT_KEYS, code, f"input {position}")
        if item["index"] != position:
            reject("CONTEXT_TOPOLOGY", "input wire index")
        if item["role"] not in INPUT_ROLE_TAGS:
            reject(code, "input role")
        require_uint(item["roleOrdinal"], 16, code, "input ordinal")
        require_hex(item["outpointTxidWireHex"], 32, code, "input txid")
        require_uint(item["outpointIndex"], 32, code, "input outpoint")
        if item["sequence"] != 0xFFFFFFFF:
            reject(code, "input sequence")
        require_decimal(item["sourceValueSats"], False, code, "input value")
        lock = require_hex(item["sourceLockingBytecodeHex"], None, code, "source lock")
        if not lock or len(lock) > MAX_ELEMENT_BYTES:
            reject(code, "source lock length")
        validate_token(item["sourceToken"], code)
    state_input = inputs[0]
    if state_input["role"] != "STATE" or state_input["roleOrdinal"] != 0 or state_input["outpointIndex"] != 0:
        reject("CONTEXT_TOPOLOGY", "state input")
    state_token = state_input["sourceToken"]
    if state_token["capability"] != "mutable" or state_token["amount"] != "0" or len(state_token["commitmentHex"]) != 256:
        reject("CONTEXT_TOPOLOGY", "state token")
    for ordinal in range(carrier_count):
        item = inputs[ordinal + 1]
        if item["role"] != "VERIFIER_CARRIER" or item["roleOrdinal"] != ordinal:
            reject("CONTEXT_TOPOLOGY", "carrier input schedule")
        if item["outpointTxidWireHex"] != state_input["outpointTxidWireHex"] or item["outpointIndex"] != ordinal + 1:
            reject("CONTEXT_TOPOLOGY", "carrier predecessor")
    external = inputs[-1]
    if external["role"] != expected_external or external["roleOrdinal"] != 0 or external["sourceToken"] != NONE_TOKEN:
        reject("CONTEXT_TOPOLOGY", "external funding input")
    for position, item in enumerate(outputs):
        exact_keys(item, OUTPUT_KEYS, code, f"output {position}")
        if item["index"] != position:
            reject("CONTEXT_TOPOLOGY", "output wire index")
        if item["role"] not in OUTPUT_ROLE_TAGS:
            reject(code, "output role")
        require_uint(item["roleOrdinal"], 16, code, "output ordinal")
        require_decimal(item["valueSats"], False, code, "output value")
        lock = require_hex(item["lockingBytecodeHex"], None, code, "output lock")
        if not lock or len(lock) > MAX_ELEMENT_BYTES:
            reject(code, "output lock length")
        validate_token(item["token"], code)
    state_output = outputs[0]
    if state_output["role"] != "STATE_SUCCESSOR" or state_output["roleOrdinal"] != 0:
        reject("CONTEXT_TOPOLOGY", "state successor")
    if state_output["token"]["capability"] != "mutable" or state_output["token"]["amount"] != "0" or len(state_output["token"]["commitmentHex"]) != 256:
        reject("CONTEXT_TOPOLOGY", "state successor token")
    if state_output["token"]["categoryHex"] != state_token["categoryHex"]:
        reject("CONTEXT_TOPOLOGY", "state token lineage")
    for ordinal in range(carrier_count):
        source = inputs[ordinal + 1]
        successor = outputs[ordinal + 1]
        if successor["role"] != "VERIFIER_CARRIER_SUCCESSOR" or successor["roleOrdinal"] != ordinal:
            reject("CONTEXT_TOPOLOGY", "carrier successor schedule")
        if (source["sourceValueSats"] != successor["valueSats"] or
                source["sourceLockingBytecodeHex"] != successor["lockingBytecodeHex"] or
                source["sourceToken"] != successor["token"]):
            reject("CONTEXT_TOPOLOGY", "carrier preservation")
    bundle_end = carrier_count + 1
    if context["actionKind"] == "DEPOSIT":
        if len(outputs) not in (bundle_end, bundle_end + 1):
            reject("CONTEXT_TOPOLOGY", "deposit output count")
        if len(outputs) == bundle_end + 1 and outputs[-1]["role"] != "TRANSPARENT_CHANGE":
            reject("CONTEXT_TOPOLOGY", "deposit change")
    else:
        if len(outputs) not in (bundle_end + 1, bundle_end + 2):
            reject("CONTEXT_TOPOLOGY", "withdrawal output count")
        payout = outputs[bundle_end]
        if payout["role"] != "PAYOUT" or payout["roleOrdinal"] != 0 or payout["valueSats"] != str(TICKET) or payout["token"] != NONE_TOKEN:
            reject("CONTEXT_TOPOLOGY", "withdrawal payout")
        if len(outputs) == bundle_end + 2 and outputs[-1]["role"] != "TRANSPARENT_CHANGE":
            reject("CONTEXT_TOPOLOGY", "withdrawal change")


def encode_context(context: dict[str, Any]) -> bytes:
    validate_context(context)
    out = bytearray(b"PCTX")
    out += u16(1)
    out.append(NETWORK_TAGS[context["networkId"]])
    out.append(ACTION_TAGS[context["actionKind"]])
    out += bytes.fromhex(context["poolInstanceIdHex"])
    out += bytes.fromhex(context["carrierManifestDigestHex"])
    out += bytes.fromhex(context["proofSecurityProfileDigestHex"])
    out += u32(2) + u32(0) + u16(len(context["inputs"]))
    for item in context["inputs"]:
        out += u16(item["index"])
        out.append(INPUT_ROLE_TAGS[item["role"]])
        out += u16(item["roleOrdinal"])
        out += bytes.fromhex(item["outpointTxidWireHex"])
        out += u32(item["outpointIndex"]) + u32(item["sequence"])
        out += u64(int(item["sourceValueSats"]))
        lock = bytes.fromhex(item["sourceLockingBytecodeHex"])
        out += u16(len(lock)) + lock + encode_token(item["sourceToken"])
    out += u16(len(context["outputs"]))
    for item in context["outputs"]:
        out += u16(item["index"])
        out.append(OUTPUT_ROLE_TAGS[item["role"]])
        out += u16(item["roleOrdinal"])
        out += u64(int(item["valueSats"]))
        lock = bytes.fromhex(item["lockingBytecodeHex"])
        out += u16(len(lock)) + lock + encode_token(item["token"])
    return bytes(out)


def decode_context(data: bytes) -> dict[str, Any]:
    reader = Reader(data, "TxContextFv1")
    if reader.take(4) != b"PCTX" or reader.read_u16() != 1:
        reject("CONTEXT_CANONICAL", "context magic/version")
    network_tag = reader.read_u8()
    action_tag = reader.read_u8()
    if network_tag not in NETWORK_NAMES or action_tag not in ACTION_NAMES:
        reject("CONTEXT_CANONICAL", "context domain tag")
    context: dict[str, Any] = {
        "codecVersion": 1,
        "networkId": NETWORK_NAMES[network_tag],
        "actionKind": ACTION_NAMES[action_tag],
        "poolInstanceIdHex": reader.take(32).hex(),
        "carrierManifestDigestHex": reader.take(32).hex(),
        "proofSecurityProfileDigestHex": reader.take(32).hex(),
        "transactionVersion": reader.read_u32(),
        "locktime": reader.read_u32(),
        "inputs": [],
        "outputs": [],
    }
    input_count = reader.read_u16()
    if input_count < 3:
        reject("CONTEXT_CANONICAL", "input count")
    for _ in range(input_count):
        role_tag = None
        index = reader.read_u16()
        role_tag = reader.read_u8()
        if role_tag not in INPUT_ROLE_NAMES:
            reject("CONTEXT_CANONICAL", "input role tag")
        context["inputs"].append({
            "index": index,
            "role": INPUT_ROLE_NAMES[role_tag],
            "roleOrdinal": reader.read_u16(),
            "outpointTxidWireHex": reader.take(32).hex(),
            "outpointIndex": reader.read_u32(),
            "sequence": reader.read_u32(),
            "sourceValueSats": str(reader.read_u64()),
            "sourceLockingBytecodeHex": reader.take(reader.read_u16()).hex(),
            "sourceToken": decode_token(reader),
        })
    output_count = reader.read_u16()
    if output_count < 2:
        reject("CONTEXT_CANONICAL", "output count")
    for _ in range(output_count):
        index = reader.read_u16()
        role_tag = reader.read_u8()
        if role_tag not in OUTPUT_ROLE_NAMES:
            reject("CONTEXT_CANONICAL", "output role tag")
        context["outputs"].append({
            "index": index,
            "role": OUTPUT_ROLE_NAMES[role_tag],
            "roleOrdinal": reader.read_u16(),
            "valueSats": str(reader.read_u64()),
            "lockingBytecodeHex": reader.take(reader.read_u16()).hex(),
            "token": decode_token(reader),
        })
    reader.finish()
    validate_context(context)
    return context


PAST_KEYS = {
    "relationVersion", "profileTag", "networkId", "actionKind", "poolInstanceIdHex",
    "proofSecurityProfileDigestHex", "carrierManifestDigestHex", "oldStateOutpointTxidWireHex",
    "oldStateOutpointIndex", "oldStateValueSats", "oldStateBytesHex", "newStateOutputIndex",
    "newStateValueSats", "newStateBytesHex", "ticketSats", "reserveDeltaSats",
    "noteCommitmentOrZeroHex", "nullifierOrZeroHex", "payoutOutputIndexOrffff",
    "payoutSatsOrZero", "payoutLockingBytecodeDigestOrZeroHex", "feeInputIndex",
    "transparentChangeOutputIndexOrffff", "feeSats", "maxFeeSats", "transactionContextDigestHex",
}


def validate_past(past: Any) -> None:
    code = "PAST_CANONICAL"
    exact_keys(past, PAST_KEYS, code, "PAST")
    if past["relationVersion"] != 1 or past["profileTag"] != 1:
        reject(code, "PAST relation/profile")
    if past["networkId"] not in NETWORK_TAGS or past["actionKind"] not in ACTION_TAGS:
        reject(code, "PAST domain tags")
    for field in (
        "poolInstanceIdHex", "proofSecurityProfileDigestHex", "carrierManifestDigestHex",
        "oldStateOutpointTxidWireHex", "noteCommitmentOrZeroHex", "nullifierOrZeroHex",
        "payoutLockingBytecodeDigestOrZeroHex", "transactionContextDigestHex",
    ):
        require_hex(past[field], 32, code, field)
    require_hex(past["oldStateBytesHex"], 128, code, "oldStateBytes")
    require_hex(past["newStateBytesHex"], 128, code, "newStateBytes")
    if past["oldStateOutpointIndex"] != 0 or past["newStateOutputIndex"] != 0:
        reject(code, "fixed state index")
    if require_decimal(past["ticketSats"], False, code, "ticket") != TICKET:
        reject(code, "ticket")
    reserve = require_decimal(past["reserveDeltaSats"], True, code, "reserve delta")
    for field in ("oldStateValueSats", "newStateValueSats", "payoutSatsOrZero", "feeSats", "maxFeeSats"):
        require_decimal(past[field], False, code, field)
    require_uint(past["payoutOutputIndexOrffff"], 16, code, "payout index")
    require_uint(past["feeInputIndex"], 16, code, "fee input")
    require_uint(past["transparentChangeOutputIndexOrffff"], 16, code, "change index")
    if int(past["feeSats"]) > int(past["maxFeeSats"]):
        reject(code, "fee cap")
    if past["actionKind"] == "DEPOSIT":
        if reserve != TICKET or past["noteCommitmentOrZeroHex"] == ZERO32 or past["nullifierOrZeroHex"] != ZERO32:
            reject(code, "deposit selector fields")
        if past["payoutOutputIndexOrffff"] != 0xFFFF or past["payoutSatsOrZero"] != "0" or past["payoutLockingBytecodeDigestOrZeroHex"] != ZERO32:
            reject(code, "deposit payout absent form")
    else:
        if reserve != -TICKET or past["noteCommitmentOrZeroHex"] != ZERO32 or past["nullifierOrZeroHex"] == ZERO32:
            reject(code, "withdrawal selector fields")
        if past["payoutOutputIndexOrffff"] == 0xFFFF or past["payoutSatsOrZero"] != str(TICKET):
            reject(code, "withdrawal payout fields")


def encode_past(past: dict[str, Any]) -> bytes:
    validate_past(past)
    out = bytearray(b"PAST")
    out += u16(1)
    out.append(1)
    out.append(NETWORK_TAGS[past["networkId"]])
    out.append(ACTION_TAGS[past["actionKind"]])
    for field in ("poolInstanceIdHex", "proofSecurityProfileDigestHex", "carrierManifestDigestHex", "oldStateOutpointTxidWireHex"):
        out += bytes.fromhex(past[field])
    out += u32(0) + u64(int(past["oldStateValueSats"]))
    out += bytes.fromhex(past["oldStateBytesHex"])
    out += u16(0) + u64(int(past["newStateValueSats"]))
    out += bytes.fromhex(past["newStateBytesHex"])
    out += u64(TICKET) + i64(int(past["reserveDeltaSats"]))
    out += bytes.fromhex(past["noteCommitmentOrZeroHex"])
    out += bytes.fromhex(past["nullifierOrZeroHex"])
    out += u16(past["payoutOutputIndexOrffff"]) + u64(int(past["payoutSatsOrZero"]))
    out += bytes.fromhex(past["payoutLockingBytecodeDigestOrZeroHex"])
    out += u16(past["feeInputIndex"]) + u16(past["transparentChangeOutputIndexOrffff"])
    out += u64(int(past["feeSats"])) + u64(int(past["maxFeeSats"]))
    out += bytes.fromhex(past["transactionContextDigestHex"])
    if len(out) != 589:
        reject("PAST_CANONICAL", f"PAST length {len(out)}")
    return bytes(out)


def decode_past(data: bytes) -> dict[str, Any]:
    if len(data) != 589:
        reject("PAST_CANONICAL", "PAST must be exactly 589 bytes")
    reader = Reader(data, "PAST")
    if reader.take(4) != b"PAST":
        reject("PAST_CANONICAL", "PAST magic")
    relation = reader.read_u16()
    profile = reader.read_u8()
    network_tag = reader.read_u8()
    action_tag = reader.read_u8()
    if network_tag not in NETWORK_NAMES or action_tag not in ACTION_NAMES:
        reject("PAST_CANONICAL", "PAST tags")
    past = {
        "relationVersion": relation,
        "profileTag": profile,
        "networkId": NETWORK_NAMES[network_tag],
        "actionKind": ACTION_NAMES[action_tag],
        "poolInstanceIdHex": reader.take(32).hex(),
        "proofSecurityProfileDigestHex": reader.take(32).hex(),
        "carrierManifestDigestHex": reader.take(32).hex(),
        "oldStateOutpointTxidWireHex": reader.take(32).hex(),
        "oldStateOutpointIndex": reader.read_u32(),
        "oldStateValueSats": str(reader.read_u64()),
        "oldStateBytesHex": reader.take(128).hex(),
        "newStateOutputIndex": reader.read_u16(),
        "newStateValueSats": str(reader.read_u64()),
        "newStateBytesHex": reader.take(128).hex(),
        "ticketSats": str(reader.read_u64()),
        "reserveDeltaSats": str(reader.read_i64()),
        "noteCommitmentOrZeroHex": reader.take(32).hex(),
        "nullifierOrZeroHex": reader.take(32).hex(),
        "payoutOutputIndexOrffff": reader.read_u16(),
        "payoutSatsOrZero": str(reader.read_u64()),
        "payoutLockingBytecodeDigestOrZeroHex": reader.take(32).hex(),
        "feeInputIndex": reader.read_u16(),
        "transparentChangeOutputIndexOrffff": reader.read_u16(),
        "feeSats": str(reader.read_u64()),
        "maxFeeSats": str(reader.read_u64()),
        "transactionContextDigestHex": reader.take(32).hex(),
    }
    reader.finish()
    validate_past(past)
    return past


def state_hex(sequence: int, deposits: int, withdrawals: int, pool: str, note: str, nullifier: str) -> str:
    return (b"PAF1" + u16(1) + u16(0) + u64(sequence) + u64(deposits) + u64(withdrawals)
            + bytes.fromhex(pool) + bytes.fromhex(note) + bytes.fromhex(nullifier)).hex()


def template_definition() -> dict[str, Any]:
    return {
        "placeholderSchema": [
            {"bytes": 32, "name": "poolInstanceId", "type": "bytes32"},
            {"bytes": 32, "name": "carrierManifestDigest", "type": "bytes32"},
            {"bytes": 2, "name": "ordinal", "type": "u16le"},
            {"bytes": 1, "name": "policyByte", "type": "u8"},
        ],
        "templateId": "offline:carrier-lock-template-fv1",
        "templateRawAscii": "OP_RETURN PUSH32(poolInstanceId) PUSH32(carrierManifestDigest) PUSH2(ordinalLE) PUSH1(policyByte)",
    }


def protocol_template_digest() -> str:
    return sha256_bytes(b"PoolActionFv1/ProtocolTemplate/TestOnly/v1" + compact_json_bytes(template_definition()))


def manifest_preimage(pool_id: str, network_id: str, parameters: list[dict[str, int]]) -> dict[str, Any]:
    return {
        "carrierCount": len(parameters),
        "carrierRoles": [
            {"ordinal": item["ordinal"], "policyByte": item["policyByte"], "tokenKind": "none", "valueSats": "1000"}
            for item in parameters
        ],
        "networkId": network_id,
        "poolInstanceIdHex": pool_id,
        "proofSchedule": ["commitments", "queries", "fri-openings"],
        "protocolTemplateDigestHex": protocol_template_digest(),
    }


def compute_manifest_digest(pool_id: str, network_id: str, parameters: list[dict[str, int]]) -> str:
    return sha256_bytes(b"PoolActionFv1/CarrierManifest/TestOnly/v1" + compact_json_bytes(manifest_preimage(pool_id, network_id, parameters)))


def instantiate_lock(pool_id: str, manifest_digest: str, ordinal: int, policy_byte: int) -> str:
    # Canonical push opcodes ensure digest bytes are data; decoded OP_CODESEPARATOR count is zero.
    return (b"\x6a\x20" + bytes.fromhex(pool_id) + b"\x20" + bytes.fromhex(manifest_digest)
            + b"\x02" + u16(ordinal) + b"\x01" + bytes((policy_byte,))).hex()


def decoded_codesep_count(script: bytes) -> int:
    count = 0
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        if 1 <= opcode <= 75:
            if offset + opcode > len(script):
                reject("LOCK_PROVENANCE", "truncated canonical push")
            offset += opcode
        elif opcode == 0xAB:
            count += 1
    return count


def make_deployment() -> dict[str, Any]:
    pool_id = h("11")
    policy_bytes = [0x40, 0xAB, 0x42]
    parameters = [{"ordinal": i, "policyByte": policy_bytes[i]} for i in range(3)]
    manifest_digest = compute_manifest_digest(pool_id, "chipnet", parameters)
    locks = [instantiate_lock(pool_id, manifest_digest, item["ordinal"], item["policyByte"]) for item in parameters]
    return {
        "carrierCount": 3,
        "carrierManifestDigestHex": manifest_digest,
        "concreteCarrierLockingBytecodeHex": locks,
        "networkId": "chipnet",
        "networkTag": 1,
        "poolInstanceIdHex": pool_id,
        "proofSecurityProfileDigestHex": h("22"),
        "protocolTemplateDigestHex": protocol_template_digest(),
        "templateDefinition": template_definition(),
        "templateParameters": parameters,
        "tokenKinds": ["none", "none", "none"],
    }


def make_context(action: str, deployment: dict[str, Any]) -> dict[str, Any]:
    pool = deployment["poolInstanceIdHex"]
    if action == "DEPOSIT":
        pre_state = state_hex(0, 0, 0, pool, h("aa"), h("bb"))
        post_state = state_hex(1, 1, 0, pool, h("cc"), h("bb"))
        pre_value, post_value, external_value = "1000", "10001000", "10000500"
        external_role = "DEPOSIT_FUNDING"
    else:
        pre_state = state_hex(1, 1, 0, pool, h("cc"), h("bb"))
        post_state = state_hex(2, 1, 1, pool, h("cc"), h("dd"))
        pre_value, post_value, external_value = "10001000", "1000", "500"
        external_role = "FEE_FUNDING"
    state_token_category = h("44")
    inputs: list[dict[str, Any]] = [{
        "index": 0,
        "outpointIndex": 0,
        "outpointTxidWireHex": h("55"),
        "role": "STATE",
        "roleOrdinal": 0,
        "sequence": 0xFFFFFFFF,
        "sourceLockingBytecodeHex": "51",
        "sourceToken": {"amount": "0", "capability": "mutable", "categoryHex": state_token_category, "commitmentHex": pre_state},
        "sourceValueSats": pre_value,
    }]
    outputs: list[dict[str, Any]] = [{
        "index": 0,
        "lockingBytecodeHex": "51",
        "role": "STATE_SUCCESSOR",
        "roleOrdinal": 0,
        "token": {"amount": "0", "capability": "mutable", "categoryHex": state_token_category, "commitmentHex": post_state},
        "valueSats": post_value,
    }]
    for ordinal, lock in enumerate(deployment["concreteCarrierLockingBytecodeHex"]):
        inputs.append({
            "index": ordinal + 1,
            "outpointIndex": ordinal + 1,
            "outpointTxidWireHex": h("55"),
            "role": "VERIFIER_CARRIER",
            "roleOrdinal": ordinal,
            "sequence": 0xFFFFFFFF,
            "sourceLockingBytecodeHex": lock,
            "sourceToken": copy.deepcopy(NONE_TOKEN),
            "sourceValueSats": "1000",
        })
        outputs.append({
            "index": ordinal + 1,
            "lockingBytecodeHex": lock,
            "role": "VERIFIER_CARRIER_SUCCESSOR",
            "roleOrdinal": ordinal,
            "token": copy.deepcopy(NONE_TOKEN),
            "valueSats": "1000",
        })
    inputs.append({
        "index": 4,
        "outpointIndex": 7,
        "outpointTxidWireHex": h("66"),
        "role": external_role,
        "roleOrdinal": 0,
        "sequence": 0xFFFFFFFF,
        "sourceLockingBytecodeHex": "51",
        "sourceToken": copy.deepcopy(NONE_TOKEN),
        "sourceValueSats": external_value,
    })
    if action == "WITHDRAWAL":
        outputs.append({
            "index": 4,
            "lockingBytecodeHex": "51",
            "role": "PAYOUT",
            "roleOrdinal": 0,
            "token": copy.deepcopy(NONE_TOKEN),
            "valueSats": str(TICKET),
        })
    return {
        "actionKind": action,
        "carrierManifestDigestHex": deployment["carrierManifestDigestHex"],
        "codecVersion": 1,
        "inputs": inputs,
        "locktime": 0,
        "networkId": deployment["networkId"],
        "outputs": outputs,
        "poolInstanceIdHex": pool,
        "proofSecurityProfileDigestHex": deployment["proofSecurityProfileDigestHex"],
        "transactionVersion": 2,
    }


def make_past(action: str, context: dict[str, Any]) -> dict[str, Any]:
    context_bytes = encode_context(context)
    context_digest = sha256_bytes(b"PoolActionFv1/TxContext" + context_bytes)
    carrier_count = len(context["inputs"]) - 2
    payout_index = carrier_count + 1
    payout_lock_digest = ZERO32
    if action == "WITHDRAWAL":
        lock = bytes.fromhex(context["outputs"][payout_index]["lockingBytecodeHex"])
        payout_lock_digest = sha256_bytes(b"PoolActionFv1/PayoutLock" + u16(len(lock)) + lock)
    return {
        "actionKind": action,
        "carrierManifestDigestHex": context["carrierManifestDigestHex"],
        "feeInputIndex": len(context["inputs"]) - 1,
        "feeSats": "500",
        "maxFeeSats": "10000",
        "networkId": context["networkId"],
        "newStateBytesHex": context["outputs"][0]["token"]["commitmentHex"],
        "newStateOutputIndex": 0,
        "newStateValueSats": context["outputs"][0]["valueSats"],
        "noteCommitmentOrZeroHex": h("77") if action == "DEPOSIT" else ZERO32,
        "nullifierOrZeroHex": ZERO32 if action == "DEPOSIT" else h("99"),
        "oldStateBytesHex": context["inputs"][0]["sourceToken"]["commitmentHex"],
        "oldStateOutpointIndex": 0,
        "oldStateOutpointTxidWireHex": context["inputs"][0]["outpointTxidWireHex"],
        "oldStateValueSats": context["inputs"][0]["sourceValueSats"],
        "payoutLockingBytecodeDigestOrZeroHex": payout_lock_digest,
        "payoutOutputIndexOrffff": 0xFFFF if action == "DEPOSIT" else payout_index,
        "payoutSatsOrZero": "0" if action == "DEPOSIT" else str(TICKET),
        "poolInstanceIdHex": context["poolInstanceIdHex"],
        "profileTag": 1,
        "proofSecurityProfileDigestHex": context["proofSecurityProfileDigestHex"],
        "relationVersion": 1,
        "reserveDeltaSats": str(TICKET) if action == "DEPOSIT" else str(-TICKET),
        "ticketSats": str(TICKET),
        "transactionContextDigestHex": context_digest,
        "transparentChangeOutputIndexOrffff": 0xFFFF,
    }


def section_digest(ordinal: int, payload: bytes) -> bytes:
    return hashlib.sha256(b"PoolActionFv1/ProofSection/v1" + u16(ordinal) + payload).digest()


def proof_session_root(past_bytes: bytes, checkpoint: bytes, sections: list[bytes], leaves: list[bytes]) -> bytes:
    profile = past_bytes[41:73]
    manifest = past_bytes[73:105]
    preimage = bytearray(b"PoolActionFv1/ProofSessionRoot/v1")
    preimage += past_bytes + profile + manifest + u16(len(sections)) + checkpoint
    for ordinal, (section, leaf) in enumerate(zip(sections, leaves, strict=True)):
        preimage += u16(ordinal) + u16(len(section))
        preimage += leaf
    return hashlib.sha256(preimage).digest()


def compute_root(past_bytes: bytes, checkpoint: bytes, sections: list[bytes]) -> tuple[bytes, list[bytes]]:
    leaves = [section_digest(i, section) for i, section in enumerate(sections)]
    root = proof_session_root(past_bytes, checkpoint, sections, leaves)
    return root, leaves


def encode_anchor(fields: dict[str, Any]) -> bytes:
    vector = b"".join(fields["membershipLeaves"])
    return (b"PAGH" + u16(fields["wrapperVersion"]) + u16(fields["carrierCount"])
            + u16(fields.get("statementLength", len(fields["past"]))) + fields["past"]
            + fields["root"] + fields["checkpoint"] + u16(fields["membershipCount"])
            + u16(fields.get("membershipVectorLength", len(vector))) + vector
            + u16(fields["ordinal"]) + u16(fields.get("sectionLength", len(fields["section"])))
            + fields["section"])


def encode_nonanchor(fields: dict[str, Any]) -> bytes:
    return (b"PASC" + u16(fields["wrapperVersion"]) + u16(fields["carrierCount"])
            + u16(fields["ordinal"]) + fields["root"] + fields["checkpoint"]
            + u16(fields.get("sectionLength", len(fields["section"]))) + fields["section"])


def decode_wrapper(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_SCRIPT_BYTES:
        reject("SCRIPT_LIMIT", "complete offline wrapper exceeds 10000")
    reader = Reader(data, "proof-session wrapper")
    magic = reader.take(4)
    if magic == b"PAGH":
        version = reader.read_u16()
        count = reader.read_u16()
        statement_length = reader.read_u16()
        if statement_length > MAX_ELEMENT_BYTES:
            reject("ELEMENT_LIMIT", "statement length above 10000")
        past = reader.take(statement_length)
        root = reader.take(32)
        checkpoint = reader.take(32)
        membership_count = reader.read_u16()
        vector_length = reader.read_u16()
        if vector_length > MAX_ELEMENT_BYTES:
            reject("ELEMENT_LIMIT", "membership vector above 10000")
        vector = reader.take(vector_length)
        ordinal = reader.read_u16()
        section_length = reader.read_u16()
        if section_length > MAX_ELEMENT_BYTES:
            reject("ELEMENT_LIMIT", "section above 10000")
        section = reader.take(section_length)
        reader.finish()
        if len(vector) % 32:
            reject("MEMBERSHIP_VECTOR", "membership vector length not multiple of 32")
        return {
            "magic": "PAGH", "wrapperVersion": version, "carrierCount": count,
            "statementLength": statement_length, "past": past, "root": root,
            "checkpoint": checkpoint, "membershipCount": membership_count,
            "membershipVectorLength": vector_length,
            "membershipLeaves": [vector[i:i + 32] for i in range(0, len(vector), 32)],
            "ordinal": ordinal, "sectionLength": section_length, "section": section,
        }
    if magic == b"PASC":
        version = reader.read_u16()
        count = reader.read_u16()
        ordinal = reader.read_u16()
        root = reader.take(32)
        checkpoint = reader.take(32)
        section_length = reader.read_u16()
        if section_length > MAX_ELEMENT_BYTES:
            reject("ELEMENT_LIMIT", "section above 10000")
        section = reader.take(section_length)
        reader.finish()
        return {
            "magic": "PASC", "wrapperVersion": version, "carrierCount": count,
            "ordinal": ordinal, "root": root, "checkpoint": checkpoint,
            "sectionLength": section_length, "section": section,
        }
    reject("ANCHOR_TOPOLOGY", "wrapper magic")


def make_token_bridge() -> list[dict[str, Any]]:
    return [{
        "candidateCanonicalKinds": ["none"],
        "introspectionProjection": {
            "amount": "0", "categoryHex": "", "commitmentHex": "", "hasToken": False,
        },
        "manifestKind": "none",
        "ordinal": ordinal,
    } for ordinal in range(3)]


def make_model(action: str, session_label: str | None = None) -> dict[str, Any]:
    deployment = make_deployment()
    context = make_context(action, deployment)
    context_bytes = encode_context(context)
    past = make_past(action, context)
    past_bytes = encode_past(past)
    label = session_label if session_label is not None else action.lower()
    sections = [f"synthetic-offline-{label}-section-{i}".encode() for i in range(3)]
    checkpoint = hashlib.sha256(b"PoolActionFv1/TestOnlyCheckpoint/v1" + label.encode() + b"\0" + past_bytes).digest()
    root, leaves = compute_root(past_bytes, checkpoint, sections)
    anchor = encode_anchor({
        "wrapperVersion": 1, "carrierCount": 3, "past": past_bytes, "root": root,
        "checkpoint": checkpoint, "membershipCount": 3, "membershipLeaves": leaves,
        "ordinal": 0, "section": sections[0],
    })
    wrappers = [anchor] + [encode_nonanchor({
        "wrapperVersion": 1, "carrierCount": 3, "ordinal": ordinal, "root": root,
        "checkpoint": checkpoint, "section": sections[ordinal],
    }) for ordinal in (1, 2)]
    carriers = [{
        "inputIndex": ordinal + 1,
        "ordinal": ordinal,
        "sourceLockingBytecodeHex": context["inputs"][ordinal + 1]["sourceLockingBytecodeHex"],
        "successorLockingBytecodeHex": context["outputs"][ordinal + 1]["lockingBytecodeHex"],
        "wrapperHex": wrappers[ordinal].hex(),
    } for ordinal in range(3)]
    return {
        "carrierInputs": carriers,
        "deployment": deployment,
        "digestAuthority": {"injectedDigestHex": None, "source": "recomputed-complete-introspection-only"},
        "modelVersion": 1,
        "pastHex": past_bytes.hex(),
        "runtimeNetworkId": "chipnet",
        "tokenBridge": make_token_bridge(),
        "transactionContext": context,
        "txContextHex": context_bytes.hex(),
    }


MODEL_KEYS = {"carrierInputs", "deployment", "digestAuthority", "modelVersion", "pastHex", "runtimeNetworkId", "tokenBridge", "transactionContext", "txContextHex"}
DEPLOYMENT_KEYS = {"carrierCount", "carrierManifestDigestHex", "concreteCarrierLockingBytecodeHex", "networkId", "networkTag", "poolInstanceIdHex", "proofSecurityProfileDigestHex", "protocolTemplateDigestHex", "templateDefinition", "templateParameters", "tokenKinds"}
CARRIER_KEYS = {"inputIndex", "ordinal", "sourceLockingBytecodeHex", "successorLockingBytecodeHex", "wrapperHex"}
BRIDGE_KEYS = {"candidateCanonicalKinds", "introspectionProjection", "manifestKind", "ordinal"}
PROJECTION_KEYS = {"amount", "categoryHex", "commitmentHex", "hasToken"}


def validate_deployment(deployment: Any, runtime_network: Any) -> None:
    exact_keys(deployment, DEPLOYMENT_KEYS, "MANIFEST_DERIVATION", "deployment")
    network = deployment["networkId"]
    if network not in NETWORK_TAGS:
        reject("NETWORK_UNSUPPORTED", "deployment network outside exact enum")
    if deployment["networkTag"] != NETWORK_TAGS[network]:
        reject("NETWORK_TAG_MISMATCH", "deployment network/tag mismatch")
    if runtime_network != network:
        reject("DEPLOYMENT_NETWORK_MISMATCH", "runtime network differs from deployment")
    if deployment["carrierCount"] != 3:
        reject("MANIFEST_DERIVATION", "test manifest carrier count")
    require_hex(deployment["poolInstanceIdHex"], 32, "MANIFEST_DERIVATION", "pool id")
    require_hex(deployment["proofSecurityProfileDigestHex"], 32, "MANIFEST_DERIVATION", "profile")
    if deployment["templateDefinition"] != template_definition() or deployment["protocolTemplateDigestHex"] != protocol_template_digest():
        reject("TEMPLATE_PROVENANCE", "template identity")
    params = deployment["templateParameters"]
    if not isinstance(params, list) or len(params) != 3:
        reject("TEMPLATE_PROVENANCE", "template parameters")
    for ordinal, item in enumerate(params):
        exact_keys(item, {"ordinal", "policyByte"}, "TEMPLATE_PROVENANCE", "template parameter")
        expected_policy = [0x40, 0xAB, 0x42][ordinal]
        if item["ordinal"] != ordinal or require_uint(item["policyByte"], 8, "TEMPLATE_PROVENANCE", "policy byte") != expected_policy:
            reject("TEMPLATE_PROVENANCE", "typed template parameter")
    expected_manifest = compute_manifest_digest(deployment["poolInstanceIdHex"], network, params)
    if deployment["carrierManifestDigestHex"] != expected_manifest:
        reject("MANIFEST_DERIVATION", "manifest digest")
    expected_locks = [instantiate_lock(deployment["poolInstanceIdHex"], expected_manifest, i, params[i]["policyByte"]) for i in range(3)]
    if deployment["concreteCarrierLockingBytecodeHex"] != expected_locks:
        reject("LOCK_PROVENANCE", "concrete lock derivation")
    if deployment["tokenKinds"] != ["none", "none", "none"]:
        reject("TOKEN_MANIFEST_BRIDGE", "deployment-static token kinds")
    for lock in expected_locks:
        if decoded_codesep_count(bytes.fromhex(lock)) != 0:
            reject("LOCK_PROVENANCE", "decoded OP_CODESEPARATOR")


def validate_past_context(past: dict[str, Any], context: dict[str, Any], context_bytes: bytes) -> None:
    fields = (
        (past["networkId"], context["networkId"]),
        (past["actionKind"], context["actionKind"]),
        (past["poolInstanceIdHex"], context["poolInstanceIdHex"]),
        (past["proofSecurityProfileDigestHex"], context["proofSecurityProfileDigestHex"]),
        (past["carrierManifestDigestHex"], context["carrierManifestDigestHex"]),
        (past["oldStateOutpointTxidWireHex"], context["inputs"][0]["outpointTxidWireHex"]),
        (past["oldStateOutpointIndex"], context["inputs"][0]["outpointIndex"]),
        (past["oldStateValueSats"], context["inputs"][0]["sourceValueSats"]),
        (past["oldStateBytesHex"], context["inputs"][0]["sourceToken"]["commitmentHex"]),
        (past["newStateOutputIndex"], context["outputs"][0]["index"]),
        (past["newStateValueSats"], context["outputs"][0]["valueSats"]),
        (past["newStateBytesHex"], context["outputs"][0]["token"]["commitmentHex"]),
        (past["feeInputIndex"], context["inputs"][-1]["index"]),
    )
    if any(left != right for left, right in fields):
        reject("PAST_CONTEXT_MISMATCH", "direct PAST/context projection")
    carrier_count = len(context["inputs"]) - 2
    if past["actionKind"] == "WITHDRAWAL":
        payout = context["outputs"][carrier_count + 1]
        lock = bytes.fromhex(payout["lockingBytecodeHex"])
        digest = sha256_bytes(b"PoolActionFv1/PayoutLock" + u16(len(lock)) + lock)
        if (past["payoutOutputIndexOrffff"] != payout["index"] or past["payoutSatsOrZero"] != payout["valueSats"]
                or past["payoutLockingBytecodeDigestOrZeroHex"] != digest):
            reject("PAST_CONTEXT_MISMATCH", "payout projection")
    source_total = sum(int(item["sourceValueSats"]) for item in context["inputs"])
    output_total = sum(int(item["valueSats"]) for item in context["outputs"])
    if str(source_total - output_total) != past["feeSats"]:
        reject("PAST_CONTEXT_MISMATCH", "fee projection")
    digest = sha256_bytes(b"PoolActionFv1/TxContext" + context_bytes)
    if past["transactionContextDigestHex"] != digest:
        reject("STALE_CONTEXT_DIGEST", "recomputed complete context digest differs")


def validate_locks_and_bridge(model: dict[str, Any], context: dict[str, Any]) -> None:
    deployment = model["deployment"]
    carriers = model["carrierInputs"]
    if not isinstance(carriers, list):
        reject("ANCHOR_TOPOLOGY", "carrier input list")
    for ordinal, carrier in enumerate(carriers):
        exact_keys(carrier, CARRIER_KEYS, "ANCHOR_TOPOLOGY", "carrier input")
        if ordinal >= len(deployment["concreteCarrierLockingBytecodeHex"]):
            break
        expected = deployment["concreteCarrierLockingBytecodeHex"][ordinal]
        if (carrier["sourceLockingBytecodeHex"] != expected or carrier["successorLockingBytecodeHex"] != expected
                or context["inputs"][ordinal + 1]["sourceLockingBytecodeHex"] != expected
                or context["outputs"][ordinal + 1]["lockingBytecodeHex"] != expected):
            reject("LOCK_SUBSTITUTION", "carrier full lock differs from manifest")
    bridges = model["tokenBridge"]
    if not isinstance(bridges, list) or len(bridges) != deployment["carrierCount"]:
        reject("TOKEN_MANIFEST_BRIDGE", "token bridge count")
    for ordinal, bridge in enumerate(bridges):
        exact_keys(bridge, BRIDGE_KEYS, "TOKEN_MANIFEST_BRIDGE", "token bridge")
        exact_keys(bridge["introspectionProjection"], PROJECTION_KEYS, "TOKEN_MANIFEST_BRIDGE", "token projection")
        candidates = bridge["candidateCanonicalKinds"]
        if not isinstance(candidates, list) or any(item not in TOKEN_KIND_TAGS for item in candidates) or len(candidates) != len(set(candidates)):
            reject("TOKEN_MANIFEST_BRIDGE", "token candidates malformed")
        if len(candidates) != 1:
            reject("TOKEN_NONINJECTIVE_COLLISION", "introspection projection has multiple token-kind preimages")
        if bridge["ordinal"] != ordinal or bridge["manifestKind"] != deployment["tokenKinds"][ordinal] or candidates[0] != bridge["manifestKind"]:
            reject("TOKEN_MANIFEST_BRIDGE", "token kind differs from exact manifest")


def validate_topology(model: dict[str, Any], past_bytes: bytes) -> None:
    carriers = model["carrierInputs"]
    count = model["deployment"]["carrierCount"]
    if len(carriers) != count:
        reject("SECTION_OMISSION", "carrier/section count")
    decoded: list[dict[str, Any]] = []
    for position, carrier in enumerate(carriers):
        if carrier["inputIndex"] != position + 1:
            reject("ANCHOR_TOPOLOGY", "carrier input position")
        if carrier["ordinal"] != position:
            reject("ORDINAL_SCHEDULE", "carrier record ordinal")
        decoded.append(decode_wrapper(bytes.fromhex(carrier["wrapperHex"])))
    anchor = decoded[0]
    if anchor["magic"] != "PAGH" or carriers[0]["inputIndex"] != 1 or anchor["ordinal"] != 0:
        reject("ANCHOR_TOPOLOGY", "missing/moved sole anchor")
    if anchor["statementLength"] != 589 or anchor["past"] != past_bytes:
        reject("PAST_BINDING", "anchor PAST")
    if anchor["wrapperVersion"] != 1:
        reject("WRAPPER_VERSION", "anchor wrapper version")
    if anchor["carrierCount"] != count or anchor["membershipCount"] != count:
        reject("COUNT_BINDING", "anchor count")
    if anchor["membershipVectorLength"] != count * 32 or len(anchor["membershipLeaves"]) != count:
        reject("MEMBERSHIP_VECTOR", "anchor membership vector")
    sections: list[bytes] = []
    for ordinal, wrapper in enumerate(decoded):
        expected_magic = "PAGH" if ordinal == 0 else "PASC"
        if wrapper["magic"] != expected_magic:
            reject("ANCHOR_TOPOLOGY", "sole anchor grammar")
        if wrapper["wrapperVersion"] != 1:
            reject("WRAPPER_VERSION", "wrapper version")
        if wrapper["carrierCount"] != count:
            reject("COUNT_BINDING", "local count")
        if wrapper["ordinal"] != ordinal:
            reject("ORDINAL_SCHEDULE", "wrapper ordinal")
        if wrapper["sectionLength"] != len(wrapper["section"]):
            reject("LENGTH_ALIAS", "section length alias")
        if len(wrapper["section"]) > MAX_ELEMENT_BYTES:
            reject("ELEMENT_LIMIT", "section element")
        sections.append(wrapper["section"])
    leaves = [section_digest(i, section) for i, section in enumerate(sections)]
    if anchor["membershipLeaves"] != leaves:
        reject("MEMBERSHIP_VECTOR", "state-recomputed leaf vector")
    root, recomputed_leaves = compute_root(past_bytes, anchor["checkpoint"], sections)
    if recomputed_leaves != leaves or anchor["root"] != root:
        reject("ROOT_BINDING", "state-recomputed root")
    for wrapper in decoded[1:]:
        if wrapper["root"] != root:
            reject("ROOT_BINDING", "local root differs")
        if wrapper["checkpoint"] != anchor["checkpoint"]:
            reject("CHECKPOINT_BINDING", "local checkpoint differs")


def validate_model(model: Any) -> None:
    exact_keys(model, MODEL_KEYS, "MODEL_ENVELOPE", "model")
    if model["modelVersion"] != 1:
        reject("MODEL_ENVELOPE", "model version")
    validate_deployment(model["deployment"], model["runtimeNetworkId"])
    exact_keys(model["digestAuthority"], {"injectedDigestHex", "source"}, "INJECTED_CONTEXT_DIGEST", "digest authority")
    if model["digestAuthority"] != {"injectedDigestHex": None, "source": "recomputed-complete-introspection-only"}:
        reject("INJECTED_CONTEXT_DIGEST", "external digest authority forbidden")
    context_hex = require_hex(model["txContextHex"], None, "CONTEXT_CANONICAL", "TxContextFv1")
    decoded_context = decode_context(context_hex)
    if decoded_context != model["transactionContext"]:
        reject("CONTEXT_CANONICAL", "introspection object/complete preimage mismatch")
    if encode_context(decoded_context) != context_hex:
        reject("CONTEXT_CANONICAL", "TxContextFv1 not canonical")
    past_bytes = require_hex(model["pastHex"], 589, "PAST_CANONICAL", "PAST")
    past = decode_past(past_bytes)
    if encode_past(past) != past_bytes:
        reject("PAST_CANONICAL", "PAST round trip")
    deployment = model["deployment"]
    if (past["networkId"] != deployment["networkId"] or past["poolInstanceIdHex"] != deployment["poolInstanceIdHex"]
            or past["proofSecurityProfileDigestHex"] != deployment["proofSecurityProfileDigestHex"]
            or past["carrierManifestDigestHex"] != deployment["carrierManifestDigestHex"]):
        reject("PAST_DEPLOYMENT_MISMATCH", "PAST/deployment identity")
    validate_past_context(past, decoded_context, context_hex)
    validate_locks_and_bridge(model, decoded_context)
    validate_topology(model, past_bytes)


def replace_context(model: dict[str, Any], mutate) -> None:
    mutate(model["transactionContext"])
    model["txContextHex"] = encode_context(model["transactionContext"]).hex()


def wrapper_fields(model: dict[str, Any], ordinal: int) -> dict[str, Any]:
    return decode_wrapper(bytes.fromhex(model["carrierInputs"][ordinal]["wrapperHex"]))


def set_wrapper(model: dict[str, Any], ordinal: int, fields: dict[str, Any]) -> None:
    encoder = encode_anchor if fields["magic"] == "PAGH" else encode_nonanchor
    model["carrierInputs"][ordinal]["wrapperHex"] = encoder(fields).hex()


def flip_hex(value: str, byte_index: int = 0) -> str:
    data = bytearray.fromhex(value)
    data[byte_index] ^= 1
    return data.hex()


def mutate_model(model: dict[str, Any], mutation_id: str, other: dict[str, Any]) -> None:
    # Every mutation is a closed, no-parameter operation. Unknown identifiers fail.
    if mutation_id == "none":
        return
    if mutation_id == "unsupported_network":
        model["deployment"]["networkId"] = "testnet4"
        return
    if mutation_id == "deployment_network_mismatch":
        model["runtimeNetworkId"] = "mainnet"
        return
    if mutation_id == "network_tag_mismatch":
        model["deployment"]["networkTag"] = 0
        return
    if mutation_id == "injected_context_digest":
        model["digestAuthority"] = {"injectedDigestHex": h("88"), "source": "injected-fact"}
        return
    if mutation_id.startswith("ctx_"):
        context = model["transactionContext"]
        actions = {
            "ctx_network": lambda c: c.__setitem__("networkId", "mainnet"),
            "ctx_action": lambda c: c.__setitem__("actionKind", "WITHDRAWAL" if c["actionKind"] == "DEPOSIT" else "DEPOSIT"),
            "ctx_pool": lambda c: c.__setitem__("poolInstanceIdHex", h("12")),
            "ctx_manifest": lambda c: c.__setitem__("carrierManifestDigestHex", h("34")),
            "ctx_profile": lambda c: c.__setitem__("proofSecurityProfileDigestHex", h("23")),
            "ctx_transaction_version": lambda c: c.__setitem__("transactionVersion", 3),
            "ctx_locktime": lambda c: c.__setitem__("locktime", 1),
            "ctx_input_index": lambda c: c["inputs"][2].__setitem__("index", 9),
            "ctx_input_role": lambda c: c["inputs"][2].__setitem__("role", "FEE_FUNDING"),
            "ctx_input_ordinal": lambda c: c["inputs"][2].__setitem__("roleOrdinal", 9),
            "ctx_input_txid": lambda c: c["inputs"][2].__setitem__("outpointTxidWireHex", h("57")),
            "ctx_input_outpoint": lambda c: c["inputs"][2].__setitem__("outpointIndex", 9),
            "ctx_input_sequence": lambda c: c["inputs"][2].__setitem__("sequence", 0xFFFFFFFE),
            "ctx_input_value": lambda c: c["inputs"][-1].__setitem__("sourceValueSats", str(int(c["inputs"][-1]["sourceValueSats"]) + 1)),
            "ctx_input_lock": lambda c: c["inputs"][2].__setitem__("sourceLockingBytecodeHex", c["inputs"][2]["sourceLockingBytecodeHex"] + "00"),
            "ctx_input_token": lambda c: c["inputs"][-1].__setitem__("sourceToken", {"amount": "1", "capability": "fungible-only", "categoryHex": h("70"), "commitmentHex": ""}),
            "ctx_output_index": lambda c: c["outputs"][2].__setitem__("index", 9),
            "ctx_output_role": lambda c: c["outputs"][2].__setitem__("role", "PAYOUT"),
            "ctx_output_ordinal": lambda c: c["outputs"][2].__setitem__("roleOrdinal", 9),
            "ctx_output_value": lambda c: c["outputs"][2].__setitem__("valueSats", "1001"),
            "ctx_output_lock": lambda c: c["outputs"][2].__setitem__("lockingBytecodeHex", c["outputs"][2]["lockingBytecodeHex"] + "00"),
            "ctx_output_token": lambda c: c["outputs"][2].__setitem__("token", {"amount": "1", "capability": "fungible-only", "categoryHex": h("71"), "commitmentHex": ""}),
        }
        if mutation_id == "ctx_input_count":
            data = bytearray.fromhex(model["txContextHex"])
            data[112:114] = u16(4)
            model["txContextHex"] = data.hex()
            return
        if mutation_id == "ctx_output_count":
            prefix_context = copy.deepcopy(context)
            prefix_context["outputs"] = []
            # Fixed header plus input count and exact encoded inputs; locate outputCount without parsing project code.
            encoded = encode_context(context)
            input_only = bytearray(b"PCTX" + u16(1) + bytes((NETWORK_TAGS[context["networkId"]], ACTION_TAGS[context["actionKind"]])))
            input_only += bytes.fromhex(context["poolInstanceIdHex"] + context["carrierManifestDigestHex"] + context["proofSecurityProfileDigestHex"])
            input_only += u32(2) + u32(0) + u16(len(context["inputs"]))
            for item in context["inputs"]:
                input_only += u16(item["index"]) + bytes((INPUT_ROLE_TAGS[item["role"]],)) + u16(item["roleOrdinal"])
                input_only += bytes.fromhex(item["outpointTxidWireHex"]) + u32(item["outpointIndex"]) + u32(item["sequence"]) + u64(int(item["sourceValueSats"]))
                lock = bytes.fromhex(item["sourceLockingBytecodeHex"])
                input_only += u16(len(lock)) + lock + encode_token(item["sourceToken"])
            data = bytearray(encoded)
            data[len(input_only):len(input_only) + 2] = u16(len(context["outputs"]) - 1)
            model["txContextHex"] = data.hex()
            return
        action = actions.get(mutation_id)
        if action is None:
            reject("UNLISTED_MUTATION", mutation_id)
        action(context)
        try:
            model["txContextHex"] = encode_context(context).hex()
        except Reject:
            # Materialize the mutated introspection object even when it no longer has a canonical encoding.
            return
        return
    if mutation_id == "stale_context_digest":
        context = model["transactionContext"]
        context["inputs"][-1]["outpointTxidWireHex"] = h("67")
        model["txContextHex"] = encode_context(context).hex()
        return
    if mutation_id == "token_noninjective_collision":
        bridge = model["tokenBridge"][1]
        bridge["candidateCanonicalKinds"] = ["fungible-only", "immutable"]
        bridge["introspectionProjection"] = {"amount": "1", "categoryHex": h("70"), "commitmentHex": "", "hasToken": True}
        return
    if mutation_id == "manifest_kind_bridge_failure":
        bridge = model["tokenBridge"][1]
        bridge["candidateCanonicalKinds"] = ["fungible-only"]
        bridge["introspectionProjection"] = {"amount": "1", "categoryHex": h("70"), "commitmentHex": "", "hasToken": True}
        return
    if mutation_id == "carrier_lock_substitution":
        alternate = "51"
        ordinal = 1
        model["carrierInputs"][ordinal]["sourceLockingBytecodeHex"] = alternate
        model["carrierInputs"][ordinal]["successorLockingBytecodeHex"] = alternate
        return
    if mutation_id == "wrong_template_parameter":
        model["deployment"]["templateParameters"][1]["policyByte"] = 0x7F
        return
    if mutation_id == "missing_anchor":
        replacement = wrapper_fields(model, 1)
        replacement["ordinal"] = 0
        model["carrierInputs"][0]["wrapperHex"] = encode_nonanchor(replacement).hex()
        return
    if mutation_id == "moved_anchor":
        model["carrierInputs"][0]["wrapperHex"], model["carrierInputs"][1]["wrapperHex"] = model["carrierInputs"][1]["wrapperHex"], model["carrierInputs"][0]["wrapperHex"]
        return
    if mutation_id in {"wrong_past", "wrong_profile", "wrong_manifest", "wrong_count", "wrong_ordinal", "wrong_section", "wrong_root", "wrong_checkpoint", "membership_leaf"}:
        ordinal = 0 if mutation_id in {"wrong_past", "wrong_profile", "wrong_manifest", "wrong_count", "wrong_root", "wrong_checkpoint", "membership_leaf"} else 1
        fields = wrapper_fields(model, ordinal)
        if mutation_id == "wrong_past":
            fields["past"] = b"X" + fields["past"][1:]
        elif mutation_id == "wrong_profile":
            data = bytearray(fields["past"]); data[41] ^= 1; fields["past"] = bytes(data)
        elif mutation_id == "wrong_manifest":
            data = bytearray(fields["past"]); data[73] ^= 1; fields["past"] = bytes(data)
        elif mutation_id == "wrong_count":
            fields["carrierCount"] = 2
        elif mutation_id == "wrong_ordinal":
            fields["ordinal"] = 2
        elif mutation_id == "wrong_section":
            fields["section"] = fields["section"] + b"!"
            fields["sectionLength"] = len(fields["section"])
        elif mutation_id == "wrong_root":
            fields["root"] = bytes((fields["root"][0] ^ 1,)) + fields["root"][1:]
        elif mutation_id == "wrong_checkpoint":
            fields["checkpoint"] = bytes((fields["checkpoint"][0] ^ 1,)) + fields["checkpoint"][1:]
        elif mutation_id == "membership_leaf":
            leaf = fields["membershipLeaves"][1]
            fields["membershipLeaves"][1] = bytes((leaf[0] ^ 1,)) + leaf[1:]
        set_wrapper(model, ordinal, fields)
        return
    if mutation_id == "section_omission":
        del model["carrierInputs"][2]
        return
    if mutation_id == "section_duplication":
        source = wrapper_fields(model, 1)["section"]
        fields = wrapper_fields(model, 2)
        fields["section"] = source
        set_wrapper(model, 2, fields)
        return
    if mutation_id == "section_reorder":
        model["carrierInputs"][1]["wrapperHex"], model["carrierInputs"][2]["wrapperHex"] = model["carrierInputs"][2]["wrapperHex"], model["carrierInputs"][1]["wrapperHex"]
        return
    if mutation_id == "wrapper_trailing_byte":
        model["carrierInputs"][1]["wrapperHex"] += "00"
        return
    if mutation_id == "section_length_alias":
        raw = bytearray.fromhex(model["carrierInputs"][1]["wrapperHex"])
        length_offset = 4 + 2 + 2 + 2 + 32 + 32
        original = struct.unpack("<H", raw[length_offset:length_offset + 2])[0]
        raw[length_offset:length_offset + 2] = u16(original + 1)
        model["carrierInputs"][1]["wrapperHex"] = raw.hex()
        return
    if mutation_id == "cross_session_splice":
        model["carrierInputs"][1]["wrapperHex"] = other["carrierInputs"][1]["wrapperHex"]
        return
    if mutation_id == "cross_session_splice_two_carriers":
        model["carrierInputs"][1]["wrapperHex"] = other["carrierInputs"][1]["wrapperHex"]
        model["carrierInputs"][2]["wrapperHex"] = other["carrierInputs"][2]["wrapperHex"]
        return
    if mutation_id == "cross_session_splice_c":
        model["carrierInputs"][2]["wrapperHex"] = other["carrierInputs"][2]["wrapperHex"]
        return
    if mutation_id == "section_payload_over_10000":
        fields = wrapper_fields(model, 1)
        fields["section"] = b"x" * 10001
        set_wrapper(model, 1, fields)
        return
    if mutation_id == "complete_wrapper_over_10000":
        fields = wrapper_fields(model, 0)
        fields["section"] = b"x" * 9234
        encoded = encode_anchor(fields)
        if len(encoded) != 10001:
            raise AssertionError(len(encoded))
        model["carrierInputs"][0]["wrapperHex"] = encoded.hex()
        return
    if mutation_id == "declared_element_length_over_10000":
        raw = bytearray.fromhex(model["carrierInputs"][0]["wrapperHex"])
        vector_length_offset = 4 + 2 + 2 + 2 + 589 + 32 + 32 + 2
        raw[vector_length_offset:vector_length_offset + 2] = u16(10001)
        model["carrierInputs"][0]["wrapperHex"] = raw.hex()
        return
    reject("UNLISTED_MUTATION", mutation_id)


CONTEXT_CASES = [
    ("CTX-01-NETWORK-TAG", "ctx_network", "header.networkTag"),
    ("CTX-02-ACTION-TAG", "ctx_action", "header.actionTag"),
    ("CTX-03-POOL-ID", "ctx_pool", "header.poolInstanceId"),
    ("CTX-04-MANIFEST", "ctx_manifest", "header.carrierManifestDigest"),
    ("CTX-05-PROFILE", "ctx_profile", "header.proofSecurityProfileDigest"),
    ("CTX-06-TX-VERSION", "ctx_transaction_version", "transaction.transactionVersion"),
    ("CTX-07-LOCKTIME", "ctx_locktime", "transaction.locktime"),
    ("CTX-08-INPUT-COUNT", "ctx_input_count", "transaction.inputCount"),
    ("CTX-09-OUTPUT-COUNT", "ctx_output_count", "transaction.outputCount"),
    ("CTX-10-INPUT-INDEX", "ctx_input_index", "input.index"),
    ("CTX-11-INPUT-ROLE", "ctx_input_role", "input.roleTag"),
    ("CTX-12-INPUT-ORDINAL", "ctx_input_ordinal", "input.roleOrdinal"),
    ("CTX-13-INPUT-TXID", "ctx_input_txid", "input.outpointTxidWire"),
    ("CTX-14-INPUT-OUTPOINT", "ctx_input_outpoint", "input.outpointIndex"),
    ("CTX-15-INPUT-SEQUENCE", "ctx_input_sequence", "input.sequence"),
    ("CTX-16-INPUT-VALUE", "ctx_input_value", "input.sourceValue"),
    ("CTX-17-INPUT-LOCK", "ctx_input_lock", "input.completeSourceLockingBytecode"),
    ("CTX-18-INPUT-TOKEN", "ctx_input_token", "input.completeSourceTokenRecord"),
    ("CTX-19-OUTPUT-INDEX", "ctx_output_index", "output.index"),
    ("CTX-20-OUTPUT-ROLE", "ctx_output_role", "output.roleTag"),
    ("CTX-21-OUTPUT-ORDINAL", "ctx_output_ordinal", "output.roleOrdinal"),
    ("CTX-22-OUTPUT-VALUE", "ctx_output_value", "output.value"),
    ("CTX-23-OUTPUT-LOCK", "ctx_output_lock", "output.completeLockingBytecode"),
    ("CTX-24-OUTPUT-TOKEN", "ctx_output_token", "output.completeTokenRecord"),
]


CASE_SPECS_BASE = [
    ("POS-01-DEPOSIT", "deposit", "none", "ACCEPT", None, "canonical synthetic DEPOSIT projection"),
    ("POS-02-WITHDRAWAL", "withdrawal", "none", "ACCEPT", None, "canonical synthetic WITHDRAWAL projection"),
    ("NET-01-UNSUPPORTED", "deposit", "unsupported_network", "REJECT", "NETWORK_UNSUPPORTED", "unsupported historical schema-valid network"),
    ("NET-02-DEPLOYMENT-MISMATCH", "deposit", "deployment_network_mismatch", "REJECT", "DEPLOYMENT_NETWORK_MISMATCH", "runtime/deployment network mismatch"),
    ("NET-03-TAG-MISMATCH", "deposit", "network_tag_mismatch", "REJECT", "NETWORK_TAG_MISMATCH", "networkId/networkTag mismatch"),
    ("DIGEST-01-INJECTED", "deposit", "injected_context_digest", "REJECT", "INJECTED_CONTEXT_DIGEST", "injected digest authority"),
    ("DIGEST-02-STALE", "deposit", "stale_context_digest", "REJECT", "STALE_CONTEXT_DIGEST", "stale digest after included-field mutation"),
    ("TOKEN-01-NONINJECTIVE", "deposit", "token_noninjective_collision", "REJECT", "TOKEN_NONINJECTIVE_COLLISION", "fungible-only versus immutable-empty projection collision"),
    ("TOKEN-02-MANIFEST-BRIDGE", "deposit", "manifest_kind_bridge_failure", "REJECT", "TOKEN_MANIFEST_BRIDGE", "deployment-static token-kind bridge failure"),
    ("LOCK-01-SUBSTITUTION", "deposit", "carrier_lock_substitution", "REJECT", "LOCK_SUBSTITUTION", "source/successor lock substitution preserving value/token"),
    ("LOCK-02-TEMPLATE-PARAM", "deposit", "wrong_template_parameter", "REJECT", "TEMPLATE_PROVENANCE", "wrong typed template parameter"),
    ("TOP-01-MISSING-ANCHOR", "deposit", "missing_anchor", "REJECT", "ANCHOR_TOPOLOGY", "missing sole anchor"),
    ("TOP-02-MOVED-ANCHOR", "deposit", "moved_anchor", "REJECT", "ANCHOR_TOPOLOGY", "moved sole anchor"),
    ("TOP-03-WRONG-PAST", "deposit", "wrong_past", "REJECT", "PAST_BINDING", "wrong exact PAST"),
    ("TOP-04-WRONG-PROFILE", "deposit", "wrong_profile", "REJECT", "PAST_BINDING", "wrong PAST profile digest"),
    ("TOP-05-WRONG-MANIFEST", "deposit", "wrong_manifest", "REJECT", "PAST_BINDING", "wrong PAST manifest digest"),
    ("TOP-06-WRONG-COUNT", "deposit", "wrong_count", "REJECT", "COUNT_BINDING", "wrong carrier count"),
    ("TOP-07-WRONG-ORDINAL", "deposit", "wrong_ordinal", "REJECT", "ORDINAL_SCHEDULE", "wrong carrier ordinal"),
    ("TOP-08-WRONG-SECTION", "deposit", "wrong_section", "REJECT", "MEMBERSHIP_VECTOR", "wrong raw section payload"),
    ("TOP-09-WRONG-ROOT", "deposit", "wrong_root", "REJECT", "ROOT_BINDING", "wrong state-authoritative root"),
    ("TOP-10-WRONG-CHECKPOINT", "deposit", "wrong_checkpoint", "REJECT", "ROOT_BINDING", "wrong transcript checkpoint"),
    ("TOP-11-SECTION-OMISSION", "deposit", "section_omission", "REJECT", "SECTION_OMISSION", "section omission"),
    ("TOP-12-SECTION-DUPLICATION", "deposit", "section_duplication", "REJECT", "MEMBERSHIP_VECTOR", "section duplication"),
    ("TOP-13-SECTION-REORDER", "deposit", "section_reorder", "REJECT", "ORDINAL_SCHEDULE", "section/carrier reorder"),
    ("TOP-14-TRAILING", "deposit", "wrapper_trailing_byte", "REJECT", "FULL_CONSUMPTION", "unconsumed wrapper byte"),
    ("TOP-15-LENGTH-ALIAS", "deposit", "section_length_alias", "REJECT", "FULL_CONSUMPTION", "declared section-length alias"),
    ("TOP-16-CROSS-SPLICE", "deposit", "cross_session_splice", "REJECT", "MEMBERSHIP_VECTOR", "two-session cross-splice with three carriers"),
    ("TOP-16B-CROSS-SPLICE-TWO", "deposit", "cross_session_splice_two_carriers", "REJECT", "MEMBERSHIP_VECTOR", "two-session two-carrier cross-splice"),
    ("TOP-16C-CROSS-SPLICE-THREE-BASES", "deposit", "cross_session_splice_c", "REJECT", "MEMBERSHIP_VECTOR", "A/C cross-splice after A/B/C antecedent validation"),
    ("TOP-17-MEMBERSHIP-LEAF", "deposit", "membership_leaf", "REJECT", "MEMBERSHIP_VECTOR", "wrong ordered membership leaf"),
    ("LIMIT-01-ELEMENT-10001", "deposit", "section_payload_over_10000", "REJECT", "SCRIPT_LIMIT", "10001-byte section and wrapper"),
    ("LIMIT-02-WRAPPER-10001", "deposit", "complete_wrapper_over_10000", "REJECT", "SCRIPT_LIMIT", "10001-byte complete wrapper with sub-10001 section"),
    ("LIMIT-03-DECLARED-10001", "deposit", "declared_element_length_over_10000", "REJECT", "ELEMENT_LIMIT", "u16 element length above static 10000 ceiling"),
]


def case_specs() -> list[tuple[str, str, str, str, str | None, str]]:
    context = [(case_id, "deposit", mutation, "REJECT", "__AUTO_STRICT__", f"stale/rejected complete context field class {field_class}")
               for case_id, mutation, field_class in CONTEXT_CASES]
    return CASE_SPECS_BASE[:7] + context + CASE_SPECS_BASE[7:]


def audit_family_contract() -> list[dict[str, Any]]:
    """Exact 57-family review contract; status never follows from case count alone."""
    rows: list[tuple[str, str, str, list[str]]] = [
        ("POS-01", "positives", "mainnet DEPOSIT N=3", []),
        ("POS-02", "positives", "mainnet WITHDRAWAL N=3", []),
        ("POS-03", "positives", "chipnet DEPOSIT N=3", ["POS-01-DEPOSIT"]),
        ("POS-04", "positives", "chipnet WITHDRAWAL N=3", ["POS-02-WITHDRAWAL"]),
        ("POS-05", "positives", "regtest DEPOSIT N=3", []),
        ("POS-06", "positives", "regtest WITHDRAWAL N=3", []),
        ("POS-07", "positives", "unlocking bytecodes excluded from TxContextFv1 without loss of authenticated context", []),
        ("POS-08", "positives", "proof bytes excluded from TxContextFv1 without loss of authenticated context", []),
        ("POS-09", "positives", "canonical token grammar kinds 0 through 4", []),
        ("POS-10", "positives", "deployment-static carrier token kind none for N=3", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("POS-11", "positives", "acyclic N=3 lock instantiation with pushed-data byte ab not decoded OP_CODESEPARATOR", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("POS-12", "positives", "valid independent session antecedents A B and C before splice", ["TOP-16C-CROSS-SPLICE-THREE-BASES"]),
        ("NET-01", "networks", "unsupported historical schema-valid network rejected", ["NET-01-UNSUPPORTED"]),
        ("NET-02", "networks", "networkId and networkTag mismatch rejected", ["NET-03-TAG-MISMATCH"]),
        ("NET-03", "networks", "deployment and runtime network mismatch rejected", ["NET-02-DEPLOYMENT-MISMATCH"]),
        ("NET-04", "networks", "all three supported network mappings accepted for both actions", []),
        ("CTX-01", "contextToken", "injected digest authority rejected", ["DIGEST-01-INJECTED"]),
        ("CTX-02", "contextToken", "stale digest after included-field mutation rejected", ["DIGEST-02-STALE"]),
        ("CTX-03", "contextToken", "complete included TxContextFv1 field-class mutation matrix", [row[0] for row in CONTEXT_CASES]),
        ("CTX-04", "contextToken", "direct PAST projection mutation matrix", ["TOP-03-WRONG-PAST", "TOP-04-WRONG-PROFILE", "TOP-05-WRONG-MANIFEST"]),
        ("CTX-05", "contextToken", "fungible-only versus immutable-empty non-injective token collision", ["TOKEN-01-NONINJECTIVE"]),
        ("CTX-06", "contextToken", "deployment-static manifest-kind bridge mismatch", ["TOKEN-02-MANIFEST-BRIDGE"]),
        ("CTX-07", "contextToken", "complete TxContextFv1 parse rejects partial or trailing input", []),
        ("CTX-08", "contextToken", "excluded-boundary mutations retain canonical context digest but remain session-authenticated", []),
        ("CTX-09", "contextToken", "exact 589-byte PAST and TxContextFv1 identity for both actions", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("LOCK-01", "locks", "complete carrier lock substitution rejected", ["LOCK-01-SUBSTITUTION"]),
        ("LOCK-02", "locks", "wrong typed template parameter rejected", ["LOCK-02-TEMPLATE-PARAM"]),
        ("LOCK-03", "locks", "three concrete locks derived from pinned typed parameters", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("LOCK-04", "locks", "pushed-data ab control has decoded OP_CODESEPARATOR count zero", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("LOCK-05", "locks", "decoded OP_CODESEPARATOR opcode rejected", []),
        ("LOCK-06", "locks", "non-executed complete-script suffix substitution rejected", []),
        ("LOCK-07", "locks", "template manifest concrete-lock derivation cycle rejected", []),
        ("SESSION-01", "sessions", "sole anchor fixed at input 1", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("SESSION-02", "sessions", "wrong PAST rejected", ["TOP-03-WRONG-PAST"]),
        ("SESSION-03", "sessions", "wrong profile digest rejected", ["TOP-04-WRONG-PROFILE"]),
        ("SESSION-04", "sessions", "wrong manifest digest rejected", ["TOP-05-WRONG-MANIFEST"]),
        ("SESSION-05", "sessions", "wrong carrier count rejected", ["TOP-06-WRONG-COUNT"]),
        ("SESSION-06", "sessions", "wrong ordinal rejected", ["TOP-07-WRONG-ORDINAL"]),
        ("SESSION-07", "sessions", "wrong raw section rejected", ["TOP-08-WRONG-SECTION"]),
        ("SESSION-08", "sessions", "wrong root rejected", ["TOP-09-WRONG-ROOT"]),
        ("SESSION-09", "sessions", "wrong checkpoint rejected", ["TOP-10-WRONG-CHECKPOINT"]),
        ("SESSION-10", "sessions", "section omission rejected", ["TOP-11-SECTION-OMISSION"]),
        ("SESSION-11", "sessions", "section duplication rejected", ["TOP-12-SECTION-DUPLICATION"]),
        ("SESSION-12", "sessions", "section reorder rejected", ["TOP-13-SECTION-REORDER"]),
        ("SESSION-13", "sessions", "wrong membership leaf rejected", ["TOP-17-MEMBERSHIP-LEAF"]),
        ("SESSION-14", "sessions", "missing anchor rejected", ["TOP-01-MISSING-ANCHOR"]),
        ("SESSION-15", "sessions", "moved anchor rejected", ["TOP-02-MOVED-ANCHOR"]),
        ("SESSION-16", "sessions", "state model recomputes every leaf and root from raw payloads and PAST", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("SESSION-17", "sessions", "each carrier local ordinal leaf membership and same-anchor facts", ["POS-01-DEPOSIT", "POS-02-WITHDRAWAL"]),
        ("SESSION-18", "sessions", "A B C session antecedents validated before splice", ["TOP-16C-CROSS-SPLICE-THREE-BASES"]),
        ("PARSER-01", "parser", "unconsumed wrapper byte rejected", ["TOP-14-TRAILING"]),
        ("PARSER-02", "parser", "section length alias rejected", ["TOP-15-LENGTH-ALIAS"]),
        ("PARSER-03", "parser", "10001-byte element rejected by static contract", ["LIMIT-01-ELEMENT-10001", "LIMIT-03-DECLARED-10001"]),
        ("PARSER-04", "parser", "10001-byte complete wrapper rejected by static contract", ["LIMIT-02-WRAPPER-10001"]),
        ("SPLICE-01", "splices", "one carrier from session B spliced into A", ["TOP-16-CROSS-SPLICE"]),
        ("SPLICE-02", "splices", "two carriers from session B spliced into A", ["TOP-16B-CROSS-SPLICE-TWO"]),
        ("SPLICE-03", "splices", "carrier from independently valid session C spliced into A", ["TOP-16C-CROSS-SPLICE-THREE-BASES"]),
    ]
    if len(rows) != 57:
        raise AssertionError(len(rows))
    return [{
        "familyId": family_id,
        "group": group,
        "materializedCaseIds": case_ids,
        "requirement": requirement,
        "status": "MATERIALIZED_SYNTHETIC" if case_ids else "PLANNED_NOT_MATERIALIZED",
    } for family_id, group, requirement, case_ids in rows]


def build_vectors() -> dict[str, Any]:
    return {
        "classification": "synthetic-offline-non-bch-non-proof",
        "evidenceTier": EVIDENCE_TIER,
        "oracleHashFunction": TEST_HASH,
        "packageId": PACKAGE_ID,
        "positives": [
            {"actionKind": "DEPOSIT", "model": make_model("DEPOSIT"), "vectorId": "deposit"},
            {"actionKind": "WITHDRAWAL", "model": make_model("WITHDRAWAL"), "vectorId": "withdrawal"},
        ],
        "schema": "shieldkit-labs/poolactionfv1-refreeze-falsifier-vectors/v1",
        "spliceAntecedents": [
            {"actionKind": "DEPOSIT", "model": make_model("DEPOSIT", "session-c"), "vectorId": "session-c"},
        ],
        "status": STATUS,
    }


def base_models(vectors: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["vectorId"]: item["model"] for item in vectors["positives"] + vectors["spliceAntecedents"]}


def execute_case(spec: tuple[str, str, str, str, str | None, str], models: dict[str, dict[str, Any]]) -> dict[str, Any]:
    case_id, base_id, mutation_id, expected, expected_code, invariant = spec
    model = copy.deepcopy(models[base_id])
    other_id = "session-c" if mutation_id == "cross_session_splice_c" else ("withdrawal" if base_id == "deposit" else "deposit")
    try:
        # Positive antecedents are checked before any negative mutation. The SUT
        # receives only a model object, never case IDs, expectations, or mutation metadata.
        validate_model(copy.deepcopy(model))
        validate_model(copy.deepcopy(models[other_id]))
        mutate_model(model, mutation_id, copy.deepcopy(models[other_id]))
        validate_model(model)
        actual = "ACCEPT"
        code = None
    except Reject as error:
        actual = "REJECT"
        code = error.code
    if expected_code == "__AUTO_STRICT__":
        # Context mutations are individually pinned in the generated index to the first exact rejection code.
        expected_code = code
    agreement = actual == expected and (expected != "REJECT" or code == expected_code)
    return {
        "actualRejectCode": code,
        "actualVerdict": actual,
        "agreement": agreement,
        "baseVectorId": base_id,
        "caseId": case_id,
        "expectedRejectCode": expected_code,
        "expectedVerdict": expected,
        "invariant": invariant,
        "mutationId": mutation_id,
    }


def binding_record(relative: str) -> dict[str, Any]:
    path = LANE_ROOT / relative
    return file_record(path, relative)


def build_bindings() -> dict[str, Any]:
    disposition_dir = LANE_ROOT / "spec/poolaction-relation-disposition-refreeze-v2"
    disposition = load_json(disposition_dir / "disposition.v2.json")
    if disposition["status"] != STATUS or disposition["relationRefreezeAllowed"] is not False:
        raise RuntimeError("blocked disposition status changed")
    return {
        "blockedDisposition": {
            "disposition": binding_record("spec/poolaction-relation-disposition-refreeze-v2/disposition.v2.json"),
            "manifest": binding_record("spec/poolaction-relation-disposition-refreeze-v2/MANIFEST.json"),
            "packageChecksums": binding_record("spec/poolaction-relation-disposition-refreeze-v2/SHA256SUMS"),
            "relationRefreezeAllowed": False,
            "status": STATUS,
        },
        "contradictionCapsule": {
            "capture": binding_record("evidence/poolactionfv1-contradiction-capture-v1/contradiction-capture.v1.json"),
            "packageChecksums": binding_record("evidence/poolactionfv1-contradiction-capture-v1/SHA256SUMS"),
            "itemCount": 4,
            "materializedFalsifierCountBeforeThisPackage": 0,
        },
        "historicalP0": {
            "aggregateSha256": disposition["p0Freeze"]["aggregate"]["sha256"],
            "artifactCount": disposition["p0Freeze"]["artifactCount"],
            "artifacts": disposition["p0Freeze"]["artifacts"],
            "freezeManifest": disposition["p0Freeze"]["manifest"],
        },
    }


def build_index(vectors: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    models = base_models(vectors)
    outcomes = [execute_case(spec, models) for spec in case_specs()]
    if not all(item["agreement"] for item in outcomes):
        raise RuntimeError("oracle case disagreement during generation")
    cases = [{key: value for key, value in item.items() if key not in {"actualRejectCode", "actualVerdict", "agreement"}} for item in outcomes]
    coverage = [{"caseId": case_id, "fieldClass": field_class, "mutationId": mutation}
                for case_id, mutation, field_class in CONTEXT_CASES]
    accepted = sum(item["expectedVerdict"] == "ACCEPT" for item in cases)
    rejected = len(cases) - accepted
    family_contract = audit_family_contract()
    materialized_families = sum(item["status"] == "MATERIALIZED_SYNTHETIC" for item in family_contract)
    index = {
        "auditMinimumContract": {
            "familyCount": len(family_contract),
            "families": family_contract,
            "groupCounts": {
                group: sum(item["group"] == group for item in family_contract)
                for group in ("positives", "networks", "contextToken", "locks", "sessions", "parser", "splices")
            },
            "materializedFamilyCount": materialized_families,
            "plannedNotMaterializedFamilyCount": len(family_contract) - materialized_families,
            "status": "INCOMPLETE_SYNTHETIC_SUBSET",
        },
        "authority": "none",
        "bindings": build_bindings(),
        "caseSummary": {
            "accepted": accepted,
            "expectedAgreementPercent": 100,
            "rejected": rejected,
            "total": len(cases),
        },
        "cases": cases,
        "contextMutationCoverage": coverage,
        "contract": {
            "carrierAnchorInputIndex": 1,
            "carrierCount": 3,
            "completeConsumptionRequired": True,
            "digestAuthority": "recomputed-complete-introspection-only",
            "fullTransactionExecutionAllowed": False,
            "maxScriptElementBytesStatic": MAX_ELEMENT_BYTES,
            "maxScriptBytesStatic": MAX_SCRIPT_BYTES,
            "maxSectionPayloadBytes": None,
            "maxStandardTransactionBytesLaterQualificationOnly": MAX_TX_BYTES,
            "pastExactBytes": 589,
            "proofSessionRootSelfReferenceAllowed": False,
            "stateInputIndex": 0,
        },
        "evidenceTier": EVIDENCE_TIER,
        "independenceAssessment": {
            "closureInferenceAllowed": False,
            "dualIndependentByteDerivationsPresent": False,
            "expectationsPassedToSut": False,
            "independentDigestAndRootImplementationPresent": False,
            "limitation": "The vector producer and offline SUT share serializer, test-only digest, token, lock-DAG, and proof-session-root helpers; agreement is deterministic regression evidence only.",
            "mutationMetadataPassedToSut": False,
            "positiveAntecedentValidatedBeforeEachMutation": True,
        },
        "openBlockers": [
            "P0-NETWORK-SCHEMA-CODEC-DRIFT",
            "P1-CONTEXT-DIGEST-FACT-INJECTION",
            "P1-CARRIER-LOCK-ANCHOR-ERASURE",
            "P1-PROOF-SESSION-CONTEXT-ERASURE",
        ],
        "oracleHashFunction": TEST_HASH,
        "packageId": PACKAGE_ID,
        "prohibitions": {
            "measurementAdmissionAllowed": False,
            "qualificationAllowed": False,
            "rankingAllowed": False,
            "relationRefreezeAllowed": False,
            "selectionAllowed": False,
        },
        "runtimeClosureMissing": [
            "selected immutable ContextDigest and independently implemented digest oracle",
            "selected proof grammar and canonical commitment checkpoint",
            "concrete reviewed wrapper and push encoding with derived maxSectionPayloadBytes",
            "concrete deployment manifest and locks enforced by BCH covenant bytecode",
            "BCH VM Libauth node network and full-transaction execution evidence",
            "independent review closing all four blocker families and root SOL final-byte review",
        ],
        "schema": "shieldkit-labs/poolactionfv1-refreeze-falsifiers/index/v1",
        "status": STATUS,
        "vectorsRef": VECTORS_FILE,
    }
    return index, outcomes


def validate_artifact_shapes(index: Any, vectors: Any, receipt: Any | None = None) -> None:
    exact_keys(index, {"auditMinimumContract", "authority", "bindings", "caseSummary", "cases", "contextMutationCoverage", "contract", "evidenceTier", "independenceAssessment", "openBlockers", "oracleHashFunction", "packageId", "prohibitions", "runtimeClosureMissing", "schema", "status", "vectorsRef"}, "ARTIFACT_SCHEMA", "index")
    exact_keys(vectors, {"classification", "evidenceTier", "oracleHashFunction", "packageId", "positives", "schema", "spliceAntecedents", "status"}, "ARTIFACT_SCHEMA", "vectors")
    if index["status"] != STATUS or vectors["status"] != STATUS or index["prohibitions"]["relationRefreezeAllowed"] is not False:
        reject("ARTIFACT_SCHEMA", "status/authority boundary")
    if vectors["classification"] != "synthetic-offline-non-bch-non-proof" or len(vectors["positives"]) != 2 or len(vectors["spliceAntecedents"]) != 1:
        reject("ARTIFACT_SCHEMA", "positive vector classification/count")
    expected_case_keys = {"baseVectorId", "caseId", "expectedRejectCode", "expectedVerdict", "invariant", "mutationId"}
    for item in index["cases"]:
        exact_keys(item, expected_case_keys, "ARTIFACT_SCHEMA", "case")
    if receipt is not None:
        exact_keys(receipt, {"agreementPercent", "authority", "caseCount", "closureClaimed", "evidenceTier", "execution", "inputs", "materializedSubsetOnly", "oracleOutcomeDigest", "packageId", "rejectedAsExpected", "relationRefreezeAllowed", "schema", "staticAgreementScope", "status", "unexpected", "unresolvedBlockerCount", "validatedAsExpected"}, "ARTIFACT_SCHEMA", "receipt")


def run_from_artifacts(index: dict[str, Any], vectors: dict[str, Any]) -> list[dict[str, Any]]:
    specs = [(item["caseId"], item["baseVectorId"], item["mutationId"], item["expectedVerdict"], item["expectedRejectCode"], item["invariant"])
             for item in index["cases"]]
    if [item[0] for item in specs] != [item[0] for item in case_specs()]:
        reject("ARTIFACT_SCHEMA", "case order/set differs from closed oracle allowlist")
    allowed = {(item[0], item[1], item[2]) for item in case_specs()}
    if any((item[0], item[1], item[2]) not in allowed for item in specs):
        reject("UNLISTED_MUTATION", "index contains unlisted mutation")
    return [execute_case(spec, base_models(vectors)) for spec in specs]


def build_receipt(index: dict[str, Any], vectors: dict[str, Any], outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    unexpected = [item["caseId"] for item in outcomes if not item["agreement"]]
    validated = sum(item["actualVerdict"] == "ACCEPT" and item["agreement"] for item in outcomes)
    rejected = sum(item["actualVerdict"] == "REJECT" and item["agreement"] for item in outcomes)
    digest_rows = [{"actualRejectCode": item["actualRejectCode"], "actualVerdict": item["actualVerdict"], "caseId": item["caseId"]} for item in outcomes]
    return {
        "agreementPercent": 100 if not unexpected else round(100 * (len(outcomes) - len(unexpected)) / len(outcomes), 8),
        "authority": "none",
        "caseCount": len(outcomes),
        "closureClaimed": False,
        "evidenceTier": EVIDENCE_TIER,
        "execution": {
            "bch": False,
            "command": "python3 oracle.py check",
            "libauth": False,
            "network": False,
            "node": False,
            "proof": False,
            "pythonStdlibOnly": True,
            "vm": False,
        },
        "inputs": {
            "index": {"bytes": len(canonical_json_bytes(index)), "rawSha256": sha256_bytes(canonical_json_bytes(index))},
            "oracle": file_record(HERE / ORACLE_FILE),
            "vectors": {"bytes": len(canonical_json_bytes(vectors)), "rawSha256": sha256_bytes(canonical_json_bytes(vectors))},
        },
        "materializedSubsetOnly": True,
        "oracleOutcomeDigest": sha256_bytes(compact_json_bytes(digest_rows)),
        "packageId": PACKAGE_ID,
        "rejectedAsExpected": rejected,
        "relationRefreezeAllowed": False,
        "schema": "shieldkit-labs/poolactionfv1-refreeze-falsifiers/receipt/v1",
        "staticAgreementScope": "Only the materialized synthetic offline rows in index.v1.json; not the complete 57-family audit contract and not BCH/runtime closure.",
        "status": STATUS,
        "unexpected": unexpected,
        "unresolvedBlockerCount": 4,
        "validatedAsExpected": validated,
    }


def verify_bindings(index: dict[str, Any]) -> None:
    bindings = index["bindings"]
    records = []
    records.extend(bindings["blockedDisposition"][key] for key in ("disposition", "manifest", "packageChecksums"))
    records.extend(bindings["contradictionCapsule"][key] for key in ("capture", "packageChecksums"))
    records.append(bindings["historicalP0"]["freezeManifest"])
    records.extend(bindings["historicalP0"]["artifacts"])
    for record in records:
        path = LANE_ROOT / record["path"]
        actual = file_record(path, record["path"])
        expected = {"bytes": record["bytes"], "path": record["path"], "rawSha256": record.get("rawSha256", record.get("sha256"))}
        if actual != expected:
            reject("BINDING_DRIFT", f"binding drift: {record['path']}")
    p0 = bindings["historicalP0"]
    rows = sorted(p0["artifacts"], key=lambda item: item["path"])
    preimage = b"".join(item["path"].encode() + b"\0" + item["rawSha256"].encode() + b"\n" for item in rows)
    if sha256_bytes(preimage) != p0["aggregateSha256"]:
        reject("BINDING_DRIFT", "P0 aggregate")


def seal() -> None:
    for name in NON_ENVELOPE_FILES:
        if not (HERE / name).is_file():
            raise RuntimeError(f"missing {name}")
    records = [file_record(HERE / name) for name in sorted(NON_ENVELOPE_FILES)]
    content_preimage = b"".join(item["path"].encode() + b"\0" + item["rawSha256"].encode() + b"\n" for item in records)
    manifest = {
        "contentAggregate": {"algorithm": "sha256", "sha256": sha256_bytes(content_preimage)},
        "envelopeRule": "MANIFEST inventories all eight non-envelope files; SHA256SUMS covers those files plus MANIFEST and excludes itself.",
        "fileCount": len(records),
        "files": records,
        "packageId": PACKAGE_ID,
        "schema": "shieldkit-labs/sealed-evidence-manifest/v1",
        "status": STATUS,
    }
    write_json(HERE / MANIFEST_FILE, manifest)
    sums_records = records + [file_record(HERE / MANIFEST_FILE)]
    (HERE / SUMS_FILE).write_text("".join(f"{item['rawSha256']}  {item['path']}\n" for item in sorted(sums_records, key=lambda item: item["path"])))


def verify_envelope() -> None:
    expected_names = set(NON_ENVELOPE_FILES) | {MANIFEST_FILE, SUMS_FILE}
    actual_names = {path.name for path in HERE.iterdir()}
    if actual_names != expected_names:
        reject("ENVELOPE", f"unexpected package entries: {sorted(actual_names ^ expected_names)}")
    for name in expected_names:
        path = HERE / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink():
            reject("ENVELOPE", f"non-regular or linked file: {name}")
        if hasattr(os, "listxattr") and os.listxattr(path):
            reject("ENVELOPE", f"xattrs present: {name}")
    manifest = load_json(HERE / MANIFEST_FILE)
    records = [file_record(HERE / name) for name in sorted(NON_ENVELOPE_FILES)]
    if manifest["files"] != records or manifest["fileCount"] != len(records):
        reject("ENVELOPE", "manifest inventory")
    preimage = b"".join(item["path"].encode() + b"\0" + item["rawSha256"].encode() + b"\n" for item in records)
    if manifest["contentAggregate"]["sha256"] != sha256_bytes(preimage):
        reject("ENVELOPE", "content aggregate")
    expected_sums = records + [file_record(HERE / MANIFEST_FILE)]
    sums = (HERE / SUMS_FILE).read_text()
    expected_text = "".join(f"{item['rawSha256']}  {item['path']}\n" for item in sorted(expected_sums, key=lambda item: item["path"]))
    if sums != expected_text:
        reject("ENVELOPE", "SHA256SUMS")


def emit() -> None:
    vectors = build_vectors()
    index, outcomes = build_index(vectors)
    validate_artifact_shapes(index, vectors)
    write_json(HERE / VECTORS_FILE, vectors)
    write_json(HERE / INDEX_FILE, index)
    outcomes = run_from_artifacts(index, vectors)
    receipt = build_receipt(index, vectors, outcomes)
    validate_artifact_shapes(index, vectors, receipt)
    write_json(HERE / RECEIPT_FILE, receipt)


def check(require_envelope: bool = True) -> dict[str, Any]:
    index = load_json(HERE / INDEX_FILE)
    vectors = load_json(HERE / VECTORS_FILE)
    receipt = load_json(HERE / RECEIPT_FILE)
    validate_artifact_shapes(index, vectors, receipt)
    if canonical_json_bytes(index) != (HERE / INDEX_FILE).read_bytes() or canonical_json_bytes(vectors) != (HERE / VECTORS_FILE).read_bytes() or canonical_json_bytes(receipt) != (HERE / RECEIPT_FILE).read_bytes():
        reject("ARTIFACT_SCHEMA", "JSON is not sorted canonical two-space form")
    verify_bindings(index)
    outcomes = run_from_artifacts(index, vectors)
    expected_receipt = build_receipt(index, vectors, outcomes)
    if receipt != expected_receipt:
        reject("RECEIPT_DRIFT", "receipt differs from deterministic rerun")
    if receipt["agreementPercent"] != 100 or receipt["unexpected"]:
        reject("CASE_DISAGREEMENT", "oracle agreement below 100 percent")
    if require_envelope:
        verify_envelope()
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("emit", "seal", "check"))
    args = parser.parse_args()
    try:
        if args.action == "emit":
            emit()
            print("EMIT_OK")
        elif args.action == "seal":
            check(require_envelope=False)
            seal()
            print("SEAL_OK")
        else:
            receipt = check(require_envelope=True)
            print(json.dumps({
                "agreementPercent": receipt["agreementPercent"],
                "caseCount": receipt["caseCount"],
                "rejectedAsExpected": receipt["rejectedAsExpected"],
                "status": receipt["status"],
                "validatedAsExpected": receipt["validatedAsExpected"],
            }, sort_keys=True))
        return 0
    except (Reject, RuntimeError, AssertionError, KeyError, ValueError, OSError) as error:
        code = error.code if isinstance(error, Reject) else type(error).__name__
        print(f"{code}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
