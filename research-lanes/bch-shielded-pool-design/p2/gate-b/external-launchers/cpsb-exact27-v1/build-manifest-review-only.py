#!/usr/bin/python3
"""Review-time manifest builder; never used by launch.sh or verify-copy.py.

This convenience script is not a trust root.  A reviewer must independently
hold and literal-pin the generated trust-manifest.v1.json before launch.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


REPO = Path(__file__).resolve().parents[6]
OUT = Path(__file__).resolve().parent / "trust-manifest.v1.json"
NODE = Path("/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node")
GATE_B = "research-lanes/bch-shielded-pool-design/p2/gate-b"
CPSB = f"{GATE_B}/gate-b0-external-authority-control-plane-schema-bridge-v1"
EAPP = f"{GATE_B}/gate-b0-external-authority-prerequisite-policy-v1"
SSA = f"{GATE_B}/gate-b0-static-source-authority-v1"
EAPP_ANCHOR = f"{GATE_B}/gate-b0-external-authority-prerequisite-policy-review-anchor.v1.json"
SSA_ANCHOR = f"{GATE_B}/gate-b0-static-source-authority-review-anchor.v1.json"
SSA_ROOT = f"{SSA}/static-source-authority-root.v1.json"
DIRECT_ROOTS = [
    f"{GATE_B}/cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json",
    f"{GATE_B}/cohort-upstream-provider-source-map-v1/upstream-provider-source-map-root.v1.json",
    f"{GATE_B}/gate-b0-evidence-plan-v1/evidence-plan-root.v1.json",
    f"{GATE_B}/gate-b0-execution-admission-contract-v1/execution-admission-contract-root.v1.json",
]
SSA_TRANSITIVE_DIRECT_ROOTS = {
    f"{GATE_B}/cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json",
    f"{GATE_B}/cohort-upstream-provider-source-map-v1/upstream-provider-source-map-root.v1.json",
    f"{GATE_B}/gate-b0-evidence-plan-v1/evidence-plan-root.v1.json",
}
RUNTIME_PREFIXES = [
    "node_modules/ajv",
    "node_modules/fast-deep-equal",
    "node_modules/fast-uri",
    "node_modules/json-schema-traverse",
    "node_modules/require-from-string",
]


def files_under(relative: str) -> list[str]:
    root = REPO / relative
    return sorted(str(path.relative_to(REPO)) for path in root.rglob("*") if path.is_file())


def row(
    group: str,
    root: str,
    locator: str,
    destination: str,
    *,
    expected_bytes: int | None = None,
    expected_hash: str | None = None,
) -> dict[str, object]:
    path = NODE if root == "node" else REPO / locator
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError(f"unsafe source: {path}")
    data = path.read_bytes()
    actual_hash = hashlib.sha256(data).hexdigest()
    if expected_bytes is not None and len(data) != expected_bytes:
        raise RuntimeError(f"SSA pin byte mismatch: {locator}")
    if expected_hash is not None and actual_hash != expected_hash:
        raise RuntimeError(f"SSA pin hash mismatch: {locator}")
    return {
        "group": group,
        "root": root,
        "locator": locator,
        "destination": destination,
        "bytes": len(data),
        "rawSha256": actual_hash,
        "sourceMode": f"{stat.S_IMODE(info.st_mode):04o}",
        "snapshotMode": "0755" if root == "node" else "0644",
    }


def package_rows(group: str, package: str) -> list[dict[str, object]]:
    return [row(group, "repo", locator, f"repo/{locator}") for locator in files_under(package)]


rows = []
rows.extend(package_rows("cpsb-authored", CPSB))
rows.extend(package_rows("eapp-authored", EAPP))
rows.append(row("eapp-anchor", "repo", EAPP_ANCHOR, f"repo/{EAPP_ANCHOR}"))
rows.extend(package_rows("ssa-authored", SSA))
rows.append(row("ssa-anchor", "repo", SSA_ANCHOR, f"repo/{SSA_ANCHOR}"))
rows.extend(row("direct-roots", "repo", locator, f"repo/{locator}") for locator in DIRECT_ROOTS)

ssa_root = json.loads((REPO / SSA_ROOT).read_text(encoding="utf-8"))
ssa_pins = ssa_root["transitiveSourcePins"]
if len(ssa_pins) != 64 or len({pin["locator"] for pin in ssa_pins}) != 64:
    raise RuntimeError("unexpected SSA transitive pin roster")
if {pin["locator"] for pin in ssa_pins} & set(DIRECT_ROOTS) != SSA_TRANSITIVE_DIRECT_ROOTS:
    raise RuntimeError("unexpected SSA/direct-root overlap")
ssa_transitive_only = [
    pin for pin in ssa_pins if pin["locator"] not in SSA_TRANSITIVE_DIRECT_ROOTS
]
rows.extend(
    row(
        "ssa-transitive-only",
        "repo",
        pin["locator"],
        f"repo/{pin['locator']}",
        expected_bytes=pin["bytes"],
        expected_hash=pin["rawSha256"],
    )
    for pin in ssa_transitive_only
)
rows.extend(row("repo-metadata", "repo", locator, f"repo/{locator}") for locator in ["package-lock.json", "package.json"])
for prefix in RUNTIME_PREFIXES:
    rows.extend(row("ajv-runtime", "repo", locator, f"repo/{locator}") for locator in files_under(prefix))
rows.append(row("node-binary", "node", "node", "runtime/node"))
rows.sort(key=lambda item: (item["group"], item["root"], item["locator"]))

group_counts: dict[str, int] = {}
group_bytes: dict[str, int] = {}
for item in rows:
    group_counts[item["group"]] = group_counts.get(item["group"], 0) + 1
    group_bytes[item["group"]] = group_bytes.get(item["group"], 0) + item["bytes"]

closure_groups = [
    {"group": "ajv-runtime", "root": "repo", "prefixes": RUNTIME_PREFIXES, "exactFiles": []},
    {"group": "cpsb-authored", "root": "repo", "prefixes": [CPSB], "exactFiles": []},
    {"group": "direct-roots", "root": "repo", "prefixes": [], "exactFiles": sorted(DIRECT_ROOTS)},
    {"group": "eapp-anchor", "root": "repo", "prefixes": [], "exactFiles": [EAPP_ANCHOR]},
    {"group": "eapp-authored", "root": "repo", "prefixes": [EAPP], "exactFiles": []},
    {"group": "node-binary", "root": "node", "prefixes": [], "exactFiles": ["node"]},
    {"group": "repo-metadata", "root": "repo", "prefixes": [], "exactFiles": ["package-lock.json", "package.json"]},
    {"group": "ssa-anchor", "root": "repo", "prefixes": [], "exactFiles": [SSA_ANCHOR]},
    {"group": "ssa-authored", "root": "repo", "prefixes": [SSA], "exactFiles": []},
    {"group": "ssa-transitive-only", "root": "repo", "prefixes": [], "exactFiles": sorted(pin["locator"] for pin in ssa_transitive_only)},
]

manifest = {
    "schema": "shieldkit-labs/external-launcher/cpsb-exact27/v1",
    "launcherId": "cpsb-exact27-v1",
    "authorization": "NONE",
    "mode": "unsealed",
    "entryCount": len(rows),
    "totalBytes": sum(item["bytes"] for item in rows),
    "groupCounts": group_counts,
    "groupBytes": group_bytes,
    "closureGroups": closure_groups,
    "snapshotPolicy": {
        "snapshotRootMode": "BWRAP_PRIVATE_NAMESPACE_ROOT_REMOUNT_RO_NONRECURSIVE_TMP_WRITABLE",
        "repoFileMode": "0644",
        "repoDirectoryMode": "0755",
        "nodeMode": "0755",
        "immutability": "SEALED_MEMFD_THEN_BWRAP_FILE_COPY_THEN_ROOT_REMOUNT_RO",
    },
    "hostTcb": {
        "python": {"required": True, "role": "literal stage0, manifest parsing, nofollow source authentication, sealed-memfd capture, bwrap orchestration", "expectedInterpreter": "/usr/bin/python3.14", "versionObserved": "3.14.6", "bytesObserved": 14424, "rawSha256Observed": "2700be1aabe3687bd597f21b0eac3b9bbdf7417e93035255a9286c67935b59bd", "requiredFlags": ["-I", "-S", "-B", "-c", "REVIEWED_LITERAL"]},
        "bubblewrap": {"requiredForValidation": True, "role": "copy 673 sealed memfds with --file into private namespace regular nlink1 files, then apply one terminal nonrecursive root read-only remount; nested private /tmp remains writable; mount/user/network namespace isolation; no upward Node module fallback", "fileMaterialization": {"source": "673 sealed memfd descriptors", "operation": "--file", "result": "private namespace regular nlink1 files", "fileCount": 673, "terminalRootRemount": ["--remount-ro", "/"], "rootRemountRecursive": False, "privateTmpRemainsWritable": True}, "expectedExecutable": "/usr/bin/bwrap", "versionObserved": "0.11.2", "bytesObserved": 84464, "rawSha256Observed": "6ad2138a73d592acb43525432965e3c66f6fad8a2f3d610c6ca0b6855e993cbe", "runtimeAuthenticated": False, "dumpableBehaviorForReviewedVersion": "PR_SET_DUMPABLE_IS_SET_TO_1_DURING_UNPRIVILEGED_SETUP", "noFallback": True},
        "literalStage0": {"trusted": True, "role": "caller provenance and reviewed-byte delivery are external TCB assertions; runtime only hashes the actual Python -c bytes from /proc/self/cmdline and matches caller-supplied pins"},
        "sourceFiles": {"trustedUntilCaptured": True, "role": "component-wise nofollow regular nlink1 exact mode/size/hash/stable-identity reads; all xattrs rejected; each payload sealed and rehashed in a memfd"},
        "kernel": {"trusted": True, "observed": "Linux 7.1.4-arch1-1 x86_64"},
        "libcAndDynamicLoader": {"trusted": True, "observed": "glibc 2.43; /lib64/ld-linux-x86-64.so.2 and Node shared libraries mounted read-only by bwrap"},
        "hardware": {"trusted": True, "observed": "x86_64; 13th Gen Intel Core i9-13900H; microcode 0x6134"},
        "filesystemAndStorage": {"trustedUntilMemfdCapture": True, "role": "source bytes and metadata; no project-data disk snapshot is created"},
        "reviewerPins": {"trusted": True, "role": "external trust-root inputs supplied in the same invocation; stage0 checks internal consistency against actual command-line/helper/manifest bytes but does not prove reviewer provenance"},
        "sameUidBoundary": {"stage0PrSetDumpable": {"requestedAndChecked": 0, "scope": "STAGE0_BEFORE_BWRAP_EXEC_ONLY"}, "bubblewrapReviewedVersionBehavior": "PR_SET_DUMPABLE_IS_SET_TO_1_DURING_UNPRIVILEGED_SETUP", "activeSameUidPtraceOrProcessInjectionAfterBubblewrapStarts": "OUT_OF_PROOF", "yamaPtraceScope": {"observed": 1, "runtimeAuthenticated": False, "protectionClaim": "NONE"}, "role": "caller/interpreter/kernel/loader and privileged host remain TCB; external execution controls must exclude active ptrace or process injection after bubblewrap starts"},
    },
    "rows": rows,
}

encoded = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
if len(rows) != 673 or sum(item["bytes"] for item in rows) != 174467070 or group_counts != {
    "ajv-runtime": 527,
    "cpsb-authored": 27,
    "direct-roots": 4,
    "eapp-anchor": 1,
    "eapp-authored": 23,
    "node-binary": 1,
    "repo-metadata": 2,
    "ssa-anchor": 1,
    "ssa-authored": 26,
    "ssa-transitive-only": 61,
}:
    raise RuntimeError(f"unexpected closure: {len(rows)} {group_counts}")
OUT.write_bytes(encoded)
os.chmod(OUT, 0o644)
print(f"{len(encoded)} {hashlib.sha256(encoded).hexdigest()} {OUT}")
