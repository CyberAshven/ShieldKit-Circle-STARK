#!/usr/bin/python3
"""Review-time CPSB seal and exact-676 manifest builder.

This non-importing convenience script never participates in launch.  It reads
raw files only, executes no CPSB JavaScript or launcher source, derives all four
outputs in memory, compares them to literal review pins, then materializes only
the two package-envelope files, outside review anchor, and launcher manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


REPO = Path(__file__).resolve().parents[6]
LAUNCHER = Path(__file__).resolve().parent
NODE = Path("/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node")
GATE_B = "research-lanes/bch-shielded-pool-design/p2/gate-b"
CPSB = f"{GATE_B}/gate-b0-external-authority-control-plane-schema-bridge-v1"
CPSB_ANCHOR = (
    f"{GATE_B}/"
    "gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json"
)
EAPP = f"{GATE_B}/gate-b0-external-authority-prerequisite-policy-v1"
SSA = f"{GATE_B}/gate-b0-static-source-authority-v1"
EAPP_ANCHOR = f"{GATE_B}/gate-b0-external-authority-prerequisite-policy-review-anchor.v1.json"
SSA_ANCHOR = f"{GATE_B}/gate-b0-static-source-authority-review-anchor.v1.json"
SSA_ROOT = f"{SSA}/static-source-authority-root.v1.json"
PREFIX = (
    "shieldkit-labs/p2/gate-b/"
    "gate-b0-external-authority-control-plane-schema-bridge/v1"
)
SCHEMA_PREFIX = (
    "https://shieldkit-labs.local/p2/gate-b/"
    "gate-b0-external-authority-control-plane-schema-bridge/v1/"
)
CPSB_AUTHORED = (
    "COMMAND.txt",
    "README.md",
    "external-authority-control-plane-schema-bridge-root.v1.json",
    "schemas/artifact-dependency-dag.v1.schema.json",
    "schemas/b0-execution-authorization.v1.schema.json",
    "schemas/binding-creation-authorization-g0.v1.schema.json",
    "schemas/control-plane-transition.v2.schema.json",
    "schemas/dependency-binding.v1.schema.json",
    "schemas/digest.v1.schema.json",
    "schemas/external-authority-contract.v2.schema.json",
    "schemas/governance-authorization-g1.v1.schema.json",
    "schemas/instance-creation-event.v1.schema.json",
    "schemas/issuer-decision.v1.schema.json",
    "schemas/manifest.v1.schema.json",
    "schemas/non-authority-boundary.v1.schema.json",
    "schemas/principal-identity-ref.v1.schema.json",
    "schemas/provider-binding-catalog.v1.schema.json",
    "schemas/provider-binding.v2.schema.json",
    "schemas/provider-contract.v1.schema.json",
    "schemas/root.v1.schema.json",
    "schemas/source-collision-decision.v2.schema.json",
    "test/digest.kat.json",
    "test/future-schema.test.mjs",
    "test/mutation.test.mjs",
    "test/package-boundary.test.mjs",
    "test/static.test.mjs",
    "validate-static.mjs",
)
CPSB_SOURCE_PINS = {
    "COMMAND.txt": (2051, "cac82d8b0971821d45f9f161cd51b73b63bcdef1968a0b1016b211167baaf580"),
    "README.md": (3517, "99068df375d07cb35dde8dd660c15339ec19d9d2545ba3771e3290dd59f5c1f0"),
    "external-authority-control-plane-schema-bridge-root.v1.json": (50052, "89c281e916790e5d488f554fdf508af80cc7c3e0b8d9a2b99f62707c150a17e4"),
    "schemas/artifact-dependency-dag.v1.schema.json": (21533, "2090fcd12b4f3a7f34cd8f73245343d1cf76918c0a6fdf8938ae87d0a9662858"),
    "schemas/b0-execution-authorization.v1.schema.json": (7895, "1584359e4bc1b355bfd94a0f7985d88538a0cba086f08d0b920184dba4693725"),
    "schemas/binding-creation-authorization-g0.v1.schema.json": (6249, "b05083c08e1417ffcbbd98da02b9245036e9ea0febfdbcc6b69ec86c2d109e71"),
    "schemas/control-plane-transition.v2.schema.json": (4625, "353b2eb0de0384d3f548b2f3db64c71ca1a5a55b6edd936dd0c4b44fea9ffea5"),
    "schemas/dependency-binding.v1.schema.json": (8440, "d70f6701b004200b7a5225503a6ae06ef7bf59489fc8cc1f8512df2ac2cf9172"),
    "schemas/digest.v1.schema.json": (1367, "49d40ad69d2382b45c2e5dbf38459eabc049bda94dd29b4df81016fa961de191"),
    "schemas/external-authority-contract.v2.schema.json": (13652, "aa9bf1d7f7c1bbd39fc9b32226bceb66efdc1f008546a2081869ef237feb46e3"),
    "schemas/governance-authorization-g1.v1.schema.json": (6365, "c6a25bcd2ff90f1a9aded54d0e784b4d7a77491c39913a7c7a6b7dcd8e8f913e"),
    "schemas/instance-creation-event.v1.schema.json": (4593, "c1a6583b16b4207b65ebe337188e21a3252afcde8aa9fd5fe761052529560059"),
    "schemas/issuer-decision.v1.schema.json": (3923, "d31d5c9323ea343a0a8103f7b3889b79e115f055f4e6c6c34fd7ea6b66b58f8f"),
    "schemas/manifest.v1.schema.json": (6946, "65d0c3cdd11f0d11276b41de2dd1bf4e2cb664deb9160d80f87775df3ce48426"),
    "schemas/non-authority-boundary.v1.schema.json": (7148, "95fab26ded9515ff1ab5820a502b6b9a982dfb66a6aaed00ce1b9ea6670bda6c"),
    "schemas/principal-identity-ref.v1.schema.json": (6896, "74865f0ff5d5a1bd76fc224fbb70daf4768dd42e0080ce98c2e9cf49858a8790"),
    "schemas/provider-binding-catalog.v1.schema.json": (9013, "1c4be4de786bcfc755fb0d50a7c0e6f161eb6b75f509273991502348089cca6d"),
    "schemas/provider-binding.v2.schema.json": (9585, "8cad8bb6ceb82479f1306fb575d62617fd97204435e79694d3d424928ce090fe"),
    "schemas/provider-contract.v1.schema.json": (4832, "67e65032013472d1330a38a5181e894272c5c8d682aa56bc8d60c439f4ea3ba9"),
    "schemas/root.v1.schema.json": (25318, "68041047821a9c0c778933d3e50e148c4604debd5da23e21888021a02afb725c"),
    "schemas/source-collision-decision.v2.schema.json": (5682, "3dec351d74091527d1b8ee9aac07f41c7f636b626c090b98e68d23832d0e2a92"),
    "test/digest.kat.json": (8661, "2856d0c5fdf91d53021d32e8a2273df88e6532d52f3c85010e8f5d44ba529e11"),
    "test/future-schema.test.mjs": (41286, "7a063f288b2c4bc00a2c423e708dc0aa6bdf811637ab8fc7fcc9436802995681"),
    "test/mutation.test.mjs": (58908, "ecaa0047bcb04de8040f41f7084e83982c4e999534f1e0ff921ae067896c4ff1"),
    "test/package-boundary.test.mjs": (10603, "e798046d20c3b39d8fec27d103d6ee36c9b59dbb12f1b6f6543ef2eb9b0982ac"),
    "test/static.test.mjs": (10475, "9087aed03dcd8ba22336ee12b8040738e1a4ad675ddce9cd92a7f9875c7c2fec"),
    "validate-static.mjs": (438375, "65727edaa77d783dd0db33f70f57856240f7c732b7156fa8c76785aadf94546c"),
}
DIRECT_ROOTS = (
    f"{GATE_B}/cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json",
    f"{GATE_B}/cohort-upstream-provider-source-map-v1/upstream-provider-source-map-root.v1.json",
    f"{GATE_B}/gate-b0-evidence-plan-v1/evidence-plan-root.v1.json",
    f"{GATE_B}/gate-b0-execution-admission-contract-v1/execution-admission-contract-root.v1.json",
)
SSA_TRANSITIVE_DIRECT_ROOTS = set(DIRECT_ROOTS[:3])
RUNTIME_PREFIXES = (
    "node_modules/ajv",
    "node_modules/fast-deep-equal",
    "node_modules/fast-uri",
    "node_modules/json-schema-traverse",
    "node_modules/require-from-string",
)
EXPECTED_OUTPUTS = {
    "MANIFEST.json": (13498, "cb7eb8a3dd6691d325fa1c0479b71a0fa0748649fef238c10e78cc0bbe7dc5c0"),
    "SHA256SUMS": (2880, "95751ed2534f16ce73eb13d18bdf9dd7b11334bc7751ed15b830a95786c85428"),
    "anchor": (32442, "42f2b1eaf7d4834f4c07248da74981f40fccb71a4e633afb29bffefab4d5b868"),
    "trust-manifest.v1.json": (243425, "12e80d243e86f6290a08c92ac1d9f92edada9509cec03ed044d99317f60186fa"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def digest_record(domain: str, value: object) -> dict[str, object]:
    return {
        "algorithm": "sha256",
        "canonicalization": (
            "recursive-lexicographic-object-key-sort-arrays-preserve-order-"
            "json-utf8-lf-v1"
        ),
        "domain": domain,
        "frame": "utf8(domain)||0x00||canonical-json-utf8||0x0a",
        "value": sha256(domain.encode() + b"\x00" + canonical(value)),
    }


def file_digest(locator: str, data: bytes) -> dict[str, object]:
    domain = f"{PREFIX}/file/{locator}"
    return {
        "algorithm": "sha256",
        "canonicalization": "raw-file-bytes-v1",
        "domain": domain,
        "frame": "utf8(domain)||0x00||raw-file-bytes",
        "value": sha256(domain.encode() + b"\x00" + data),
    }


def files_under(relative: str) -> list[str]:
    root = REPO / relative
    return sorted(path.relative_to(REPO).as_posix() for path in root.rglob("*") if path.is_file())


def raw_row(group: str, root: str, locator: str, destination: str) -> dict[str, object]:
    path = NODE if root == "node" else REPO / locator
    info = path.lstat()
    data = path.read_bytes()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError(f"unsafe source: {path}")
    return {
        "group": group,
        "root": root,
        "locator": locator,
        "destination": destination,
        "bytes": len(data),
        "rawSha256": sha256(data),
        "sourceMode": f"{stat.S_IMODE(info.st_mode):04o}",
        "snapshotMode": "0755" if root == "node" else "0644",
    }


def prospective_row(group: str, locator: str, data: bytes) -> dict[str, object]:
    return {
        "group": group,
        "root": "repo",
        "locator": locator,
        "destination": f"repo/{locator}",
        "bytes": len(data),
        "rawSha256": sha256(data),
        "sourceMode": "0644",
        "snapshotMode": "0644",
    }


def package_rows(group: str, package: str) -> list[dict[str, object]]:
    return [raw_row(group, "repo", locator, f"repo/{locator}") for locator in files_under(package)]


def check_output(name: str, data: bytes) -> None:
    if (len(data), sha256(data)) != EXPECTED_OUTPUTS[name]:
        raise RuntimeError(f"review pin mismatch: {name}")


# Freeze the exact 27 source leaves before deriving any output.
source_bytes: dict[str, bytes] = {}
for locator in CPSB_AUTHORED:
    path = REPO / CPSB / locator
    info = path.lstat()
    data = path.read_bytes()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o644
        or (len(data), sha256(data)) != CPSB_SOURCE_PINS[locator]
    ):
        raise RuntimeError(f"CPSB source drift: {locator}")
    source_bytes[locator] = data

entries = [
    {
        "bytes": len(source_bytes[locator]),
        "fileDigest": file_digest(locator, source_bytes[locator]),
        "locator": locator,
        "rawSha256": sha256(source_bytes[locator]),
    }
    for locator in CPSB_AUTHORED
]
roster_digest = digest_record(f"{PREFIX}/manifest-roster", entries)
package_manifest = {
    "schema": f"{SCHEMA_PREFIX}manifest.v1.schema.json",
    "format": "shieldkit-static-manifest-v1",
    "packageId": "gate-b0-external-authority-control-plane-schema-bridge-v1",
    "entryCount": 27,
    "entries": entries,
    "rosterDigest": roster_digest,
}
manifest_bytes = canonical(package_manifest)
sums_bytes = (
    "".join(f"{item['rawSha256']}  {item['locator']}\n" for item in entries)
    + f"{sha256(manifest_bytes)}  MANIFEST.json\n"
).encode()
root = json.loads(source_bytes["external-authority-control-plane-schema-bridge-root.v1.json"])
eapp_digest = next(
    item["digest"]
    for item in root["componentDigests"]
    if item["component"] == "eappV1Disposition"
)
anchor = {
    "schema": f"{PREFIX}/external-review-anchor/v1",
    "artifactId": (
        "artifact:gate-b:gate-b0-external-authority-control-plane-"
        "schema-bridge-review-anchor-v1"
    ),
    "packageId": "gate-b0-external-authority-control-plane-schema-bridge-v1",
    "status": (
        "sealed-static-control-plane-schema-bridge-review-anchor-no-principals-"
        "no-decisions-no-contracts-no-bindings-no-authorizations-no-instances-"
        "no-admission-no-execution-unqualified"
    ),
    "package": CPSB,
    "rootRawSha256": CPSB_SOURCE_PINS[
        "external-authority-control-plane-schema-bridge-root.v1.json"
    ][1],
    "rootContentDigest": root["contentDigest"],
    "validatorRawSha256": CPSB_SOURCE_PINS["validate-static.mjs"][1],
    "entryCount": 27,
    "rosterDigest": roster_digest,
    "manifestRawSha256": sha256(manifest_bytes),
    "sha256SumsRawSha256": sha256(sums_bytes),
    "schemaBindingTableDigest": digest_record(
        f"{PREFIX}/schema-bindings", root["schemaBindings"]
    ),
    "schemaBindings": root["schemaBindings"],
    "componentDigests": root["componentDigests"],
    "directDependencyBinding": root["dependencyBinding"],
    "eappV1DispositionDigest": eapp_digest,
    "nonAuthorityBoundary": root["nonAuthorityBoundary"],
    "orderedClosure": entries,
}
anchor_bytes = canonical(anchor)
check_output("MANIFEST.json", manifest_bytes)
check_output("SHA256SUMS", sums_bytes)
check_output("anchor", anchor_bytes)

rows: list[dict[str, object]] = []
rows.extend(
    prospective_row("cpsb-authored", f"{CPSB}/{locator}", source_bytes[locator])
    for locator in CPSB_AUTHORED
)
rows.extend(
    [
        prospective_row("cpsb-envelope", f"{CPSB}/MANIFEST.json", manifest_bytes),
        prospective_row("cpsb-envelope", f"{CPSB}/SHA256SUMS", sums_bytes),
        prospective_row("cpsb-anchor", CPSB_ANCHOR, anchor_bytes),
    ]
)
rows.extend(package_rows("eapp-authored", EAPP))
rows.append(raw_row("eapp-anchor", "repo", EAPP_ANCHOR, f"repo/{EAPP_ANCHOR}"))
rows.extend(package_rows("ssa-authored", SSA))
rows.append(raw_row("ssa-anchor", "repo", SSA_ANCHOR, f"repo/{SSA_ANCHOR}"))
rows.extend(raw_row("direct-roots", "repo", locator, f"repo/{locator}") for locator in DIRECT_ROOTS)
ssa = json.loads((REPO / SSA_ROOT).read_text(encoding="utf-8"))
ssa_pins = ssa["transitiveSourcePins"]
if len(ssa_pins) != 64 or len({item["locator"] for item in ssa_pins}) != 64:
    raise RuntimeError("unexpected SSA transitive roster")
if {item["locator"] for item in ssa_pins} & set(DIRECT_ROOTS) != SSA_TRANSITIVE_DIRECT_ROOTS:
    raise RuntimeError("unexpected SSA/direct overlap")
ssa_transitive_only = [
    item for item in ssa_pins if item["locator"] not in SSA_TRANSITIVE_DIRECT_ROOTS
]
for item in ssa_transitive_only:
    row = raw_row(
        "ssa-transitive-only", "repo", item["locator"], f"repo/{item['locator']}"
    )
    if (row["bytes"], row["rawSha256"]) != (item["bytes"], item["rawSha256"]):
        raise RuntimeError(f"SSA pin mismatch: {item['locator']}")
    rows.append(row)
rows.extend(
    raw_row("repo-metadata", "repo", locator, f"repo/{locator}")
    for locator in ("package-lock.json", "package.json")
)
for runtime_prefix in RUNTIME_PREFIXES:
    rows.extend(package_rows("ajv-runtime", runtime_prefix))
rows.append(raw_row("node-binary", "node", "node", "runtime/node"))
rows.sort(key=lambda item: (item["group"], item["root"], item["locator"]))

group_counts: dict[str, int] = {}
group_bytes: dict[str, int] = {}
for item in rows:
    group_counts[item["group"]] = group_counts.get(item["group"], 0) + 1
    group_bytes[item["group"]] = group_bytes.get(item["group"], 0) + int(item["bytes"])
closure_groups = [
    {"group": "ajv-runtime", "root": "repo", "prefixes": list(RUNTIME_PREFIXES), "exactFiles": []},
    {"group": "cpsb-anchor", "root": "repo", "prefixes": [], "exactFiles": [CPSB_ANCHOR]},
    {"group": "cpsb-authored", "root": "repo", "prefixes": [], "exactFiles": sorted(f"{CPSB}/{locator}" for locator in CPSB_AUTHORED)},
    {"group": "cpsb-envelope", "root": "repo", "prefixes": [], "exactFiles": [f"{CPSB}/MANIFEST.json", f"{CPSB}/SHA256SUMS"]},
    {"group": "direct-roots", "root": "repo", "prefixes": [], "exactFiles": sorted(DIRECT_ROOTS)},
    {"group": "eapp-anchor", "root": "repo", "prefixes": [], "exactFiles": [EAPP_ANCHOR]},
    {"group": "eapp-authored", "root": "repo", "prefixes": [EAPP], "exactFiles": []},
    {"group": "node-binary", "root": "node", "prefixes": [], "exactFiles": ["node"]},
    {"group": "repo-metadata", "root": "repo", "prefixes": [], "exactFiles": ["package-lock.json", "package.json"]},
    {"group": "ssa-anchor", "root": "repo", "prefixes": [], "exactFiles": [SSA_ANCHOR]},
    {"group": "ssa-authored", "root": "repo", "prefixes": [SSA], "exactFiles": []},
    {"group": "ssa-transitive-only", "root": "repo", "prefixes": [], "exactFiles": sorted(item["locator"] for item in ssa_transitive_only)},
]
host_tcb = {
    "python": {"required": True, "role": "literal stage0, manifest parsing, nofollow source authentication, sealed-memfd capture, bwrap orchestration", "expectedInterpreter": "/usr/bin/python3.14", "versionObserved": "3.14.6", "bytesObserved": 14424, "rawSha256Observed": "2700be1aabe3687bd597f21b0eac3b9bbdf7417e93035255a9286c67935b59bd", "requiredFlags": ["-I", "-S", "-B", "-c", "REVIEWED_LITERAL"]},
    "bubblewrap": {"requiredForValidation": True, "role": "copy 676 sealed memfds with --file into private namespace regular nlink1 files, then apply one terminal nonrecursive root read-only remount; nested private /tmp remains writable; mount/user/network namespace isolation; no upward Node module fallback", "fileMaterialization": {"source": "676 sealed memfd descriptors", "operation": "--file", "result": "private namespace regular nlink1 files", "fileCount": 676, "terminalRootRemount": ["--remount-ro", "/"], "rootRemountRecursive": False, "privateTmpRemainsWritable": True}, "expectedExecutable": "/usr/bin/bwrap", "versionObserved": "0.11.2", "bytesObserved": 84464, "rawSha256Observed": "6ad2138a73d592acb43525432965e3c66f6fad8a2f3d610c6ca0b6855e993cbe", "runtimeAuthenticated": False, "dumpableBehaviorForReviewedVersion": "PR_SET_DUMPABLE_IS_SET_TO_1_DURING_UNPRIVILEGED_SETUP", "noFallback": True},
    "literalStage0": {"trusted": True, "role": "caller provenance and reviewed-byte delivery are external TCB assertions; runtime only hashes the actual Python -c bytes from /proc/self/cmdline and matches caller-supplied pins"},
    "sourceFiles": {"trustedUntilCaptured": True, "role": "component-wise nofollow regular nlink1 exact mode/size/hash/stable-identity reads across the sealed CPSB package, its outside review anchor, dependencies, runtime, and metadata; all xattrs rejected; each payload sealed and rehashed in a memfd"},
    "kernel": {"trusted": True, "observed": "Linux 7.1.4-arch1-1 x86_64"},
    "libcAndDynamicLoader": {"trusted": True, "observed": "glibc 2.43; /lib64/ld-linux-x86-64.so.2 and Node shared libraries mounted read-only by bwrap"},
    "hardware": {"trusted": True, "observed": "x86_64; 13th Gen Intel Core i9-13900H; microcode 0x6134"},
    "filesystemAndStorage": {"trustedUntilMemfdCapture": True, "role": "source bytes and metadata; no project-data disk snapshot is created"},
    "reviewerPins": {"trusted": True, "role": "external trust-root inputs supplied in the same invocation; stage0 checks internal consistency against actual command-line/helper/manifest bytes but does not prove reviewer provenance"},
    "sameUidBoundary": {"stage0PrSetDumpable": {"requestedAndChecked": 0, "scope": "STAGE0_BEFORE_BWRAP_EXEC_ONLY"}, "bubblewrapReviewedVersionBehavior": "PR_SET_DUMPABLE_IS_SET_TO_1_DURING_UNPRIVILEGED_SETUP", "activeSameUidPtraceOrProcessInjectionAfterBubblewrapStarts": "OUT_OF_PROOF", "yamaPtraceScope": {"observed": 1, "runtimeAuthenticated": False, "protectionClaim": "NONE"}, "role": "caller/interpreter/kernel/loader and privileged host remain TCB; external execution controls must exclude active ptrace or process injection after bubblewrap starts"},
}
trust_manifest = {
    "schema": "shieldkit-labs/external-launcher/cpsb-exact29/v1",
    "launcherId": "cpsb-exact29-v1",
    "authorization": "NONE",
    "mode": "sealed",
    "entryCount": len(rows),
    "totalBytes": sum(int(item["bytes"]) for item in rows),
    "groupCounts": group_counts,
    "groupBytes": group_bytes,
    "closureGroups": closure_groups,
    "snapshotPolicy": {"snapshotRootMode": "BWRAP_PRIVATE_NAMESPACE_ROOT_REMOUNT_RO_NONRECURSIVE_TMP_WRITABLE", "repoFileMode": "0644", "repoDirectoryMode": "0755", "nodeMode": "0755", "immutability": "SEALED_MEMFD_THEN_BWRAP_FILE_COPY_THEN_ROOT_REMOUNT_RO"},
    "hostTcb": host_tcb,
    "rows": rows,
}
trust_bytes = canonical(trust_manifest)
if len(rows) != 676 or trust_manifest["totalBytes"] != 174_515_890:
    raise RuntimeError("unexpected exact-676 totals")
if sha256(canonical(rows)) != "2d6667fca54ea6fd326ab7f7cf1f2f09477766e3f0184b0e46fef84cba67c688":
    raise RuntimeError("unexpected ordered-row digest")
check_output("trust-manifest.v1.json", trust_bytes)

outputs = (
    (REPO / CPSB / "MANIFEST.json", manifest_bytes),
    (REPO / CPSB / "SHA256SUMS", sums_bytes),
    (REPO / CPSB_ANCHOR, anchor_bytes),
    (LAUNCHER / "trust-manifest.v1.json", trust_bytes),
)
for path, data in outputs:
    path.write_bytes(data)
    os.chmod(path, 0o644)
for path, data in outputs:
    print(f"{len(data)} {sha256(data)} {path}")
