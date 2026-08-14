"""Authenticated CPSB exact-673 closure verifier and sealed-memfd launcher.

This module is never imported or executed by pathname.  The reviewed literal
stage-0 program authenticates its raw bytes, compiles them in memory, and calls
``stage0_entry`` with the already authenticated manifest bytes.  Only Python's
standard library is used.  Project Python/JavaScript modules are never imported.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from pathlib import PurePosixPath


SCHEMA = "shieldkit-labs/external-launcher/cpsb-exact27/v1"
LAUNCHER_ID = "cpsb-exact27-v1"
EXPECTED_MANIFEST_BYTES = 237_511
EXPECTED_MANIFEST_SHA256 = (
    "4bf28ded94240574fe50278d33460bb2ae983823bd0333f5fc435f75d1e603b0"
)
EXPECTED_TOTAL = 673
EXPECTED_TOTAL_BYTES = 174_467_070
EXPECTED_ORDERED_ROW_DIGEST = (
    "0f7c21c1d9382be59e0fe1c54f6f1c511eca581ff6bba087495373d30d3f8fa4"
)
EXPECTED_GROUP_COUNTS = {
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
}
EXPECTED_GROUP_BYTES = {
    "ajv-runtime": 1_239_787,
    "cpsb-authored": 777_990,
    "direct-roots": 210_252,
    "eapp-anchor": 33_461,
    "eapp-authored": 782_770,
    "node-binary": 124_835_376,
    "repo-metadata": 10_381,
    "ssa-anchor": 26_079,
    "ssa-authored": 414_678,
    "ssa-transitive-only": 46_136_296,
}
EXPECTED_ROOTS = {"repo", "node"}
EXPECTED_SNAPSHOT_POLICY = {
    # Field names are retained by the approved manifest schema; values describe
    # the ephemeral bwrap namespace, not a filesystem snapshot.
    "snapshotRootMode": (
        "BWRAP_PRIVATE_NAMESPACE_ROOT_REMOUNT_RO_NONRECURSIVE_TMP_WRITABLE"
    ),
    "repoFileMode": "0644",
    "repoDirectoryMode": "0755",
    "nodeMode": "0755",
    "immutability": "SEALED_MEMFD_THEN_BWRAP_FILE_COPY_THEN_ROOT_REMOUNT_RO",
}
EXPECTED_NODE_PATH = "/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node"
BWRAP_PATH = "/usr/bin/bwrap"
CPSB_DIRECTORY = (
    "/repo/research-lanes/bch-shielded-pool-design/p2/gate-b/"
    "gate-b0-external-authority-control-plane-schema-bridge-v1"
)
SSA_ROOT_LOCATOR = (
    "research-lanes/bch-shielded-pool-design/p2/gate-b/"
    "gate-b0-static-source-authority-v1/static-source-authority-root.v1.json"
)
SSA_TRANSITIVE_DIRECT_LOCATORS = {
    "research-lanes/bch-shielded-pool-design/p2/gate-b/"
    "gate-b0-evidence-plan-v1/evidence-plan-root.v1.json",
    "research-lanes/bch-shielded-pool-design/p2/gate-b/"
    "cohort-upstream-origin-provider-contract-v1/"
    "upstream-origin-provider-contract-root.v1.json",
    "research-lanes/bch-shielded-pool-design/p2/gate-b/"
    "cohort-upstream-provider-source-map-v1/"
    "upstream-provider-source-map-root.v1.json",
}
EXPECTED_VALIDATOR_VALUE = {
    "files": 27,
    "directories": 3,
    "schemaCount": 18,
    "futureRecordSchemaCount": 11,
    "totalRecordCount": 0,
    "rootContentDigest": (
        "d05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c"
    ),
    "unsealed": True,
}
EXPECTED_VALIDATOR_STDOUT = (
    b'{"files":27,"directories":3,"schemaCount":18,'
    b'"futureRecordSchemaCount":11,"totalRecordCount":0,'
    b'"rootContentDigest":"d05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c",'
    b'"unsealed":true}\n'
)
VALIDATOR_TIMEOUT_SECONDS = 30.0
VALIDATOR_STDOUT_MAX_BYTES = len(EXPECTED_VALIDATOR_STDOUT)
VALIDATOR_STDERR_MAX_BYTES = 1_024
VALIDATOR_PIPE_BYTES = 4_096
VALIDATOR_KILL_WAIT_SECONDS = 5.0
VALIDATOR_ARGV = [
    "/runtime/node",
    "--no-addons",
    "--no-global-search-paths",
    "validate-static.mjs",
    "--mode",
    "unsealed",
]
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"0[0-7]{3}\Z")
NAME_RE = re.compile(r"[a-z][a-z0-9-]*\Z")
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
MFD_ALLOW_SEALING = getattr(os, "MFD_ALLOW_SEALING", 0)
MFD_CLOEXEC = getattr(os, "MFD_CLOEXEC", 0)
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", None)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", None)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", None)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", None)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", None)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", None)


class Reject(RuntimeError):
    """A fail-closed bootstrap rejection."""


def reject(code: str, detail: str = "") -> None:
    suffix = f":{detail}" if detail else ""
    raise Reject(f"CPSB_BOOTSTRAP_{code}{suffix}")


def raw_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def exact_object(value: object, keys: set[str], where: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        reject("MANIFEST_SHAPE", where)
    return value


def safe_locator(value: object, where: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        reject("LOCATOR", where)
    if value != value.strip() or "//" in value:
        reject("LOCATOR", where)
    path = PurePosixPath(value)
    if path.is_absolute() or value in {".", ".."}:
        reject("LOCATOR", where)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        reject("LOCATOR", where)
    if str(path) != value:
        reject("LOCATOR", where)
    return value


def absolute_clean_path(value: object, where: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        reject("ABSOLUTE_PATH", where)
    if not os.path.isabs(value) or value == "/" or os.path.normpath(value) != value:
        reject("ABSOLUTE_PATH", where)
    return value


def parse_authenticated_json(data: bytes, where: str) -> object:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        reject("JSON_UTF8", where)

    def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                reject("JSON_DUPLICATE_KEY", f"{where}:{key}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=no_duplicate_keys)
    except (json.JSONDecodeError, RecursionError):
        reject("JSON_PARSE", where)


def validate_manifest_bytes(manifest_bytes: bytes) -> tuple[dict[str, object], list[dict[str, object]]]:
    if len(manifest_bytes) != EXPECTED_MANIFEST_BYTES:
        reject("MANIFEST_BYTES")
    if raw_sha256(manifest_bytes) != EXPECTED_MANIFEST_SHA256:
        reject("MANIFEST_HASH")
    value = parse_authenticated_json(manifest_bytes, "manifest")
    if canonical_json_bytes(value) != manifest_bytes:
        reject("MANIFEST_CANONICAL")
    manifest = exact_object(
        value,
        {
            "schema",
            "launcherId",
            "authorization",
            "mode",
            "entryCount",
            "totalBytes",
            "groupCounts",
            "groupBytes",
            "closureGroups",
            "snapshotPolicy",
            "hostTcb",
            "rows",
        },
        "root",
    )
    if manifest["schema"] != SCHEMA or manifest["launcherId"] != LAUNCHER_ID:
        reject("MANIFEST_ID")
    if manifest["authorization"] != "NONE" or manifest["mode"] != "unsealed":
        reject("MANIFEST_AUTHORITY")
    if manifest["entryCount"] != EXPECTED_TOTAL:
        reject("ENTRY_COUNT")
    if manifest["totalBytes"] != EXPECTED_TOTAL_BYTES:
        reject("TOTAL_BYTES")
    if manifest["groupCounts"] != EXPECTED_GROUP_COUNTS:
        reject("GROUP_COUNTS")
    if manifest["groupBytes"] != EXPECTED_GROUP_BYTES:
        reject("GROUP_BYTES")
    if manifest["snapshotPolicy"] != EXPECTED_SNAPSHOT_POLICY:
        reject("SNAPSHOT_POLICY")
    if not isinstance(manifest["hostTcb"], dict):
        reject("HOST_TCB")

    rows = manifest["rows"]
    if not isinstance(rows, list) or len(rows) != EXPECTED_TOTAL:
        reject("ENTRY_COUNT")
    group_counts: dict[str, int] = {}
    group_bytes: dict[str, int] = {}
    sources: set[tuple[str, str]] = set()
    destinations: set[str] = set()
    previous_key: tuple[str, str, str] | None = None
    for index, raw in enumerate(rows):
        row = exact_object(
            raw,
            {
                "group",
                "root",
                "locator",
                "destination",
                "bytes",
                "rawSha256",
                "sourceMode",
                "snapshotMode",
            },
            f"row:{index}",
        )
        group = row["group"]
        root = row["root"]
        if not isinstance(group, str) or not NAME_RE.fullmatch(group):
            reject("GROUP", str(index))
        if group not in EXPECTED_GROUP_COUNTS:
            reject("GROUP", group)
        if not isinstance(root, str) or root not in EXPECTED_ROOTS:
            reject("ROOT", str(index))
        locator = safe_locator(row["locator"], f"row:{index}:locator")
        destination = safe_locator(row["destination"], f"row:{index}:destination")
        if root == "repo":
            if destination != f"repo/{locator}":
                reject("DESTINATION", str(index))
        elif locator != "node" or destination != "runtime/node":
            reject("NODE_DESTINATION")
        byte_count = row["bytes"]
        digest = row["rawSha256"]
        source_mode = row["sourceMode"]
        snapshot_mode = row["snapshotMode"]
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            reject("BYTES", str(index))
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            reject("HASH", str(index))
        if not isinstance(source_mode, str) or not MODE_RE.fullmatch(source_mode):
            reject("SOURCE_MODE", str(index))
        if int(source_mode, 8) & 0o022:
            reject("WRITABLE_SOURCE", locator)
        expected_snapshot_mode = "0755" if root == "node" else "0644"
        if snapshot_mode != expected_snapshot_mode:
            reject("SNAPSHOT_MODE", str(index))
        key = (group, root, locator)
        if previous_key is not None and key <= previous_key:
            reject("ROW_ORDER", str(index))
        previous_key = key
        source = (root, locator)
        if source in sources:
            reject("SOURCE_COLLISION", f"{root}:{locator}")
        if destination in destinations:
            reject("DESTINATION_COLLISION", destination)
        sources.add(source)
        destinations.add(destination)
        group_counts[group] = group_counts.get(group, 0) + 1
        group_bytes[group] = group_bytes.get(group, 0) + byte_count
    if group_counts != EXPECTED_GROUP_COUNTS or group_bytes != EXPECTED_GROUP_BYTES:
        reject("ROW_AGGREGATES")
    if sum(group_bytes.values()) != EXPECTED_TOTAL_BYTES:
        reject("ROW_TOTAL_BYTES")
    if raw_sha256(canonical_json_bytes(rows)) != EXPECTED_ORDERED_ROW_DIGEST:
        reject("ORDERED_ROW_DIGEST")
    validate_closure_declarations(manifest, rows)
    return manifest, rows


def validate_closure_declarations(
    manifest: dict[str, object], rows: list[dict[str, object]]
) -> None:
    groups = manifest["closureGroups"]
    if not isinstance(groups, list) or len(groups) != len(EXPECTED_GROUP_COUNTS):
        reject("CLOSURE_GROUPS")
    previous = ""
    seen: set[str] = set()
    for index, raw in enumerate(groups):
        item = exact_object(
            raw, {"group", "root", "prefixes", "exactFiles"}, f"closure:{index}"
        )
        name = item["group"]
        root = item["root"]
        if not isinstance(name, str) or name not in EXPECTED_GROUP_COUNTS or name <= previous:
            reject("CLOSURE_GROUP_ORDER", str(index))
        previous = name
        seen.add(name)
        if root not in EXPECTED_ROOTS:
            reject("CLOSURE_ROOT", name)
        prefixes = item["prefixes"]
        exact_files = item["exactFiles"]
        if not isinstance(prefixes, list) or not isinstance(exact_files, list):
            reject("CLOSURE_GROUP_SHAPE", name)
        normalized_prefixes = [safe_locator(value, f"closure:{name}:prefix") for value in prefixes]
        normalized_files = [safe_locator(value, f"closure:{name}:file") for value in exact_files]
        if normalized_prefixes != sorted(set(normalized_prefixes)):
            reject("CLOSURE_PREFIX_ORDER", name)
        if normalized_files != sorted(set(normalized_files)):
            reject("CLOSURE_FILE_ORDER", name)
        if not normalized_prefixes and not normalized_files:
            reject("CLOSURE_EMPTY", name)
        expected = sorted(
            str(row["locator"])
            for row in rows
            if row["group"] == name and row["root"] == root
        )
        declared = set(normalized_files)
        for locator in expected:
            if locator in declared:
                continue
            if not any(
                locator == prefix or locator.startswith(prefix + "/")
                for prefix in normalized_prefixes
            ):
                reject("CLOSURE_COVERAGE", f"{name}:{locator}")
        for locator in normalized_files:
            if locator not in expected:
                reject("CLOSURE_DECLARATION", f"{name}:{locator}")
    if seen != set(EXPECTED_GROUP_COUNTS):
        reject("CLOSURE_GROUPS")


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def open_absolute_directory_nofollow(path: str, where: str) -> int:
    path = absolute_clean_path(path, where)
    if not O_NOFOLLOW or not O_DIRECTORY or not O_CLOEXEC:
        reject("NOFOLLOW_UNAVAILABLE")
    fd = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        for component in path.split("/")[1:]:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                    dir_fd=fd,
                )
            except OSError as exc:
                reject("ROOT_OPEN", f"{where}:{component}:{exc.errno}")
            os.close(fd)
            fd = next_fd
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            reject("ROOT_TYPE", where)
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_parent_nofollow(root_fd: int, locator: str, where: str) -> tuple[int, str]:
    parts = PurePosixPath(locator).parts
    fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                    dir_fd=fd,
                )
            except OSError as exc:
                reject("PARENT_OPEN", f"{where}:{component}:{exc.errno}")
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def source_for_row(
    row: dict[str, object], repo_fd: int, node_parent_fd: int, node_name: str
) -> tuple[int, str]:
    if row["root"] == "repo":
        return repo_fd, str(row["locator"])
    if row["root"] == "node" and row["locator"] == "node" and node_name == "node":
        return node_parent_fd, node_name
    reject("NODE_LOCATOR")


def create_sealed_memfd(index: int, data_fd: int, expected: dict[str, object]) -> int:
    required_seal_constants = (
        F_ADD_SEALS,
        F_GET_SEALS,
        F_SEAL_WRITE,
        F_SEAL_GROW,
        F_SEAL_SHRINK,
        F_SEAL_SEAL,
    )
    if not hasattr(os, "memfd_create") or not MFD_ALLOW_SEALING or not MFD_CLOEXEC:
        reject("MEMFD_SEALING_UNAVAILABLE")
    if any(value is None for value in required_seal_constants):
        reject("MEMFD_SEALING_UNAVAILABLE")
    memfd = os.memfd_create(
        f"cpsb-{index:04d}", flags=MFD_CLOEXEC | MFD_ALLOW_SEALING
    )
    digest = hashlib.sha256()
    byte_count = int(expected["bytes"])
    remaining = byte_count
    try:
        while remaining:
            chunk = os.read(data_fd, min(1024 * 1024, remaining))
            if not chunk:
                reject("SOURCE_SHORT_READ", str(expected["locator"]))
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(memfd, view)
                if written <= 0:
                    reject("MEMFD_WRITE", str(expected["locator"]))
                view = view[written:]
            remaining -= len(chunk)
        if os.read(data_fd, 1):
            reject("SOURCE_LONG_READ", str(expected["locator"]))
        if digest.hexdigest() != expected["rawSha256"]:
            reject("SOURCE_HASH", str(expected["locator"]))
        if os.fstat(memfd).st_size != byte_count:
            reject("MEMFD_SIZE", str(expected["locator"]))
        seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL
        fcntl.fcntl(memfd, F_ADD_SEALS, seals)
        if fcntl.fcntl(memfd, F_GET_SEALS) != seals:
            reject("MEMFD_SEALS", str(expected["locator"]))
        os.lseek(memfd, 0, os.SEEK_SET)
        readback = hashlib.sha256()
        remaining = byte_count
        while remaining:
            chunk = os.read(memfd, min(1024 * 1024, remaining))
            if not chunk:
                reject("MEMFD_SHORT_READ", str(expected["locator"]))
            readback.update(chunk)
            remaining -= len(chunk)
        if os.read(memfd, 1) or readback.hexdigest() != expected["rawSha256"]:
            reject("MEMFD_READBACK", str(expected["locator"]))
        os.lseek(memfd, 0, os.SEEK_SET)
        return memfd
    except BaseException:
        os.close(memfd)
        raise


def authenticate_row_to_memfd(
    index: int,
    row: dict[str, object],
    root_fd: int,
    locator: str,
) -> int:
    parent_fd, name = open_parent_nofollow(root_fd, locator, f"source:{locator}")
    try:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            reject("SOURCE_LSTAT", f"{locator}:{exc.errno}")
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            reject("SOURCE_TYPE_OR_NLINK", locator)
        if stat.S_IMODE(before.st_mode) != int(str(row["sourceMode"]), 8):
            reject("SOURCE_MODE", locator)
        if before.st_size != row["bytes"]:
            reject("SOURCE_SIZE", locator)
        try:
            data_fd = os.open(
                name, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC, dir_fd=parent_fd
            )
        except OSError as exc:
            reject("SOURCE_OPEN", f"{locator}:{exc.errno}")
        try:
            opened = os.fstat(data_fd)
            if identity(before) != identity(opened):
                reject("SOURCE_RACE_OPEN", locator)
            if not hasattr(os, "listxattr"):
                reject("SOURCE_XATTR_API_UNAVAILABLE")
            try:
                xattrs = os.listxattr(data_fd)
            except (NotImplementedError, OSError) as exc:
                reject(
                    "SOURCE_XATTR_READ", f"{locator}:{getattr(exc, 'errno', None)}"
                )
            if xattrs:
                reject("SOURCE_XATTR", f"{locator}:{sorted(xattrs)[0]}")
            memfd = create_sealed_memfd(index, data_fd, row)
            after = os.fstat(data_fd)
            try:
                post = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                os.close(memfd)
                reject("SOURCE_POST_LSTAT", f"{locator}:{exc.errno}")
            if identity(opened) != identity(after) or identity(opened) != identity(post):
                os.close(memfd)
                reject("SOURCE_RACE_POST", locator)
            return memfd
        finally:
            os.close(data_fd)
    finally:
        os.close(parent_fd)


def read_sealed_memfd(memfd: int, expected: dict[str, object]) -> bytes:
    os.lseek(memfd, 0, os.SEEK_SET)
    remaining = int(expected["bytes"])
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(memfd, min(1024 * 1024, remaining))
        if not chunk:
            reject("MEMFD_SHORT_READ", str(expected["locator"]))
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(memfd, 1):
        reject("MEMFD_LONG_READ", str(expected["locator"]))
    data = b"".join(chunks)
    if raw_sha256(data) != expected["rawSha256"]:
        reject("MEMFD_HASH", str(expected["locator"]))
    os.lseek(memfd, 0, os.SEEK_SET)
    return data


def scan_regular_files(root_fd: int, prefix: str, where: str) -> set[str]:
    prefix = safe_locator(prefix, where)
    parent_fd, name = open_parent_nofollow(root_fd, prefix, where)
    try:
        try:
            start_fd = os.open(
                name,
                os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            reject("CLOSURE_OPEN", f"{where}:{exc.errno}")
    finally:
        os.close(parent_fd)
    found: set[str] = set()
    stack: list[tuple[int, str]] = [(start_fd, prefix)]
    while stack:
        directory_fd, relative = stack.pop()
        try:
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError as exc:
                reject("CLOSURE_LIST", f"{where}:{relative}:{exc.errno}")
            for name in names:
                if name in {".", ".."} or "/" in name or "\x00" in name:
                    reject("CLOSURE_NAME", f"{where}:{relative}")
                locator = f"{relative}/{name}"
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    reject("CLOSURE_LSTAT", f"{where}:{locator}:{exc.errno}")
                if stat.S_ISREG(info.st_mode):
                    found.add(locator)
                elif stat.S_ISDIR(info.st_mode):
                    try:
                        child = os.open(
                            name,
                            os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                            dir_fd=directory_fd,
                        )
                    except OSError as exc:
                        reject("CLOSURE_OPEN", f"{where}:{locator}:{exc.errno}")
                    stack.append((child, locator))
                else:
                    reject("CLOSURE_UNSAFE", f"{where}:{locator}")
        finally:
            os.close(directory_fd)
    return found


def verify_exact_source_closures(
    manifest: dict[str, object], rows: list[dict[str, object]], root_fds: dict[str, int]
) -> None:
    for item in manifest["closureGroups"]:
        expected = {
            str(row["locator"])
            for row in rows
            if row["group"] == item["group"] and row["root"] == item["root"]
        }
        actual = set(str(value) for value in item["exactFiles"])
        for prefix in item["prefixes"]:
            actual.update(
                scan_regular_files(
                    root_fds[str(item["root"])], str(prefix), str(item["group"])
                )
            )
        if actual != expected:
            extras = sorted(actual - expected)
            missing = sorted(expected - actual)
            reject(
                "CLOSURE_EXACT",
                f"{item['group']}:extra={extras[:3]}:missing={missing[:3]}",
            )


def verify_ssa_transitive_coverage(
    rows: list[dict[str, object]], captured: list[tuple[dict[str, object], int]]
) -> None:
    matches = [
        (row, memfd)
        for row, memfd in captured
        if row["group"] == "ssa-authored"
        and row["root"] == "repo"
        and row["locator"] == SSA_ROOT_LOCATOR
    ]
    if len(matches) != 1:
        reject("SSA_ROOT_ROSTER")
    root = parse_authenticated_json(read_sealed_memfd(matches[0][1], matches[0][0]), "ssa-root")
    if not isinstance(root, dict):
        reject("SSA_ROOT_SHAPE")
    pins = root.get("transitiveSourcePins")
    if not isinstance(pins, list) or len(pins) != 64:
        reject("SSA_TRANSITIVE_PIN_COUNT")
    pin_map: dict[str, tuple[int, str]] = {}
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict):
            reject("SSA_TRANSITIVE_PIN_SHAPE", str(index))
        locator = safe_locator(pin.get("locator"), f"ssa-pin:{index}:locator")
        byte_count = pin.get("bytes")
        digest = pin.get("rawSha256")
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            reject("SSA_TRANSITIVE_PIN_BYTES", str(index))
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            reject("SSA_TRANSITIVE_PIN_HASH", str(index))
        if locator in pin_map:
            reject("SSA_TRANSITIVE_PIN_DUPLICATE", locator)
        pin_map[locator] = (byte_count, digest)

    transitive = [row for row in rows if row["group"] == "ssa-transitive-only"]
    direct = {
        str(row["locator"]): row
        for row in rows
        if row["group"] == "direct-roots"
        and row["locator"] in SSA_TRANSITIVE_DIRECT_LOCATORS
    }
    if len(transitive) != 61 or set(direct) != SSA_TRANSITIVE_DIRECT_LOCATORS:
        reject("SSA_TRANSITIVE_PARTITION")
    union = transitive + [direct[key] for key in sorted(direct)]
    coverage = {
        str(row["locator"]): (int(row["bytes"]), str(row["rawSha256"]))
        for row in union
    }
    if len(union) != 64 or len(coverage) != 64 or set(coverage) != set(pin_map):
        reject("SSA_TRANSITIVE_COVERAGE")
    for locator, pin in pin_map.items():
        if coverage[locator] != pin:
            reject("SSA_TRANSITIVE_PIN_MISMATCH", locator)


def parent_directories(rows: list[dict[str, object]]) -> list[str]:
    directories: set[str] = set()
    for row in rows:
        path = PurePosixPath("/" + str(row["destination"])).parent
        while str(path) != "/":
            directories.add(str(path))
            path = path.parent
    return sorted(directories, key=lambda value: (value.count("/"), value))


def bwrap_argv(
    rows: list[dict[str, object]], captured: list[tuple[dict[str, object], int]]
) -> list[str]:
    args = [
        BWRAP_PATH,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--assert-userns-disabled",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "HOME",
        "/nonexistent",
        "--setenv",
        "PATH",
        "/runtime",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "LANG",
        "C",
        "--setenv",
        "TZ",
        "UTC",
        "--perms",
        "0755",
        "--dir",
        "/usr",
        "--ro-bind",
        "/usr/lib",
        "/usr/lib",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib",
        "/lib64",
        "--perms",
        "0755",
        "--dir",
        "/etc",
        "--ro-bind",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ]
    for directory in parent_directories(rows):
        args.extend(["--perms", "0755", "--dir", directory])
    for row, memfd in captured:
        os.lseek(memfd, 0, os.SEEK_SET)
        args.extend(
            [
                "--perms",
                str(row["snapshotMode"]),
                "--file",
                str(memfd),
                "/" + str(row["destination"]),
            ]
        )
    args.extend(["--remount-ro", "/"])
    args.extend(["--chdir", CPSB_DIRECTORY, "--", *VALIDATOR_ARGV])
    return args


def node_pin(rows: list[dict[str, object]]) -> dict[str, object]:
    matches = [row for row in rows if row["group"] == "node-binary"]
    if len(matches) != 1:
        reject("NODE_ROW")
    row = matches[0]
    return {
        "bytes": row["bytes"],
        "rawSha256": row["rawSha256"],
        "sourceMode": row["sourceMode"],
        "mountedMode": row["snapshotMode"],
        "sourcePath": EXPECTED_NODE_PATH,
        "mountedPath": "/runtime/node",
    }


def base_receipt(
    *,
    action: str,
    manifest: dict[str, object],
    rows: list[dict[str, object]],
    repo_root: str,
    stage0_identity: dict[str, object],
    helper_identity: dict[str, object],
    manifest_identity: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "shieldkit-labs/external-launcher/cpsb-exact27/receipt/v1",
        "launcherId": LAUNCHER_ID,
        "action": action,
        "authorization": "NONE",
        "mode": "unsealed",
        "entryCount": EXPECTED_TOTAL,
        "totalBytes": EXPECTED_TOTAL_BYTES,
        "groupCounts": EXPECTED_GROUP_COUNTS,
        "groupBytes": EXPECTED_GROUP_BYTES,
        "orderedRowDigest": {
            "algorithm": "SHA256_CANONICAL_JSON_ROWS_LF",
            "value": EXPECTED_ORDERED_ROW_DIGEST,
        },
        "ssaTransitiveCoverage": {
            "authenticatedRoot": SSA_ROOT_LOCATOR,
            "pinCount": 64,
            "directRootRows": 3,
            "ssaTransitiveOnlyRows": 61,
            "locatorBytesHashEquality": True,
        },
        "stage0": stage0_identity,
        "helper": helper_identity,
        "manifest": manifest_identity,
        "node": node_pin(rows),
        "sourceRepoRoot": repo_root,
        "hostTcb": {
            "manifestDisclosure": manifest["hostTcb"],
            "pythonInvocation": {
                "executable": "/usr/bin/python3.14",
                "flags": ["-I", "-S", "-B", "-c", "<reviewed-literal>"],
                "prSetDumpable": {
                    "requestedAndChecked": 0,
                    "scope": "STAGE0_BEFORE_BWRAP_EXEC_ONLY",
                },
            },
            "bubblewrap": {
                "executable": BWRAP_PATH,
                "requiredForValidation": True,
                "hostMounts": ["/usr/lib", "/etc/ld.so.cache"],
                "sealedMemfdMaterialization": {
                    "operation": "BWRAP_FILE_COPY",
                    "fileCount": EXPECTED_TOTAL,
                    "result": "PRIVATE_NAMESPACE_REGULAR_NLINK1_FILES",
                    "terminalRootRemount": ["--remount-ro", "/"],
                    "rootRemountRecursive": False,
                    "privateTmpRemainsWritable": True,
                },
                "noFallback": True,
            },
            "processInspectionBoundary": {
                "activeSameUidPtraceOrProcessInjectionAfterBubblewrapStarts": (
                    "OUT_OF_PROOF"
                ),
                "bubblewrapReviewedVersionBehavior": (
                    "PR_SET_DUMPABLE_IS_SET_TO_1_DURING_UNPRIVILEGED_SETUP"
                ),
                "protectionClaim": "NONE",
                "yamaPtraceScope": {
                    "observed": 1,
                    "runtimeAuthenticated": False,
                    "protectionClaim": "NONE",
                },
            },
        },
        "validatorExecutionPolicy": {
            "timeoutSeconds": VALIDATOR_TIMEOUT_SECONDS,
            "stdoutCeilingBytes": VALIDATOR_STDOUT_MAX_BYTES,
            "stderrCeilingBytes": VALIDATOR_STDERR_MAX_BYTES,
            "expectedStdoutBytes": len(EXPECTED_VALIDATOR_STDOUT),
            "expectedStderrBytes": 0,
        },
        "retention": (
            "SEALED_MEMFDS_CLOSED_AND_NAMESPACE_FILE_COPIES_DISCARDED_AT_"
            "PROCESS_END_NO_PROJECT_DATA_DISK_SNAPSHOT"
        ),
    }


def emit_receipt(receipt: dict[str, object]) -> None:
    encoded = canonical_json_bytes(receipt)
    view = memoryview(encoded)
    while view:
        written = os.write(1, view)
        if written <= 0:
            reject("RECEIPT_WRITE")
        view = view[written:]


def close_quietly(descriptor: int) -> None:
    """Close during final cleanup without creating a post-receipt failure."""
    try:
        os.close(descriptor)
    except OSError:
        pass


def kill_and_reap_validator(process: subprocess.Popen[bytes]) -> None:
    """Best-effort bounded cleanup for a validator that crossed a hard limit."""
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=VALIDATOR_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        reject("VALIDATOR_REAP_TIMEOUT")


def run_validator_bounded(
    args: list[str], pass_fds: tuple[int, ...]
) -> tuple[int, bytes, bytes]:
    """Run bwrap with a wall timeout and incrementally capped output pipes."""
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            close_fds=True,
            pass_fds=pass_fds,
            bufsize=0,
            pipesize=VALIDATOR_PIPE_BYTES,
        )
    except OSError as exc:
        reject("BWRAP_EXEC", str(exc.errno))

    if process.stdout is None or process.stderr is None:
        kill_and_reap_validator(process)
        reject("VALIDATOR_PIPE_SETUP")

    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    streams = (process.stdout, process.stderr)
    try:
        for stream, name, limit, output in (
            (process.stdout, "STDOUT", VALIDATOR_STDOUT_MAX_BYTES, stdout),
            (process.stderr, "STDERR", VALIDATOR_STDERR_MAX_BYTES, stderr),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, limit, output))

        deadline = time.monotonic() + VALIDATOR_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                kill_and_reap_validator(process)
                reject("VALIDATOR_TIMEOUT", str(VALIDATOR_TIMEOUT_SECONDS))
            events = selector.select(remaining)
            if not events:
                kill_and_reap_validator(process)
                reject("VALIDATOR_TIMEOUT", str(VALIDATOR_TIMEOUT_SECONDS))
            for key, _ in events:
                name, limit, output = key.data
                read_limit = min(VALIDATOR_PIPE_BYTES, limit + 1 - len(output))
                try:
                    chunk = os.read(key.fd, max(1, read_limit))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    kill_and_reap_validator(process)
                    reject(f"VALIDATOR_{name}_LIMIT", str(limit))

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            kill_and_reap_validator(process)
            reject("VALIDATOR_TIMEOUT", str(VALIDATOR_TIMEOUT_SECONDS))
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            kill_and_reap_validator(process)
            reject("VALIDATOR_TIMEOUT", str(VALIDATOR_TIMEOUT_SECONDS))
        return returncode, bytes(stdout), bytes(stderr)
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
        if process.poll() is None:
            kill_and_reap_validator(process)


def run_authenticated(
    *,
    manifest_bytes: bytes,
    repo_root: str,
    node_path: str,
    action: str,
    stage0_identity: dict[str, object],
    helper_identity: dict[str, object],
    manifest_identity: dict[str, object],
) -> int:
    if action not in {"verify-only", "validate-unsealed"}:
        reject("ACTION")
    repo_root = absolute_clean_path(repo_root, "repo-root")
    node_path = absolute_clean_path(node_path, "node")
    if node_path != EXPECTED_NODE_PATH:
        reject("NODE_PATH")
    manifest, rows = validate_manifest_bytes(manifest_bytes)
    if manifest_identity != {
        "bytes": EXPECTED_MANIFEST_BYTES,
        "rawSha256": EXPECTED_MANIFEST_SHA256,
    }:
        reject("MANIFEST_STAGE0_IDENTITY")

    repo_fd = open_absolute_directory_nofollow(repo_root, "repo")
    node_parent_fd = open_absolute_directory_nofollow(
        os.path.dirname(node_path), "node-parent"
    )
    node_name = os.path.basename(node_path)
    captured: list[tuple[dict[str, object], int]] = []
    try:
        root_fds = {"repo": repo_fd, "node": node_parent_fd}
        verify_exact_source_closures(manifest, rows, root_fds)
        for index, row in enumerate(rows):
            root_fd, locator = source_for_row(row, repo_fd, node_parent_fd, node_name)
            memfd = authenticate_row_to_memfd(index, row, root_fd, locator)
            captured.append((row, memfd))
        # Re-establish each declared closure after capture.  Runtime bytes come
        # only from sealed memfds; the second scan also rejects source-roster
        # drift across the capture interval.
        verify_exact_source_closures(manifest, rows, root_fds)
        verify_ssa_transitive_coverage(rows, captured)

        receipt = base_receipt(
            action=action,
            manifest=manifest,
            rows=rows,
            repo_root=repo_root,
            stage0_identity=stage0_identity,
            helper_identity=helper_identity,
            manifest_identity=manifest_identity,
        )
        if action == "verify-only":
            receipt["classification"] = "AUTHENTICATED_INPUT_CLOSURE_ONLY_NO_NODE"
            receipt["validator"] = {
                "executed": False,
                "argv": VALIDATOR_ARGV,
            }
            emit_receipt(receipt)
            return 0

        args = bwrap_argv(rows, captured)
        pass_fds = tuple(memfd for _, memfd in captured)
        returncode, validator_stdout, validator_stderr = run_validator_bounded(
            args, pass_fds
        )
        if returncode < 0:
            reject("VALIDATOR_SIGNAL", str(-returncode))
        if returncode != 0:
            reject("VALIDATOR_EXIT", str(returncode))
        if validator_stderr != b"":
            reject("VALIDATOR_STDERR", raw_sha256(validator_stderr))
        if validator_stdout != EXPECTED_VALIDATOR_STDOUT:
            reject("VALIDATOR_STDOUT", raw_sha256(validator_stdout))
        try:
            validator_value = json.loads(validator_stdout)
        except json.JSONDecodeError:
            reject("VALIDATOR_JSON")
        if validator_value != EXPECTED_VALIDATOR_VALUE:
            reject("VALIDATOR_VALUE")
        receipt["classification"] = "AUTHENTICATED_UNSEALED_STATIC_VALIDATION_ONLY"
        receipt["validator"] = {
            "executed": True,
            "argv": VALIDATOR_ARGV,
            "exitCode": returncode,
            "signal": None,
            "stderrBytes": 0,
            "stdoutBytes": len(validator_stdout),
            "stdoutRawSha256": raw_sha256(validator_stdout),
            "stdoutUtf8": validator_stdout.decode("utf-8"),
            "value": validator_value,
        }
        emit_receipt(receipt)
        return 0
    finally:
        for _, memfd in captured:
            close_quietly(memfd)
        close_quietly(repo_fd)
        close_quietly(node_parent_fd)


def stage0_entry(
    *,
    manifest_bytes: bytes,
    repo_root: str,
    node_path: str,
    action: str,
    stage0_identity: dict[str, object],
    helper_identity: dict[str, object],
    manifest_identity: dict[str, object],
) -> int:
    """Only entrypoint permitted to the authenticated in-memory helper."""
    try:
        return run_authenticated(
            manifest_bytes=manifest_bytes,
            repo_root=repo_root,
            node_path=node_path,
            action=action,
            stage0_identity=stage0_identity,
            helper_identity=helper_identity,
            manifest_identity=manifest_identity,
        )
    except Reject as exc:
        os.write(2, (str(exc) + "\n").encode("utf-8", "strict"))
        return 1
    except (OSError, ValueError, TypeError) as exc:
        message = f"CPSB_BOOTSTRAP_INTERNAL:{type(exc).__name__}:{exc}\n"
        os.write(2, message.encode("utf-8", "backslashreplace"))
        return 1


if __name__ == "__main__":
    os.write(2, b"CPSB_BOOTSTRAP_HELPER_PATH_EXECUTION_FORBIDDEN\n")
    raise SystemExit(1)
