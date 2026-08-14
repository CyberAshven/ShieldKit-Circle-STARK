"""Literal-only stage 0 for the CPSB exact-673 nonauthorizing bootstrap.

This reviewed source is a reference artifact.  The caller is responsible for
supplying its independently reviewed bytes as the argument after
``/usr/bin/python3.14 -I -S -B -c``.  Runtime checks prove only that the actual
``-c`` bytes match the size/hash arguments in the same invocation.  They do not
prove how the caller obtained or reviewed those bytes.  Stage 0 itself never
opens this reference artifact by pathname.
"""

import builtins
import ctypes
import hashlib
import os
import stat
import sys


PYTHON = b"/usr/bin/python3.14"
PYTHON_OPTIONS = [b"-I", b"-S", b"-B", b"-c"]
SHA256_CHARS = frozenset("0123456789abcdef")
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4


class Stage0Reject(RuntimeError):
    pass


def reject(code, detail=""):
    suffix = ":" + detail if detail else ""
    raise Stage0Reject("CPSB_STAGE0_" + code + suffix)


def unsigned(value, where):
    if not value or (value != "0" and (value[0] == "0" or not value.isdecimal())):
        reject("UINT", where)
    if value == "0":
        return 0
    if not value.isascii():
        reject("UINT", where)
    return int(value, 10)


def sha256_pin(value, where):
    if len(value) != 64 or any(character not in SHA256_CHARS for character in value):
        reject("SHA256", where)
    return value


def clean_absolute(value, where):
    if not value or "\x00" in value or not value.startswith("/") or value == "/":
        reject("PATH", where)
    if os.path.normpath(value) != value or "//" in value:
        reject("PATH", where)
    return value


def file_identity(info):
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


def open_absolute_directory(path, where):
    clean_absolute(path, where)
    if not O_NOFOLLOW or not O_DIRECTORY or not O_CLOEXEC:
        reject("NOFOLLOW_UNAVAILABLE")
    descriptor = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        for component in path.split("/")[1:]:
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                    dir_fd=descriptor,
                )
            except OSError as error:
                reject("DIRECTORY_OPEN", where + ":" + component + ":" + str(error.errno))
            os.close(descriptor)
            descriptor = next_descriptor
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            reject("DIRECTORY_TYPE", where)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def pinned_file(path, expected_bytes, expected_hash, where):
    path = clean_absolute(path, where)
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    parent_descriptor = open_absolute_directory(parent, where + "-parent")
    try:
        try:
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as error:
            reject("FILE_LSTAT", where + ":" + str(error.errno))
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            reject("FILE_TYPE_OR_NLINK", where)
        if stat.S_IMODE(before.st_mode) != 0o644:
            reject("FILE_MODE", where)
        if before.st_size != expected_bytes:
            reject("FILE_BYTES", where)
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            reject("FILE_OPEN", where + ":" + str(error.errno))
        try:
            opened = os.fstat(descriptor)
            if file_identity(before) != file_identity(opened):
                reject("FILE_RACE_OPEN", where)
            if not hasattr(os, "listxattr"):
                reject("FILE_XATTR_API_UNAVAILABLE")
            try:
                xattrs = os.listxattr(descriptor)
            except (NotImplementedError, OSError) as error:
                reject(
                    "FILE_XATTR_READ",
                    where + ":" + str(getattr(error, "errno", None)),
                )
            if xattrs:
                reject("FILE_XATTR", where + ":" + sorted(xattrs)[0])
            digest = hashlib.sha256()
            chunks = []
            remaining = expected_bytes
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    reject("FILE_SHORT_READ", where)
                chunks.append(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                reject("FILE_LONG_READ", where)
            after = os.fstat(descriptor)
            try:
                post = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except OSError as error:
                reject("FILE_POST_LSTAT", where + ":" + str(error.errno))
            if file_identity(opened) != file_identity(after):
                reject("FILE_RACE_READ", where)
            if file_identity(opened) != file_identity(post):
                reject("FILE_RACE_POST", where)
            if digest.hexdigest() != expected_hash:
                reject("FILE_HASH", where)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def read_proc_cmdline():
    descriptor = os.open("/proc/self/cmdline", os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    try:
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if not raw.endswith(b"\x00"):
        reject("PROC_CMDLINE")
    return raw[:-1].split(b"\x00")


def disable_dumpability():
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        reject("PR_SET_DUMPABLE", str(ctypes.get_errno()))
    if prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
        reject("PR_GET_DUMPABLE")


def run():
    if sys.argv[0] != "-c":
        reject("LITERAL_C_REQUIRED")
    if len(sys.argv) != 12:
        reject("ARGV_COUNT")
    if sys.executable != PYTHON.decode("ascii"):
        reject("PYTHON_EXECUTABLE")
    if not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode:
        reject("PYTHON_FLAGS")

    stage0_bytes = unsigned(sys.argv[1], "stage0-bytes")
    stage0_hash = sha256_pin(sys.argv[2], "stage0-hash")
    helper_path = clean_absolute(sys.argv[3], "helper")
    helper_bytes_count = unsigned(sys.argv[4], "helper-bytes")
    helper_hash = sha256_pin(sys.argv[5], "helper-hash")
    manifest_path = clean_absolute(sys.argv[6], "manifest")
    manifest_bytes_count = unsigned(sys.argv[7], "manifest-bytes")
    manifest_hash = sha256_pin(sys.argv[8], "manifest-hash")
    repo_root = clean_absolute(sys.argv[9], "repo-root")
    node_path = clean_absolute(sys.argv[10], "node")
    action = sys.argv[11]
    if action not in {"verify-only", "diagnose-unsealed"}:
        reject("ACTION")

    cmdline = read_proc_cmdline()
    if len(cmdline) != 6 + len(sys.argv) - 1:
        reject("PROC_ARGV_COUNT")
    if cmdline[0] != PYTHON or cmdline[1:5] != PYTHON_OPTIONS:
        reject("PROC_PYTHON_ARGV")
    literal = cmdline[5]
    actual_stage0_bytes = len(literal)
    actual_stage0_hash = hashlib.sha256(literal).hexdigest()
    if actual_stage0_bytes != stage0_bytes or actual_stage0_hash != stage0_hash:
        reject("LITERAL_PIN")
    expected_tail = [value.encode("utf-8", "strict") for value in sys.argv[1:]]
    if cmdline[6:] != expected_tail:
        reject("PROC_ARGUMENT_BYTES")

    os.umask(0o077)
    disable_dumpability()
    os.environ.clear()
    os.environ.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})

    helper_bytes = pinned_file(
        helper_path, helper_bytes_count, helper_hash, "helper"
    )
    manifest_bytes = pinned_file(
        manifest_path, manifest_bytes_count, manifest_hash, "manifest"
    )
    try:
        helper_bytes.decode("utf-8", "strict")
        code = compile(
            helper_bytes,
            "<authenticated-cpsb-helper>",
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=0,
        )
    except (UnicodeDecodeError, SyntaxError, ValueError) as error:
        reject("HELPER_COMPILE", type(error).__name__)
    namespace = {
        "__name__": "__authenticated_cpsb_helper__",
        "__file__": "<authenticated-cpsb-helper>",
        "__builtins__": builtins.__dict__,
    }
    exec(code, namespace, namespace)
    entry = namespace.get("stage0_entry")
    if not callable(entry):
        reject("HELPER_ENTRY")
    result = entry(
        manifest_bytes=manifest_bytes,
        repo_root=repo_root,
        node_path=node_path,
        action=action,
        stage0_identity={
            "delivery": "LITERAL_C_ARG_MATCHED_CALLER_SUPPLIED_PINS_VIA_PROC_SELF_CMDLINE",
            "bytes": actual_stage0_bytes,
            "rawSha256": actual_stage0_hash,
            "callerPinMatchedActualCmdline": True,
            "callerProvenance": "EXTERNAL_TCB_ASSERTION_NOT_RUNTIME_PROVED",
            "referencePathNotReadByStage0": True,
        },
        helper_identity={
            "bytes": helper_bytes_count,
            "rawSha256": helper_hash,
            "delivery": "COMPONENT_NOFOLLOW_AUTHENTICATED_BYTES_COMPILED_IN_MEMORY",
        },
        manifest_identity={
            "bytes": manifest_bytes_count,
            "rawSha256": manifest_hash,
        },
    )
    if result != 0:
        raise SystemExit(result if isinstance(result, int) else 1)


try:
    run()
except Stage0Reject as error:
    os.write(2, (str(error) + "\n").encode("utf-8", "strict"))
    raise SystemExit(1)
except SystemExit:
    raise
except BaseException as error:
    message = "CPSB_STAGE0_INTERNAL:" + type(error).__name__ + ":" + str(error) + "\n"
    os.write(2, message.encode("utf-8", "backslashreplace"))
    raise SystemExit(1)
