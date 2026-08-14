# cohort-commit-helper-v1

Freestanding Linux x86_64 helper for the final no-replace directory commit.
It is assembled directly by `/usr/bin/as --64` and linked directly by
`/usr/bin/ld`; no compiler driver, libc, interpreter, or dynamic dependency is
used. The resulting program invokes exactly `renameat2(3, oldBasename,
4, newBasename, RENAME_NOREPLACE)` and then `_exit`.

The caller must pass already-open directory descriptors 3 and 4, plus fd 5
retaining the validated source directory, and exactly two basename arguments.
Before rename, fd 5 is compared with fd 3 plus the source basename using
`AT_SYMLINK_NOFOLLOW` over device, inode, type, mode, uid, and gid. After
rename, fd 4 plus the destination basename is compared again. No path contains
a slash; `.`, `..`, and empty names are rejected before the syscall. The
helper writes zero stdout/stderr bytes.

The name lookup, comparison, and rename are separate syscalls. Linux does not
provide an atomic “compare this pathname to this retained fd and rename it”
operation here. The helper therefore detects replacement before rename and
verifies the destination afterward, but its residual boundary is the
cooperative same-UID namespace assumption: an untrusted actor can still race
the final pathname check. A mismatch returns `111` and is never reported as
success.

Exit codes are stable: `0` success, `17` existing destination, `18`
cross-device, `64` usage/name validation, and `111` all other syscall errors.

This package is a helper artifact only. It is not integrated into any executor,
lane, authorization, claim, or evidence package.
