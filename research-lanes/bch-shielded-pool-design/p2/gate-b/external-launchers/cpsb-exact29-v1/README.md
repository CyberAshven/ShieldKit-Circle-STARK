# CPSB exact-676 sealed-source bootstrap

This directory is a nonauthorizing bootstrap for the materially sealed 29-file CPSB package. It has exactly two fixed actions: `verify-only` and `validate-sealed`. Both authenticate the complete 676-row runtime closure and independently reconstruct the package envelope, outside review anchor, root/component digests, and schema-binding table from sealed memfds before any namespace materialization. Only `validate-sealed` starts Node.

The bootstrap grants no principal, authority, admission, attempt, measurement, benchmark, qualification, ranking, selection, or promotion semantics. The outside review anchor is an exact source-contract review anchor whose status remains explicitly unqualified and nonauthorizing.

`validate-sealed` runs exactly:

```text
/runtime/node --no-addons --no-global-search-paths validate-static.mjs --mode sealed --anchor-root /repo/research-lanes/bch-shielded-pool-design/p2/gate-b --anchor-locator gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json --anchor-bytes 32442 --anchor-raw-sha256 42f2b1eaf7d4834f4c07248da74981f40fccb71a4e633afb29bffefab4d5b868
```

No unsealed mode, authored test, arbitrary script, caller-supplied Node option, or third action is supported.

## Material seal

The 27 source leaves remain byte-identical to the reviewed source-unsealed closure. The seal adds only:

| Artifact | Bytes | Raw SHA-256 |
| --- | ---: | --- |
| package `MANIFEST.json` | 13,498 | `cb7eb8a3dd6691d325fa1c0479b71a0fa0748649fef238c10e78cc0bbe7dc5c0` |
| package `SHA256SUMS` | 2,880 | `95751ed2534f16ce73eb13d18bdf9dd7b11334bc7751ed15b830a95786c85428` |
| outside review anchor | 32,442 | `42f2b1eaf7d4834f4c07248da74981f40fccb71a4e633afb29bffefab4d5b868` |

The anchor has the validator-required 19 keys, retains the validator's `AUTHORED_FILES` order, and is outside the package at `p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-review-anchor.v1.json`. The package root remains 50,052 bytes with raw SHA-256 `89c281e916790e5d488f554fdf508af80cc7c3e0b8d9a2b99f62707c150a17e4` and content digest `d05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c`. The validator remains 438,375 bytes with raw SHA-256 `65727edaa77d783dd0db33f70f57856240f7c732b7156fa8c76785aadf94546c`.

The historical exact-673 launcher and its authenticated source-unsealed receipt are retention-only evidence. Exact-673/source-unsealed and exact-676/sealed operation are mutually exclusive after the envelope is materialized; the old launcher is not modified or reused.

## Exact authenticated closure

The canonical trust manifest has 676 unique source rows and 174,515,890 bytes. It is the old 673-row closure plus the two envelope files and one outside anchor:

| Group | Rows | Bytes |
| --- | ---: | ---: |
| `ajv-runtime` | 527 | 1,239,787 |
| `cpsb-anchor` | 1 | 32,442 |
| `cpsb-authored` | 27 | 777,990 |
| `cpsb-envelope` | 2 | 16,378 |
| `direct-roots` | 4 | 210,252 |
| `eapp-anchor` | 1 | 33,461 |
| `eapp-authored` | 23 | 782,770 |
| `node-binary` | 1 | 124,835,376 |
| `repo-metadata` | 2 | 10,381 |
| `ssa-anchor` | 1 | 26,079 |
| `ssa-authored` | 26 | 414,678 |
| `ssa-transitive-only` | 61 | 46,136,296 |
| **Total** | **676** | **174,515,890** |

The ordered-row canonical-JSON digest is `2d6667fca54ea6fd326ab7f7cf1f2f09477766e3f0184b0e46fef84cba67c688`. The helper separately scans the sealed CPSB package and requires exactly the 27 ordered source leaves plus `MANIFEST.json` and `SHA256SUMS`; splitting those rows into review groups cannot hide an extra package file.

Before either action can emit a receipt, the helper authenticates all rows into sealed memfds and then:

1. derives all 27 manifest entries, raw hashes, framed file digests, roster digest, canonical manifest bytes, and exact checksum text;
2. authenticates the outside anchor and proves exact equality to the derived closure;
3. recomputes the root content digest and all eight component digests;
4. verifies the ordered 18-schema binding roster, each schema raw hash, canonical JSON, and `$id`, then recomputes the schema-binding-table digest;
5. binds the anchor to the root, validator, dependency binding, EAPP disposition, component digests, schema bindings, and nonauthority boundary; and
6. re-establishes the 64-pin SSA transitive partition and every declared source closure.

`verify-only` stops there and classifies only `AUTHENTICATED_SEALED_STATIC_SOURCE_CONTRACT_ONLY_NO_NODE_NO_ADMISSION`. `validate-sealed` additionally requires exit 0, empty stderr, and the exact 200-byte stdout below (raw SHA-256 `15fc4579d00875eb182ec5d23d1986940de53590e97b29e454ecf1baa1b76098`):

```json
{"files":29,"directories":3,"schemaCount":18,"futureRecordSchemaCount":11,"totalRecordCount":0,"rootContentDigest":"d05a1a2432a23d43706fbeee575b7f8389ce509af04ff1234733c92f86e3869c","unsealed":false}
```

Its receipt classification is only `AUTHENTICATED_SEALED_STATIC_VALIDATION_ONLY`.

## Runtime architecture and trust boundary

`stage0-literal.py` is a reviewed reference artifact, never a pathname entrypoint. The caller must independently hold its reviewed bytes and supply those exact bytes directly as the `-c` argument of `/usr/bin/python3.14 -I -S -B`. Stage 0 checks the actual `/proc/self/cmdline` literal against caller-supplied size/hash pins, authenticates the helper and trust manifest using component-wise nofollow reads, then compiles the authenticated helper bytes in memory. Caller provenance and literal delivery remain external TCB assertions.

The helper performs component-wise `O_NOFOLLOW` regular-`nlink=1` mode/size/hash/stable-identity reads, rejects all xattrs, captures each payload in a sealed memfd, rehashes every memfd, and materializes exactly 676 files with bubblewrap `--file`. It creates parent directories first and appends exactly one terminal nonrecursive `--remount-ro /`; the nested private `/tmp` remains writable. Bubblewrap is mandatory and has no fallback. Project-data copies disappear with the namespace and no project-data disk snapshot is retained.

The host TCB includes the caller, `/usr/bin/python3.14`, `/usr/bin/bwrap`, kernel, loader/libc, authenticated Node binary's dynamic host libraries, filesystem/storage, hardware, and privileged processes. `PR_SET_DUMPABLE=0` is proved only for stage 0 before input capture. The reviewed bubblewrap 0.11.2 setup later sets dumpability to 1; active same-UID ptrace or process injection after bubblewrap starts is outside this proof and must be excluded by external execution controls. No protection claim is inferred from the unauthenticated observed Yama setting.

## Exact reviewed pins

| Artifact | Bytes | Raw SHA-256 |
| --- | ---: | --- |
| `stage0-literal.py` | 10,672 | `f603f774bbe9511c67d57be71a62c6518b2564063aad0323a6520c3e9ee958df` |
| `verify-copy.py` | 56,234 | `292bdd4cb497a84f088f7f493a66ce5e12b6a3861f10e8064181297f7fe40b70` |
| `trust-manifest.v1.json` | 243,425 | `12e80d243e86f6290a08c92ac1d9f92edada9509cec03ed044d99317f60186fa` |
| `/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node` | 124,835,376 | `93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068` |

`build-seal-review-only.py` is a non-importing convenience artifact, not a trust root or runtime input. It is 20,642 bytes with raw SHA-256 `4a540674167e93ab81757a34a64f5eb512d3ebd03be9348b5374a69c8b4d88af`. It executes no CPSB JavaScript or launcher source, hard-pins all 27 source identities and all four outputs, and stops before writing on any derivation disagreement.

## Literal invocation contract

The caller-controlled boundary is:

```text
execve(
  "/usr/bin/python3.14",
  [
    "/usr/bin/python3.14", "-I", "-S", "-B", "-c",
    REVIEWED_STAGE0_BYTES,
    "10672", "f603f774bbe9511c67d57be71a62c6518b2564063aad0323a6520c3e9ee958df",
    "/home/toorik/Projects/ShieldKit-LABS/research-lanes/bch-shielded-pool-design/p2/gate-b/external-launchers/cpsb-exact29-v1/verify-copy.py",
    "56234", "292bdd4cb497a84f088f7f493a66ce5e12b6a3861f10e8064181297f7fe40b70",
    "/home/toorik/Projects/ShieldKit-LABS/research-lanes/bch-shielded-pool-design/p2/gate-b/external-launchers/cpsb-exact29-v1/trust-manifest.v1.json",
    "243425", "12e80d243e86f6290a08c92ac1d9f92edada9509cec03ed044d99317f60186fa",
    "/home/toorik/Projects/ShieldKit-LABS",
    "/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node",
    "verify-only"
  ],
  EMPTY_ENVIRONMENT
)
```

Review and retain the `verify-only` receipt before changing only the final action to `validate-sealed`. The tombstone `launch.sh` always fails and must never be used as an entrypoint.
