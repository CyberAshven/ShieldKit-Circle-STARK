# CPSB exact-673 literal bootstrap

This directory contains a nonauthorizing bootstrap with exactly two fixed actions. Both authenticate the complete source-unsealed CPSB runtime closure. Only `validate-unsealed` executes the exact static validator in an isolated namespace whose root is remounted read-only after file materialization. The bootstrap grants no principal, authority, seal, admission, attempt, measurement, benchmark, qualification, ranking, or promotion semantics.

The initial reviewed action is `verify-only`. It authenticates and captures the complete closure in sealed anonymous memory, emits one canonical receipt, and never starts Node. `validate-unsealed` is the only execution action and may be invoked only after the stage-0/helper/manifest pins and `verify-only` receipt have been independently reviewed. It runs exactly:

```text
/runtime/node --no-addons --no-global-search-paths validate-static.mjs --mode unsealed
```

No tests, sealed validation, third action, arbitrary script, or caller-supplied Node option is supported.

## Exact authenticated closure

The canonical [trust manifest](./trust-manifest.v1.json) has 673 unique source rows and 174,467,070 bytes:

| Group | Rows | Bytes |
| --- | ---: | ---: |
| `ajv-runtime` | 527 | 1,239,787 |
| `cpsb-authored` | 27 | 777,990 |
| `direct-roots` | 4 | 210,252 |
| `eapp-anchor` | 1 | 33,461 |
| `eapp-authored` | 23 | 782,770 |
| `node-binary` | 1 | 124,835,376 |
| `repo-metadata` | 2 | 10,381 |
| `ssa-anchor` | 1 | 26,079 |
| `ssa-authored` | 26 | 414,678 |
| `ssa-transitive-only` | 61 | 46,136,296 |
| **Total** | **673** | **174,467,070** |

The helper first authenticates the SSA root from the `ssa-authored` group. It parses the root's exact 64 `transitiveSourcePins` and proves locator/byte-count/raw-SHA-256 equality against the disjoint union of 61 `ssa-transitive-only` rows plus the B0R, UOPC, and SPM roots already present in `direct-roots`. EAC remains the fourth direct root and is not duplicated. The ordered-row canonical-JSON digest is `0f7c21c1d9382be59e0fe1c54f6f1c511eca581ff6bba087495373d30d3f8fa4`.

The prior 612-row omission analysis is retained only as [historical-612-omissions.tsv](./historical-612-omissions.tsv). It is not in the trust manifest, is never read by stage 0 or the helper, and has no launch role.

## Trust boundary and data flow

`stage0-literal.py` is a reviewed source artifact, not a pathname entrypoint. The caller must first independently review its exact bytes, hold its size and SHA-256 outside this directory, read those reviewed bytes into its own process, and supply those exact bytes directly as the `-c` argument of `/usr/bin/python3.14 -I -S -B`. That provenance is an external TCB assertion: stage 0 cannot prove where its caller obtained or reviewed the literal. It proves only that the actual `-c` bytes in `/proc/self/cmdline` match the size/hash arguments supplied in that same invocation. The Python interpreter parses that literal before any code in it can run; consequently the interpreter, literal-delivery mechanism, caller, kernel, loader, and privileged host are part of the pre-start TCB.

At runtime stage 0:

1. reads `/proc/self/cmdline`, hashes the actual `-c` byte string, and compares it to the caller-supplied literal size/hash arguments;
2. checks the exact Python executable and `-I -S -B -c` argument boundary;
3. applies `umask(077)` and checks `PR_SET_DUMPABLE=0` before any helper, manifest, or project-input read;
4. component-walks helper and manifest paths with `O_NOFOLLOW`, requiring regular `nlink=1`, mode `0644`, no extended attributes, exact bytes/hash, and stable pre/open/post identity;
5. compiles and executes only the authenticated helper bytes in a fresh namespace; and
6. passes the already authenticated manifest bytes directly, so neither helper nor manifest is reopened by pathname. The receipt field is therefore narrowly named `referencePathNotReadByStage0`; it makes no claim about what the external caller read before start.

Stage 0 sets only locale/time-zone process environment after interpreter start. It intentionally does not assign `PYTHONHASHSEED` there because a post-start assignment cannot change the interpreter's already selected hash seed.

The helper authenticates every manifest source by component-wise `O_NOFOLLOW` opens, exact type/link/mode/size/hash, no extended attributes, and stable pre/open/post identity. Each payload is copied directly from its held source descriptor into a new `MFD_ALLOW_SEALING` memfd, sealed with `F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`, then read back and rehashed. No project-data disk snapshot is created.

For validation, the helper creates parent-first mode-`0755` namespace directories and supplies all 673 sealed descriptors using mode-normalized `--perms ... --file FD DEST` operations. Each operation copies one sealed memfd into one private-namespace regular `nlink=1` file; repository files are `0644` and the Node binary is `0755`. After the last of exactly 673 `--file` operations, the helper appends exactly one terminal `--remount-ro /` before `--chdir`. That remount is nonrecursive: it makes the namespace root hierarchy read-only while the nested private `/tmp` mount remains writable. Bubblewrap is mandatory and has no fallback. It uses `--unshare-all --unshare-user --disable-userns --assert-userns-disabled`, drops all capabilities, clears the environment, provides private `/tmp`, `/dev`, and `/proc`, and mounts only the disclosed host runtime TCB plus the authenticated files. The validator has a 30-second wall timeout. The `validate-unsealed` collector is incrementally capped at the exact expected 199 stdout bytes and 1,024 stderr bytes; either overflow kills the child and rejects the run, while acceptance still requires byte-exact stdout and empty stderr. All memfds close and all private namespace file copies disappear when the process exits; no project-data disk snapshot is created.

The old [launch.sh](./launch.sh) pathname launcher is a tombstone which always fails. It does not authenticate itself and must never be used as an entrypoint.

## Exact reviewed pins

These pins must be re-established after every edit. The values below describe this reviewed version:

| Artifact | Bytes | Raw SHA-256 |
| --- | ---: | --- |
| `stage0-literal.py` | `10667` | `0d069f199ea9e6fbb7eabed4d7b6a31494981dab0461722c0fa8d3a99ca9c9b1` |
| `verify-copy.py` | `41138` | `e3916aa3f9aa396892caccc6082e1ac5928cade157b266d6c44ffce3524b7069` |
| `trust-manifest.v1.json` | `237511` | `4bf28ded94240574fe50278d33460bb2ae983823bd0333f5fc435f75d1e603b0` |
| `/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node` | `124835376` | `93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068` |

The stage-0 and helper pins above are inputs to review. A caller must re-establish them independently from its reviewed byte copies; this table is documentation, not an authenticated pin channel.

## Literal invocation contract

The following is pseudocode for the caller-controlled delivery boundary. `REVIEWED_STAGE0_BYTES` means the caller's already-reviewed byte string; it must not be obtained from the launcher directory as part of the same unreviewed command. The `stage0-literal.py` pathname is intentionally absent from the Python invocation.

```text
execve(
  "/usr/bin/python3.14",
  [
    "/usr/bin/python3.14", "-I", "-S", "-B", "-c",
    REVIEWED_STAGE0_BYTES,
    "10667", "0d069f199ea9e6fbb7eabed4d7b6a31494981dab0461722c0fa8d3a99ca9c9b1",
    "/home/toorik/Projects/ShieldKit-LABS/research-lanes/bch-shielded-pool-design/p2/gate-b/external-launchers/cpsb-exact27-v1/verify-copy.py",
    "41138", "e3916aa3f9aa396892caccc6082e1ac5928cade157b266d6c44ffce3524b7069",
    "/home/toorik/Projects/ShieldKit-LABS/research-lanes/bch-shielded-pool-design/p2/gate-b/external-launchers/cpsb-exact27-v1/trust-manifest.v1.json",
    "237511", "4bf28ded94240574fe50278d33460bb2ae983823bd0333f5fc435f75d1e603b0",
    "/home/toorik/Projects/ShieldKit-LABS",
    "/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node",
    "verify-only"
  ],
  EMPTY_ENVIRONMENT
)
```

Run and review `verify-only` before replacing its final action argument with `validate-unsealed`. The receipt reports the hash of the actual `/proc/self/cmdline` stage-0 bytes, helper/manifest/Node identities, group totals, ordered-row digest, SSA 64-pin coverage, action, fixed validator argv, timeout/output policy, the limited TCB/process-injection boundary, and `authorization: "NONE"`. A successful validation receipt additionally requires exit 0, no signal, empty stderr, and the exact deterministic validator JSON and LF.

## Explicit host TCB and limitations

The manifest authenticates the Node executable and project/runtime data, not the whole machine. The external TCB includes:

- the caller's reviewed literal provenance and exact-byte delivery mechanism;
- `/usr/bin/python3.14` 3.14.6 and its standard library, libc, loader, and inherited process setup;
- `/usr/bin/bwrap` 0.11.2, Linux namespace/mount enforcement, and the bwrap option parser;
- the Linux kernel, `/proc/self/cmdline`, memfd/seal/xattr/filesystem implementations, scheduler, storage, and process-descriptor semantics;
- host `/usr/lib`, `/etc/ld.so.cache`, Node's dynamically loaded libraries, glibc, and dynamic loader;
- x86-64 hardware and microcode; and
- any privileged process able to inspect or alter the running process or host TCB.

`PR_SET_DUMPABLE=0` is checked only for stage 0 before it reads the authenticated inputs. It must not be treated as protection of the later validator: the reviewed bubblewrap 0.11.2 source sets `PR_SET_DUMPABLE=1` during its unprivileged setup before executing the sandbox command. The observed host value `kernel.yama.ptrace_scope=1` is recorded only as an unauthenticated review-time observation; the launcher neither pins nor enforces it and claims no protection from it. Active same-UID ptrace or other process injection after bubblewrap starts is explicitly outside this bootstrap's proof and must be excluded by external execution controls. This boundary is recorded in both the manifest disclosure and each receipt. See bubblewrap's reviewed [`drop_privs` implementation](https://github.com/containers/bubblewrap/blob/v0.11.2/bubblewrap.c#L3791-L3798).

The helper rejects source extended attributes rather than interpreting capability or other xattr semantics. It also treats bubblewrap, Python, the caller, privileged processes, the kernel, loader, and hardware as TCB; their observed hashes or settings in the manifest are disclosures, not runtime authentication. Receipt correctness is therefore conditional on this explicit host TCB and process-injection exclusion.

## Nonauthorizing classification

`verify-only` proves only `AUTHENTICATED_INPUT_CLOSURE_ONLY_NO_NODE`. `validate-unsealed` proves only `AUTHENTICATED_UNSEALED_STATIC_VALIDATION_ONLY`. No result seals CPSB, authenticates an outside review anchor, grants authority, admits execution, creates an attempt, runs authored tests, measures performance, or qualifies any Circle-FRI candidate.
