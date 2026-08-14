# Gate B0 execution-admission contract v1

This package is a static pre-execution prerequisite catalog. It creates no attempt, authority, admission, provider, owner, fact, artifact map, workload, run, result, evidence, measurement, qualification, ranking, selection, or fallback capability.

Its only purpose is to preserve the exact prerequisites that a separate, externally authorized future retry would have to satisfy. Every instance count is zero and every admission, execution, runtime-import, endpoint-import, qualification, ranking, selection, and fallback gate is false.

Lifecycle is explicit rather than inferred. An authored-only source copy is validated in `unsealed` mode and must contain neither `MANIFEST.json` nor `SHA256SUMS`. A mechanically sealed package is validated in `sealed` mode and contains both envelopes. Sealed validation requires a separately reviewed sibling review anchor supplied as four explicit caller-pin fields; the package never discovers, embeds, or derives that anchor pin.

The validator reads only regular raw source leaves under safe containment checks. It does not import or evaluate runner, endpoint, executor, engine, BCH, VM, prover, or Lean modules. Upstream leaves may retain their pinned `0444`, `0600`, or `0644` modes; raw SHA-256, byte count, regular-file, no-link, and single-file-link checks remain mandatory. Package directories are checked only for exact roster, directory type, non-symlink status, and mode: directory link counts are filesystem-dependent and are not used as file-hardlink evidence.

The `futureStateGrammar` is descriptive only. Its retry slice has 37 ordered prerequisites and its artifact/result contract has 7 ordered edges; both remain unavailable. In particular, a caller-created `Map`, catalog digest, null placeholder, static model, historical attempt, or retry wrapper is not a provider, owner, fact, root, capture, artifact map, authorization, claim, or result.

Future measurement and adversarial schemas remain external references only. This package creates no such instance and cannot admit one.

The direct package-local validator is a nonauthorizing static self-check only: it cannot authenticate the `validate-static.mjs` bytes it is executing. A later authenticated lane or other outside-package caller must raw-pin and hash `validate-static.mjs` before importing or executing it, then supply an independently pinned review anchor. A caller-created artifact map or review-anchor pin remains nonauthoritative unless that outside authority independently pins it.
