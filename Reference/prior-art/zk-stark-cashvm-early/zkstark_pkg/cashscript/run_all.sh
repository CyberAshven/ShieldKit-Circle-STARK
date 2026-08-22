#!/usr/bin/env bash
set -e
npm install >/dev/null 2>&1 || npm install
echo "== fused single verifier (trace opening + composition + multi-layer FRI fold, one program) =="
node fused/verify.mjs
echo
echo "== individual verifier blocks =="
for f in validate.mjs vfold.mjs vgrind.mjs vmulti.mjs vstark.mjs vfs.mjs vverify.mjs vcomp.mjs; do
  echo "--- $f ---"; node "$f" || true
done
echo "--- handasm/vfold_asm.mjs ---"; node handasm/vfold_asm.mjs || true
