import assert from 'node:assert/strict';
import test from 'node:test';
import { deriveManifest, verifyManifest } from '../src/integrity.mjs';
import { checkSealedBytes, deriveSealedBytes } from '../generate.mjs';

function records() {
  return [
    { locator: 'alpha.txt', sha256: 'a'.repeat(64), bytes: 1 },
    { locator: 'generate.mjs', sha256: 'b'.repeat(64), bytes: 2 },
    { locator: 'runtime-core.v1.json', sha256: 'c'.repeat(64), bytes: 3 },
    { locator: 'src/contracts.mjs', sha256: 'd'.repeat(64), bytes: 4 },
    { locator: 'src/integrity.mjs', sha256: 'e'.repeat(64), bytes: 5 },
    { locator: 'validate.mjs', sha256: 'f'.repeat(64), bytes: 6 }
  ];
}

test('deterministic generator and checker agree on the sealed closure', async () => {
  const left = await deriveSealedBytes();
  const right = await deriveSealedBytes();
  assert.equal(left.manifest.packageRoot, right.manifest.packageRoot);
  assert.equal(left.manifest.runtimeCore.runtimeEntrypoint, 'src/contracts.mjs');
  assert.equal(await checkSealedBytes(), true);
});

test('manifest closure rejects causal member, ordering, count, and classification mutants', () => {
  const input = records();
  const manifest = deriveManifest(input);
  assert.equal(manifest.entryCount, input.length);
  assert.equal(verifyManifest(manifest, input), true);

  const alteredMember = structuredClone(manifest);
  alteredMember.entries[0].bytes = 2;
  assert.throws(() => verifyManifest(alteredMember, input), /K_MANIFEST/);
  const alteredCount = structuredClone(manifest);
  alteredCount.entryCount -= 1;
  assert.throws(() => verifyManifest(alteredCount, input), /K_MANIFEST/);
  const alteredCore = structuredClone(manifest);
  alteredCore.runtimeCore.closureSha256 = '0'.repeat(64);
  assert.throws(() => verifyManifest(alteredCore, input), /K_MANIFEST/);
  assert.throws(() => deriveManifest([...input].reverse()), /artifact closure order/);
  assert.throws(() => deriveManifest([...input, { ...input[input.length - 1] }]), /artifact closure/);
  assert.throws(() => deriveManifest([{ locator: 'MANIFEST.json', sha256: 'a'.repeat(64), bytes: 1 }]), /K_MANIFEST/);
  assert.throws(() => deriveManifest([...input, { locator: 'src/%2e/escape.mjs', sha256: '0'.repeat(64), bytes: 1 }]), /K_LOCATOR/);
});
