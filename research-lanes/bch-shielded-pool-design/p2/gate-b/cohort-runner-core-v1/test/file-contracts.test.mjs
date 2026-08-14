import assert from 'node:assert/strict';
import test from 'node:test';
import { exclusiveClaimStorageContract, privateStorageContract, requireArtifactLocator, requireClosedLocator, requireDisjointLocators, requireStorageInspection } from '../src/file-contracts.mjs';

test('closed locator and private storage KAT', () => {
  assert.equal(requireClosedLocator('capture-001', 'KAT'), 'capture-001');
  assert.equal(requireArtifactLocator('src/contracts.mjs', 'KAT'), 'src/contracts.mjs');
  assert.deepEqual(requireDisjointLocators(['capture-001', 'terminal-001']), ['capture-001', 'terminal-001']);
  for (const mutant of ['', '.', '..', '../escape', '/absolute', 'a/b', 'a\\b', '%2e', '%2f', '%5c', 'a..b', 'a.']) {
    assert.throws(() => requireClosedLocator(mutant, 'KAT'), /K_LOCATOR/);
  }
  for (const mutant of ['', '/absolute', 'src//contracts.mjs', 'src/../contracts.mjs', 'src/%2e/contracts.mjs', 'src/%2f/contracts.mjs', 'src\\contracts.mjs']) {
    assert.throws(() => requireArtifactLocator(mutant, 'KAT'), /K_LOCATOR/);
  }
  assert.throws(() => requireDisjointLocators(['same', 'same']), /K_LOCATOR_SET/);
  const contract = privateStorageContract();
  assert.equal(contract.privateDirectoryMode, '0700');
  assert.deepEqual(contract.openFlags, ['O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_CLOEXEC']);
  assert.equal(contract.terminalProtocol.flag, 'RENAME_NOREPLACE');
  const claimContract = exclusiveClaimStorageContract();
  assert.equal(claimContract.primitive, 'openat');
  assert.equal(claimContract.creation.noFollow, true);
  assert.throws(() => requireStorageInspection({
    locator: 'capture-001', kind: 'regular', linkCount: 2, mode: '0600', noFollow: true, noReplace: true
  }), /K_STORAGE/);
});
