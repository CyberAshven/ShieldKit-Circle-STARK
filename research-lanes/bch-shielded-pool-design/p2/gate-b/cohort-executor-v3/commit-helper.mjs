/* Execute-only binding for the separately sealed renameat2 helper. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalBytes, digestRecord, omit } from '../cohort-execution-v3/contract.mjs';
import { readRegularFileNoFollow } from './durable-io.mjs';

export const COMMIT_HELPER_ROOT_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-commit-helper-v1';
export const COMMIT_HELPER_DESCRIPTOR_REL = `${COMMIT_HELPER_ROOT_REL}/helper-descriptor.v1.json`;
export const COMMIT_HELPER_BINARY_REL = `${COMMIT_HELPER_ROOT_REL}/renameat2-helper`;
const workspace = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../../../..');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-executor-v3 commit helper: ${message}`); };
const read = relative => readRegularFileNoFollow(workspace, relative);
const json = (relative, label) => { const opened = read(relative); const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(opened.bytes)); assert(canonicalBytes(value).equals(opened.bytes), `${label} canonical JSON`); return { opened, value }; };
const binding = (relative, opened, contentDigest = null) => ({ path: relative, realpath: opened.realpath, rawSha256: opened.rawSha256, byteLength: opened.byteLength, ...(contentDigest === null ? {} : { contentDigest }) });

/** Read all helper authority bytes with descriptor-relative O_NOFOLLOW reads. */
export function currentCommitHelperBinding() {
  const descriptor = json(COMMIT_HELPER_DESCRIPTOR_REL, 'descriptor'); const manifest = json(`${COMMIT_HELPER_ROOT_REL}/MANIFEST.json`, 'manifest'); const receipt = json(`${COMMIT_HELPER_ROOT_REL}/build-receipt.v1.json`, 'build receipt'); const checksums = read(`${COMMIT_HELPER_ROOT_REL}/SHA256SUMS`); const binary = read(COMMIT_HELPER_BINARY_REL); const source = read(`${COMMIT_HELPER_ROOT_REL}/renameat2-helper.S`);
  assert(descriptor.value.schema === 'shieldkit-labs/p2/gate-b/cohort-commit-helper-v1/descriptor/v1' && descriptor.value.helperId === 'renameat2-noreplace-dir-commit-x86_64-linux-v1' && descriptor.value.platform === 'linux-x86_64', 'descriptor identity');
  assert(descriptor.value.contentDigest?.domain === 'shieldkit-labs/p2/gate-b/cohort-commit-helper-v1/descriptor/root' && descriptor.value.contentDigest.value === digestRecord(omit(descriptor.value), descriptor.value.contentDigest.domain).value, 'descriptor digest');
  assert(canonicalBytes(descriptor.value.syscall).equals(canonicalBytes({ name: 'renameat2', number: 316, oldParentFd: 3, newParentFd: 4, flags: { RENAME_NOREPLACE: 1 } })), 'descriptor syscall');
  assert(canonicalBytes(descriptor.value.interface).equals(canonicalBytes({ argv: ['<executable>', '<old-basename>', '<new-basename>'], requiredInheritedFds: [3, 4, 5], basenameRules: { nonempty: true, rejectDot: true, rejectDotDot: true, rejectSlash: true }, stdio: { stdoutByteLength: 0, stderrByteLength: 0 }, exitCodes: { success: 0, existing: 17, crossDevice: 18, usageOrName: 64, otherErrno: 111 }, sourceValidation: { comparisonFields: ['st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid'], lookupFlags: 'AT_SYMLINK_NOFOLLOW', mismatchExit: 111, postRenameCheck: true, preRenameCheck: true, raceBoundary: 'cooperative-same-uid-namespace-name-check-not-atomic', retainedSourceFd: 5, sourceType: 'directory' } })), 'descriptor interface');
  assert(descriptor.value.binaryPath === 'renameat2-helper', 'helper binary path');
  assert(descriptor.value.sourceBinding?.path === 'renameat2-helper.S' && descriptor.value.sourceBinding.rawSha256 === source.rawSha256 && descriptor.value.sourceBinding.byteLength === source.byteLength, 'helper source binding');
  assert(receipt.value.output?.rawSha256 === binary.rawSha256 && receipt.value.output?.byteLength === binary.byteLength && receipt.value.contentDigest?.value === digestRecord(omit(receipt.value), receipt.value.contentDigest.domain).value, 'helper receipt binding');
  assert(manifest.value.contentDigest?.value === digestRecord(omit(manifest.value), manifest.value.contentDigest.domain).value && manifest.value.files.some(item => item.path === COMMIT_HELPER_BINARY_REL && item.rawSha256 === binary.rawSha256 && item.byteLength === binary.byteLength), 'helper manifest binary binding');
  const rows = [[manifest.opened.rawSha256, `${COMMIT_HELPER_ROOT_REL}/MANIFEST.json`], ...manifest.value.files.map(item => [item.rawSha256, item.path])]; assert(checksums.bytes.equals(Buffer.from(`${rows.map(row => row.join('  ')).join('\n')}\n`, 'utf8')), 'helper checksums');
  return Object.freeze({ descriptor: binding(COMMIT_HELPER_DESCRIPTOR_REL, descriptor.opened, descriptor.value.contentDigest), binary: binding(COMMIT_HELPER_BINARY_REL, binary), source: binding(`${COMMIT_HELPER_ROOT_REL}/renameat2-helper.S`, source), buildReceipt: binding(`${COMMIT_HELPER_ROOT_REL}/build-receipt.v1.json`, receipt.opened, receipt.value.contentDigest), manifest: binding(`${COMMIT_HELPER_ROOT_REL}/MANIFEST.json`, manifest.opened, manifest.value.contentDigest), checksums: binding(`${COMMIT_HELPER_ROOT_REL}/SHA256SUMS`, checksums), interface: descriptor.value.interface, syscall: descriptor.value.syscall });
}

/** The actual helper launch is intentionally deferred until runner integration
 * owns a complete success/failure transition. No arbitrary callback seam is
 * accepted: the future implementation must compare this binding against the
 * authorization's exact commitHelper field and inherit directory fds 3/4. */
export const COMMIT_HELPER_BOUNDARY = Object.freeze({ helperId: 'renameat2-noreplace-dir-commit-x86_64-linux-v1', inheritedDirectoryFds: [3, 4, 5], argv: ['<descriptor-bound-executable>', '<old-basename>', '<new-basename>'], noReplace: true, launchIntegrated: true, launchBoundary: 'execute-only-after-full-scratch-validation-and-before-final-path-revalidation', residualRaceBoundary: 'cooperative-same-uid-namespace-name-check-not-atomic' });
