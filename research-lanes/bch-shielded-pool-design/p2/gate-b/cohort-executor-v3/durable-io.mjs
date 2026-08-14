/* Linux descriptor-relative durable I/O for the execute-only opening. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-executor-v3 durable io: ${message}`); };
const { O_NOFOLLOW: noFollow, O_DIRECTORY: directory, O_RDONLY: readOnly, O_WRONLY: writeOnly, O_CREAT: create, O_EXCL: exclusive } = fs.constants;
assert(Number.isInteger(noFollow) && Number.isInteger(directory), 'Linux O_NOFOLLOW/O_DIRECTORY are required');
const close = fd => { if (fd !== null) fs.closeSync(fd); };
const name = value => { assert(typeof value === 'string' && value.length > 0 && value !== '.' && value !== '..' && !value.includes('/') && !value.includes('\\'), 'unsafe path component'); return value; };
const parts = relative => { assert(typeof relative === 'string' && relative.length > 0 && !path.isAbsolute(relative), 'relative path required'); return relative.split('/').map(name); };
const owner = () => typeof process.getuid === 'function' ? process.getuid() : null;

function assertOwnedDirectoryFd(fd, label) {
  const stat = fs.fstatSync(fd); assert(stat.isDirectory() && (!Number.isInteger(stat.nlink) || stat.nlink >= 1), `${label} not a directory`);
  assert((stat.mode & 0o777) === 0o700, `${label} mode is not 0700`); if (owner() !== null) assert(stat.uid === owner(), `${label} owner drift`); return stat;
}
function openAbsoluteDirectory(absoluteDirectory, { requireOwned = false } = {}) {
  assert(path.isAbsolute(absoluteDirectory), 'absolute directory required'); const root = path.parse(absoluteDirectory).root; let fd = fs.openSync(root, readOnly | directory | noFollow);
  try {
    for (const component of absoluteDirectory.slice(root.length).split('/').filter(Boolean).map(name)) { const child = fs.openSync(`/proc/self/fd/${fd}/${component}`, readOnly | directory | noFollow); close(fd); fd = child; }
    if (requireOwned) assertOwnedDirectoryFd(fd, absoluteDirectory); else assert(fs.fstatSync(fd).isDirectory(), `${absoluteDirectory} not a directory`); return fd;
  } catch (error) { close(fd); throw error; }
}
/** Retained descriptor variant for an inherited-fd child interface. The caller
 * owns the descriptor and must close it after the child has terminated. */
export function openDirectoryDescriptorNoFollow(absoluteDirectory, options = {}) { return openAbsoluteDirectory(absoluteDirectory, options); }
export function closeDescriptor(fd) { close(fd); }
export function fsyncDescriptor(fd) { fs.fsyncSync(fd); }
function openParentAndLeaf(absoluteFile) {
  assert(path.isAbsolute(absoluteFile), 'absolute file required'); return { parentFd: openAbsoluteDirectory(path.dirname(absoluteFile)), leaf: name(path.basename(absoluteFile)) };
}
function readAllFd(fd, byteLength) { const output = Buffer.alloc(byteLength); let offset = 0; while (offset < output.length) { const count = fs.readSync(fd, output, offset, output.length - offset, offset); assert(count > 0, 'short descriptor read'); offset += count; } return output; }

/** Component-wise O_NOFOLLOW read; returned bytes/hash share a final inode fd. */
export function readRegularFileNoFollow(rootDirectory, relative) {
  let parentFd = openAbsoluteDirectory(rootDirectory); let fd = null; const components = parts(relative);
  try {
    for (let index = 0; index < components.length; index += 1) { const component = components[index]; const child = fs.openSync(`/proc/self/fd/${parentFd}/${component}`, readOnly | noFollow | (index === components.length - 1 ? 0 : directory)); close(parentFd); parentFd = child; }
    fd = parentFd; parentFd = null; const before = fs.fstatSync(fd); assert(before.isFile() && (!Number.isInteger(before.nlink) || before.nlink === 1) && Number.isSafeInteger(before.size) && before.size >= 0, `regular single-link authority file ${relative}`);
    const bytes = readAllFd(fd, before.size); const after = fs.fstatSync(fd); assert(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.nlink === after.nlink, `authority file changed while reading ${relative}`);
    return Object.freeze({ bytes, rawSha256: sha(bytes), byteLength: bytes.length, realpath: fs.realpathSync(`/proc/self/fd/${fd}`), stat: Object.freeze({ dev: before.dev, ino: before.ino, nlink: before.nlink, size: before.size }) });
  } finally { close(fd); close(parentFd); }
}

/** Open and hash an absolute regular file through a no-follow parent walk,
 * retaining the exact inode descriptor for a later exec-via-/proc/self/fd. */
export function openRegularFileDescriptorNoFollow(absoluteFile) {
  const { parentFd, leaf } = openParentAndLeaf(absoluteFile); let fd = null;
  try {
    fd = fs.openSync(`/proc/self/fd/${parentFd}/${leaf}`, readOnly | noFollow); const before = fs.fstatSync(fd);
    assert(before.isFile() && (!Number.isInteger(before.nlink) || before.nlink === 1) && Number.isSafeInteger(before.size) && before.size >= 0, `regular single-link executable ${absoluteFile}`);
    const bytes = readAllFd(fd, before.size); const after = fs.fstatSync(fd);
    assert(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.nlink === after.nlink, `executable changed while reading ${absoluteFile}`);
    return Object.freeze({ fd, bytes, rawSha256: sha(bytes), byteLength: bytes.length, realpath: fs.realpathSync(`/proc/self/fd/${fd}`), stat: Object.freeze({ dev: before.dev, ino: before.ino, nlink: before.nlink, size: before.size }) });
  } catch (error) { close(fd); throw error; } finally { close(parentFd); }
}

export function fsyncDirectory(absoluteDirectory) { const fd = openAbsoluteDirectory(absoluteDirectory); try { fs.fsyncSync(fd); } finally { close(fd); } }

function createDirectoryAt(parentFd, leaf, label) {
  try { fs.mkdirSync(`/proc/self/fd/${parentFd}/${leaf}`, { mode: 0o700 }); } catch (error) { throw new Error(`cohort-executor-v3 durable io: ${label}: ${error.code ?? error.message}`); }
  const child = fs.openSync(`/proc/self/fd/${parentFd}/${leaf}`, readOnly | directory | noFollow); try { assertOwnedDirectoryFd(child, label); fs.fsyncSync(child); } finally { close(child); } fs.fsyncSync(parentFd);
}

/** Create (once) or verify the exact 0700 empty external run base after the
 * exclusive claim exists. It never chmods or adopts an arbitrary directory. */
export function ensureExactOwnedEmptyRunBase(absoluteRunBase) {
  assert(path.isAbsolute(absoluteRunBase), 'absolute run base'); const parent = path.dirname(absoluteRunBase); const leaf = path.basename(absoluteRunBase); let parentFd = openAbsoluteDirectory(parent);
  try {
    try { createDirectoryAt(parentFd, leaf, 'external run base'); }
    catch (error) {
      if (!String(error.message).includes('EEXIST')) throw error;
      const existingFd = fs.openSync(`/proc/self/fd/${parentFd}/${leaf}`, readOnly | directory | noFollow);
      try { assertOwnedDirectoryFd(existingFd, 'preexisting external run base'); assert(fs.readdirSync(`/proc/self/fd/${existingFd}`).length === 0, 'preexisting external run base is not empty'); } finally { close(existingFd); }
    }
    const baseFd = fs.openSync(`/proc/self/fd/${parentFd}/${leaf}`, readOnly | directory | noFollow);
    try { assertOwnedDirectoryFd(baseFd, 'external run base'); assert(fs.readdirSync(`/proc/self/fd/${baseFd}`).length === 0, 'external run base is not empty'); fs.fsyncSync(baseFd); } finally { close(baseFd); }
    fs.fsyncSync(parentFd); return absoluteRunBase;
  } finally { close(parentFd); }
}

/** Descriptor-safe private directory creation/verification. Existing
 * directories are never chmodded or adopted: ownership, mode, and (when
 * supplied) the complete immediate namespace must already be exact. */
export function ensureExactOwnedDirectory(absoluteDirectory, { expectedEntries = null } = {}) {
  assert(path.isAbsolute(absoluteDirectory), 'absolute owned directory'); const parent = path.dirname(absoluteDirectory); const leaf = path.basename(absoluteDirectory); let parentFd = openAbsoluteDirectory(parent);
  try {
    try { createDirectoryAt(parentFd, leaf, 'owned directory'); }
    catch (error) { if (!String(error.message).includes('EEXIST')) throw error; }
    const childFd = fs.openSync(`/proc/self/fd/${parentFd}/${leaf}`, readOnly | directory | noFollow);
    try {
      assertOwnedDirectoryFd(childFd, absoluteDirectory);
      if (expectedEntries !== null) {
        assert(Array.isArray(expectedEntries) && expectedEntries.every(item => typeof item === 'string'), 'expected directory entries');
        const actual = fs.readdirSync(`/proc/self/fd/${childFd}`).sort(); const expected = [...expectedEntries].sort();
        assert(JSON.stringify(actual) === JSON.stringify(expected), `owned directory namespace ${absoluteDirectory}`);
      }
      fs.fsyncSync(childFd);
    } finally { close(childFd); }
    fs.fsyncSync(parentFd); return absoluteDirectory;
  } finally { close(parentFd); }
}

/** Creates one new 0700 same-device scratch leaf under an already-authenticated 0700 parent. */
export function createScratchDirectory(absoluteScratchRoot, outputParent) {
  assert(path.isAbsolute(absoluteScratchRoot) && path.dirname(absoluteScratchRoot) === outputParent, 'exact scratch parent'); const parentFd = openAbsoluteDirectory(outputParent, { requireOwned: true });
  try { assert(!fs.existsSync(absoluteScratchRoot), `scratch already exists ${absoluteScratchRoot}`); createDirectoryAt(parentFd, path.basename(absoluteScratchRoot), 'scratch root'); const scratchFd = fs.openSync(`/proc/self/fd/${parentFd}/${path.basename(absoluteScratchRoot)}`, readOnly | directory | noFollow); try { const scratch = assertOwnedDirectoryFd(scratchFd, 'scratch root'); const parent = fs.fstatSync(parentFd); assert(scratch.dev === parent.dev, 'scratch/output parent cross-device'); return Object.freeze({ path: absoluteScratchRoot, device: scratch.dev, mode: 0o700 }); } finally { close(scratchFd); } } finally { close(parentFd); }
}
export function createScratchSubdirectory(absoluteDirectory) { const { parentFd, leaf } = openParentAndLeaf(absoluteDirectory); try { createDirectoryAt(parentFd, leaf, 'scratch subdirectory'); return absoluteDirectory; } finally { close(parentFd); } }
export function assertOwnedDirectoryNoFollow(absoluteDirectory) { const fd = openAbsoluteDirectory(absoluteDirectory, { requireOwned: true }); try { return true; } finally { close(fd); } }

function openExclusiveAt(parentFd, leaf, mode) { const fd = fs.openSync(`/proc/self/fd/${parentFd}/${leaf}`, writeOnly | create | exclusive | noFollow, mode); fs.fchmodSync(fd, mode); return fd; }
function writeAll(fd, bytes) { let offset = 0; while (offset < bytes.length) { const count = fs.writeSync(fd, bytes, offset, bytes.length - offset); assert(count > 0, 'short descriptor write'); offset += count; } }

/** Descriptor-relative O_EXCL/O_NOFOLLOW 0600 writer, fsyncing the same parent fd. */
export function writeExclusiveFileNoFollow(absoluteFile, bytes, { mode = 0o600 } = {}) {
  assert(Buffer.isBuffer(bytes) && mode === 0o600, '0600 Buffer write required'); const { parentFd, leaf } = openParentAndLeaf(absoluteFile); assertOwnedDirectoryFd(parentFd, path.dirname(absoluteFile)); let fd = null;
  try { fd = openExclusiveAt(parentFd, leaf, mode); writeAll(fd, bytes); fs.fsyncSync(fd); const stat = fs.fstatSync(fd); assert(stat.isFile() && stat.size === bytes.length && (!Number.isInteger(stat.nlink) || stat.nlink === 1) && (stat.mode & 0o777) === mode, 'exclusive file postcondition'); } finally { close(fd); fs.fsyncSync(parentFd); close(parentFd); }
  return Object.freeze({ path: absoluteFile, rawSha256: sha(bytes), byteLength: bytes.length, mode });
}

/** Pre-opened capture file with an incremental SHA-256: no pathname reread occurs at close. */
export function openCaptureSlot(absoluteFile, { capBytes, fsyncEachAppend = false }) {
  assert(Number.isSafeInteger(capBytes) && capBytes >= 0, 'capture cap'); const { parentFd, leaf } = openParentAndLeaf(absoluteFile); assertOwnedDirectoryFd(parentFd, path.dirname(absoluteFile)); const fd = openExclusiveAt(parentFd, leaf, 0o600); const hash = crypto.createHash('sha256'); let byteLength = 0; let closed = false;
  const append = chunk => { assert(!closed && Buffer.isBuffer(chunk), 'capture append'); assert(byteLength + chunk.length <= capBytes, `capture cap exceeded ${absoluteFile}`); writeAll(fd, chunk); hash.update(chunk); byteLength += chunk.length; if (fsyncEachAppend) fs.fsyncSync(fd); };
  const closeDurably = () => { assert(!closed, 'capture already closed'); closed = true; try { fs.fsyncSync(fd); const stat = fs.fstatSync(fd); assert(stat.size === byteLength && stat.isFile() && (!Number.isInteger(stat.nlink) || stat.nlink === 1), 'capture close postcondition'); } finally { close(fd); fs.fsyncSync(parentFd); close(parentFd); } return Object.freeze({ path: absoluteFile, byteLength, rawSha256: hash.digest('hex'), fsynced: true }); };
  const finish = () => closeDurably();
  /* A controller may exhaust its bounded termination sequence without a
   * child close event. Preserve the byte prefix already appended to this
   * descriptor instead of deleting it or rereading a pathname. The caller
   * records the resulting stream as partial and the lifecycle as unclosed. */
  const sealPartial = () => closeDurably();
  const abort = () => { if (!closed) { closed = true; close(fd); fsyncSyncSafe(parentFd); close(parentFd); } };
  return Object.freeze({ append, finish, sealPartial, abort, get byteLength() { return byteLength; } });
}

/** Remove only newly-created scratch capture leaves through their already
 * component-checked parent. This is used when child creation never reached a
 * process lifecycle (spawn throw/error), so the sealed failure representation
 * has three unavailable stream slots rather than unbound empty files. */
export function removeScratchLeavesNoFollow(absoluteDirectory, leaves) {
  assert(Array.isArray(leaves) && leaves.length > 0, 'scratch leaves required'); const parentFd = openAbsoluteDirectory(absoluteDirectory, { requireOwned: true });
  try {
    for (const leafValue of leaves) {
      const leaf = name(leafValue); let fd = null;
      try {
        fd = fs.openSync(`/proc/self/fd/${parentFd}/${leaf}`, readOnly | noFollow);
        const stat = fs.fstatSync(fd); assert(stat.isFile() && (!Number.isInteger(stat.nlink) || stat.nlink === 1), `scratch leaf ${leaf}`);
      } finally { close(fd); }
      fs.unlinkSync(`/proc/self/fd/${parentFd}/${leaf}`);
    }
    fs.fsyncSync(parentFd);
  } finally { close(parentFd); }
}

function fsyncSyncSafe(fd) { try { fs.fsyncSync(fd); } catch { /* an abort is deliberately not a durable capture */ } }

/**
 * No Node rename API supplies RENAME_NOREPLACE. Production commit remains
 * gated on an independently pinned helper. The test seam is separate so a
 * caller cannot select an arbitrary commit callback in executeAuthorizedAttempt.
 */
export function requirePinnedNoReplaceDirectoryCommit({ scratchRoot, destinationRoot }) {
  assert(path.isAbsolute(scratchRoot) && path.isAbsolute(destinationRoot) && fs.statSync(scratchRoot).isDirectory() && !fs.existsSync(destinationRoot), 'no-replace commit precondition');
  assert(fs.statSync(scratchRoot).dev === fs.statSync(path.dirname(destinationRoot)).dev, 'commit cross-device');
  throw new Error('cohort-executor-v3 durable io: pinned Linux renameat2(RENAME_NOREPLACE) helper is not integrated');
}
export function testOnlyNoReplaceDirectoryCommit({ scratchRoot, destinationRoot, nativeCommit }) { assert(typeof nativeCommit === 'function', 'test native commit required'); assert(!fs.existsSync(destinationRoot), 'test destination exists'); return nativeCommit({ scratchRoot, destinationRoot }); }
