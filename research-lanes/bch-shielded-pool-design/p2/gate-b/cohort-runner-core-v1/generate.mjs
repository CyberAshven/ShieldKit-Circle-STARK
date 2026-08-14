import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { deriveManifest, serializeManifest, verifyManifest } from './src/integrity.mjs';
import { canonicalJson, fail } from './src/strict.mjs';

const ROOT = new URL('./', import.meta.url);
const OMITTED = new Set(['MANIFEST.json', 'SHA256SUMS']);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function collect(url = ROOT, prefix = '') {
  const entries = await readdir(url, { withFileTypes: true });
  const result = [];
  for (const entry of entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))) {
    const locator = `${prefix}${entry.name}`;
    const child = new URL(`${encodeURIComponent(entry.name)}${entry.isDirectory() ? '/' : ''}`, url);
    if (entry.isDirectory()) {
      result.push(...await collect(child, `${locator}/`));
    } else if (entry.isFile()) {
      if (!OMITTED.has(locator)) {
        const bytes = await readFile(child);
        result.push(Object.freeze({ locator, sha256: sha256(bytes), bytes: bytes.length }));
      }
    } else {
      fail('K_TREE', `sealed tree has a non-regular member at ${locator}`);
    }
  }
  return result.sort((left, right) => (left.locator < right.locator ? -1 : left.locator > right.locator ? 1 : 0));
}

function sumText(records, manifestBytes) {
  const lines = records.map((record) => `${record.sha256}  ${record.locator}`);
  lines.push(`${sha256(manifestBytes)}  MANIFEST.json`);
  return `${lines.join('\n')}\n`;
}

export async function deriveSealedBytes() {
  const records = await collect();
  const manifest = deriveManifest(records);
  const manifestBytes = Buffer.from(serializeManifest(manifest), 'utf8');
  return Object.freeze({ records, manifest, manifestBytes, sumsBytes: Buffer.from(sumText(records, manifestBytes), 'utf8') });
}

export async function checkSealedBytes() {
  const sealed = await deriveSealedBytes();
  const manifestBytes = await readFile(new URL('MANIFEST.json', ROOT));
  const sumsBytes = await readFile(new URL('SHA256SUMS', ROOT));
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    fail('K_MANIFEST', 'MANIFEST.json is not JSON');
  }
  verifyManifest(manifest, sealed.records);
  if (!manifestBytes.equals(sealed.manifestBytes) || !sumsBytes.equals(sealed.sumsBytes)) {
    fail('K_MANIFEST', 'sealed bytes differ from deterministic derivation');
  }
  return true;
}

export async function sealStaticMetadata() {
  const sealed = await deriveSealedBytes();
  await writeFile(new URL('MANIFEST.json', ROOT), sealed.manifestBytes, { mode: 0o600 });
  await writeFile(new URL('SHA256SUMS', ROOT), sealed.sumsBytes, { mode: 0o600 });
  return canonicalJson({ manifestRoot: sealed.manifest.manifestRoot, packageRoot: sealed.manifest.packageRoot });
}

const invoked = process.argv[1] && import.meta.url === new URL(process.argv[1], `file://${process.cwd()}/`).href;
if (invoked) {
  const mode = process.argv[2];
  if (mode === '--seal') {
    sealStaticMetadata().then((result) => process.stdout.write(`${result}\n`)).catch((error) => {
      process.stderr.write(`${error.stack ?? error}\n`);
      process.exitCode = 1;
    });
  } else if (mode === '--check') {
    checkSealedBytes().then(() => process.stdout.write('PASS K sealed metadata\n')).catch((error) => {
      process.stderr.write(`${error.stack ?? error}\n`);
      process.exitCode = 1;
    });
  } else {
    process.stderr.write('usage: node generate.mjs --seal|--check\n');
    process.exitCode = 2;
  }
}
