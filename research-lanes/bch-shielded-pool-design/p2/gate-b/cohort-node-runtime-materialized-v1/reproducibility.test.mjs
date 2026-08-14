import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { imagePath, validateAll } from './semantic-validators.mjs';

test('sealed Node image is statically reproducible and unqualified', () => {
  const result = validateAll();
  assert.equal(result.materialization.ok, true);
  assert.equal(result.source.ok, true);
  assert.equal(result.image.ok, true);
  assert.equal(result.manifest.ok, true);
  assert.equal(JSON.parse(fs.readFileSync(imagePath('runtime-image.v1.json'))).executionAllowed, false);
});
