import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

async function schema(name) {
  return JSON.parse(await readFile(new URL(`../schemas/${name}`, import.meta.url), 'utf8'));
}

test('schema KAT keeps dispatch, journal entry, and manifest closures exact', async () => {
  const dispatch = await schema('dispatch-plan.v1.schema.json');
  assert.deepEqual(dispatch.required.slice().sort(), ['dispatchPlanRoot', 'executionAllowed', 'rowRoot', 'workerRows']);
  assert.deepEqual(Object.keys(dispatch.properties).sort(), ['dispatchPlanRoot', 'executionAllowed', 'rowRoot', 'workerRows']);
  assert.equal(dispatch.properties.executionAllowed.const, false);

  const journal = await schema('evidence-journal.v1.schema.json');
  assert.equal(Object.hasOwn(journal.properties, 'dispatchPlanRoot'), true);
  assert.equal(Object.hasOwn(journal.properties, 'journalRoot'), true);
  const entry = await schema('journal-entry.v1.schema.json');
  assert.deepEqual(entry.required.slice().sort(), ['dispatchReceipt', 'entryRoot', 'eventRoot', 'journalKey', 'journalReceipt', 'kind', 'previousRoot', 'sequence']);

  const manifest = await schema('manifest.v1.schema.json');
  assert.equal(manifest.properties.entries.minItems >= 1, true);
  assert.equal(manifest.properties.entries.uniqueItems, true);
  assert.equal(manifest.properties.entries.items.additionalProperties, false);
  assert.deepEqual(manifest.properties.entries.items.required.slice().sort(), ['bytes', 'locator', 'sha256']);
  assert.equal(manifest.properties.entryCount.minimum, 1);
  assert.equal(manifest.properties.runtimeCore.additionalProperties, false);
});
