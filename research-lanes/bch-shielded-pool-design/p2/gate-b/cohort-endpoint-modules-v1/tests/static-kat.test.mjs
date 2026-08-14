/* KAT: package-byte and contract inspection only; endpoints are never imported. */
import assert from 'node:assert/strict';
import { assertClosedEndpointSource, parseCanonicalEndpointNdjson, validatePackage } from '../semantic-validator.mjs';

const result = validatePackage();
assert.equal(result.status, 'PASS');
assert.equal(result.outputCardinality, 4608);
assert.equal(result.native.endpointId, 'engine:native');
assert.equal(result.libauth.endpointId, 'engine:libauth');
assert.equal(result.libauth.sha256.length, 64);
const ids = Array.from({ length: 4608 }, (_, index) => `static-kat:${index}`);
const transcript = Buffer.from(ids.map(workItemId => JSON.stringify({ workItemId, verdict: 'accept', failureStage: 'accept', metrics: { operationCost: 1 }, txChecks: 'unsupported', phase: 'semantic-reference', terminalStatus: 'observed' })).join('\n') + '\n', 'utf8');
assert.equal(parseCanonicalEndpointNdjson(transcript, { engineId: 'engine:native', workItemIds: ids }).length, 4608);
assert.throws(() => parseCanonicalEndpointNdjson(Buffer.from(transcript.toString('utf8').replace('"operationCost":1', '"operationCost":1e999')), { engineId: 'engine:native', workItemIds: ids }), /finite metrics/);
assert.throws(() => parseCanonicalEndpointNdjson(Buffer.from(transcript.toString('utf8').replace('"workItemId":"static-kat:0",', '"workItemId":"static-kat:0","workItemId":"static-kat:0",')), { engineId: 'engine:native', workItemIds: ids }), /canonical JSON/);
assert.throws(() => parseCanonicalEndpointNdjson(Buffer.from(transcript.toString('utf8').replace(/[^\n]*\n$/u, '')), { engineId: 'engine:native', workItemIds: ids }), /output cardinality/);
assert.throws(() => assertClosedEndpointSource("import('node:fs')", 'mutation'), /import capability/);
assert.throws(() => assertClosedEndpointSource('new Function("return 1")', 'mutation'), /forbidden capability: Function/);
console.log(JSON.stringify({ status: 'PASS', kat: 'static-contract-byte-identities-parser-and-capability-policy' }));
