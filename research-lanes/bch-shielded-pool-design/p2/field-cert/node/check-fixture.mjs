import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';

import {
  replayFrontierPrimeChecksFixture,
  replayM89X2PlusOneFixture
} from './replay.mjs';

const fail = (message) => {
  process.stderr.write(`FAIL ${message}\n`);
  process.exitCode = 1;
};

const [fixturePath, ...extraArguments] = process.argv.slice(2);
if (!fixturePath || extraArguments.length !== 0) {
  fail('usage: node check-fixture.mjs <fixture-path>');
} else {
  try {
    const schema = JSON.parse(readFileSync(new URL('../certificate.schema.json', import.meta.url), 'utf8'));
    const fixture = JSON.parse(readFileSync(resolve(fixturePath), 'utf8'));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    if (!validate(fixture)) {
      fail(`schema ${JSON.stringify(validate.errors)}`);
    } else {
      const replay = fixture.kind === 'mersenne-prime-check-fixture'
        ? replayFrontierPrimeChecksFixture
        : fixture.kind === 'rabin-irreducibility-fixture'
          ? replayM89X2PlusOneFixture
          : null;
      if (replay === null || !replay(fixture)) {
        fail('replay rejected fixture');
      } else {
        process.stdout.write(`PASS ${fixture.fixtureId} ${fixture.kind}\n`);
      }
    }
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
