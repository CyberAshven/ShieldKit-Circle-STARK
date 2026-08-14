import { validateAll } from './semantic-validators.mjs';

try {
  const result = validateAll();
  console.log(JSON.stringify({ ok: true, result }));
} catch (error) {
  console.error(JSON.stringify({ ok: false, error: error.message }));
  process.exitCode = 1;
}
