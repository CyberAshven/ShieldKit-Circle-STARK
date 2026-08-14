import { validatePackage } from './semantic-validator.mjs';

try { console.log(JSON.stringify(validatePackage())); }
catch (error) { console.error(JSON.stringify({ ok: false, error: error.message })); process.exitCode = 1; }
