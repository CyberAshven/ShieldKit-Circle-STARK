/* Frozen materialization check: static bytes only; no endpoint is imported. */
import { verifyMaterializationOnly } from './semantic-validator.mjs';

if (process.argv.length !== 3 || process.argv[2] !== '--check') throw new Error('usage: node materialize.mjs --check');
console.log(JSON.stringify(verifyMaterializationOnly()));
