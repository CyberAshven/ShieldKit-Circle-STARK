import {fileURLToPath} from 'node:url';
import {seal, validatePackage} from './validate.mjs';

if (process.argv.length !== 3 || !['--check', '--seal'].includes(process.argv[2])) {
  throw new Error('usage: node generate.mjs --check|--seal');
}
console.log(JSON.stringify(process.argv[2] === '--check' ? validatePackage() : seal()));
