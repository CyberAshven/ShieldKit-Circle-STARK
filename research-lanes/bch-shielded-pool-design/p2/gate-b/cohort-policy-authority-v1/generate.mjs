import {fileURLToPath} from 'node:url';
import {findRepoRoot, seal, validatePackage} from './validate.mjs';
const mode = process.argv[2];
if (process.argv.length !== 3 || !['--check','--seal'].includes(mode)) throw new Error('usage: node generate.mjs --check|--seal');
const root = findRepoRoot(fileURLToPath(import.meta.url));
console.log(JSON.stringify(mode === '--check' ? validatePackage(undefined,root,{allowUnsealed:true}) : seal(undefined,root)));
