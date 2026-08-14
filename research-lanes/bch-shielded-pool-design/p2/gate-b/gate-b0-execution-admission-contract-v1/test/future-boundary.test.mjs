import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertRootSemantics } from '../validate-static.mjs';

const here=dirname(fileURLToPath(import.meta.url));
const root=JSON.parse(readFileSync(resolve(here,'../execution-admission-contract-root.v1.json'),'utf8'));
const clone=()=>JSON.parse(JSON.stringify(root));
let negatives=0;
for(let i=0;i<root.externalRequirements.length;i+=1){const value=clone();value.externalRequirements[i].instanceCount=1;let failed=false;try{assertRootSemantics(value);}catch(error){failed=String(error.message).startsWith('EXTERNAL_REQUIREMENT_ROSTER');}if(!failed)throw new Error(`REQUIREMENT_NEGATIVE:${i}`);negatives+=1;}
if(negatives!==30)throw new Error('FUTURE_BOUNDARY_COUNT');
console.log(`PASS future-boundary negatives=${negatives} instances=0`);
