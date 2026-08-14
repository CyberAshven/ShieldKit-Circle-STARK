/* Full static package check: no endpoint import/evaluation and no process launch. */
import { validatePackage } from './semantic-validator.mjs';

console.log(JSON.stringify(validatePackage()));
