import { checkSealedBytes } from './generate.mjs';

const invoked = process.argv[1] && import.meta.url === new URL(process.argv[1], `file://${process.cwd()}/`).href;
if (invoked) {
  checkSealedBytes().then(() => process.stdout.write('PASS K validation\n')).catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  });
}

export { checkSealedBytes };
