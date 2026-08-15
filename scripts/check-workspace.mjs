import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import process from 'node:process';

const root = process.cwd();
const manifest = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const required = [
  'apps/web/package.json',
  'apps/api/package.json',
  'packages/contracts/package.json',
  'infra/package.json',
];

if (process.version !== 'v24.19.0') {
  throw new Error(`Node must be v24.19.0; received ${process.version}`);
}
if (manifest.packageManager !== 'pnpm@11.19.0') {
  throw new Error('packageManager must remain pnpm@11.19.0');
}
for (const file of required) {
  readFileSync(resolve(root, file));
}
if (!process.env.npm_config_user_agent?.startsWith('pnpm/11.19.0')) {
  throw new Error('Run workspace checks through pnpm 11.19.0');
}

console.log('WORKSPACE_CHECK=PASS');
