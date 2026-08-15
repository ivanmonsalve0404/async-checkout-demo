import { readdirSync, readFileSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import process from 'node:process';

const root = process.cwd();
const apiRoot = resolve(root, 'apps/api/src');
const sourceExtensions = new Set(['.ts', '.tsx']);
const forbidden = [
  {
    zone: join('apps', 'api', 'src', 'domain'),
    pattern: /from ['"](?:@nestjs\/|@aws-sdk\/|express|rxjs)/,
    reason: 'domain must not import frameworks, HTTP, RxJS, or AWS SDKs',
  },
  {
    zone: join('apps', 'api', 'src', 'application'),
    pattern: /from ['"](?:@nestjs\/|@aws-sdk\/|express)/,
    reason: 'application must not import transport or infrastructure frameworks',
  },
  {
    zone: join('apps', 'api', 'src', 'interfaces', 'http', 'controllers'),
    pattern: /from ['"].*(?:in-memory|dynamodb).*['"];/,
    reason: 'controllers must not import persistence adapters',
  },
];

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : sourceExtensions.has(extname(path)) ? [path] : [];
  });
}

const violations = [];
for (const file of files(apiRoot)) {
  const relativePath = relative(root, file);
  const source = readFileSync(file, 'utf8');
  for (const rule of forbidden) {
    if (relativePath.startsWith(rule.zone) && rule.pattern.test(source)) {
      violations.push(`${relativePath}: ${rule.reason}`);
    }
  }
}

if (violations.length > 0) {
  throw new Error(`Architecture boundary violations:\n${violations.join('\n')}`);
}
console.log('ARCHITECTURE_BOUNDARIES=PASS');
