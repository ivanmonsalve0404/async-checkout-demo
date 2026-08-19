import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import * as path from 'node:path';

export interface ReleaseArtifact {
  readonly path: string;
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly files: readonly string[];
}

const forbiddenName =
  /(^|\/)(?:\.env(?:\.|$)|node_modules|coverage|tests?|__tests__)(\/|$)|\.(?:map|pem|key)$/iu;

export function inspectReleaseArtifact(
  configuredPath: string,
  requiredFiles: readonly string[],
  kind: 'api' | 'worker' | 'web',
): ReleaseArtifact {
  const repositoryRoot = realpathSync(path.join(__dirname, '..', '..'));
  const candidate = path.resolve(process.cwd(), configuredPath);
  if (!existsSync(candidate) || !statSync(candidate).isDirectory()) {
    throw new Error(kind + ' release artifact directory does not exist: ' + candidate);
  }
  const resolved = realpathSync(candidate);
  const relativeToRepository = path.relative(repositoryRoot, resolved);
  if (
    relativeToRepository === '' ||
    relativeToRepository.startsWith('..' + path.sep) ||
    path.isAbsolute(relativeToRepository)
  ) {
    throw new Error(kind + ' release artifact must be a dedicated directory inside the repository');
  }

  const files = listFiles(resolved);
  for (const required of requiredFiles) {
    if (!files.includes(required))
      throw new Error(kind + ' release artifact is missing ' + required);
  }
  if (files.some((file) => forbiddenName.test(file))) {
    throw new Error(kind + ' release artifact contains forbidden development or secret files');
  }
  if (
    kind === 'web' &&
    !files.some((file) => /^assets\/[^/]+-[A-Za-z0-9_-]+\.(?:css|js)$/u.test(file))
  ) {
    throw new Error('web release artifact must contain content-hashed assets');
  }

  const hash = createHash('sha256');
  let sizeBytes = 0;
  for (const file of files) {
    const contents = readFileSync(path.join(resolved, ...file.split('/')));
    sizeBytes += contents.length;
    hash.update(file).update('\0').update(contents).update('\0');
  }
  return { path: resolved, sha256: hash.digest('hex'), sizeBytes, files };
}

function listFiles(directory: string, prefix = ''): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    const absolute = path.join(directory, entry.name);
    if (lstatSync(absolute).isSymbolicLink()) {
      throw new Error('release artifacts may not contain symbolic links');
    }
    const relative = prefix === '' ? entry.name : prefix + '/' + entry.name;
    if (entry.isDirectory()) files.push(...listFiles(absolute, relative));
    else if (entry.isFile()) files.push(relative);
  }
  return files;
}
