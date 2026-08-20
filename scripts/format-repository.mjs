import { existsSync, lstatSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2];

if (!['check', 'write'].includes(mode) || process.argv.length !== 3) {
  process.stderr.write('repository-format: ARGUMENT_SET_INVALID\n');
  process.exitCode = 2;
} else {
  const inventory = spawnSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    {
      cwd: root,
      encoding: 'buffer',
      windowsHide: true,
    },
  );
  if (inventory.status !== 0 || inventory.error) {
    process.stderr.write('repository-format: INVENTORY_FAILED\n');
    process.exitCode = 2;
  } else {
    const files = inventory.stdout
      .toString('utf8')
      .split('\0')
      .filter(Boolean)
      .map((entry) => entry.replaceAll('\\', '/'))
      .filter((entry) => {
        if (entry === '.stage7/private' || entry.startsWith('.stage7/private/')) {
          process.stderr.write('repository-format: TRACKED_PRIVATE_PATH\n');
          process.exitCode = 2;
          return false;
        }
        const absolute = path.resolve(root, entry);
        return (
          absolute.startsWith(`${root}${path.sep}`) &&
          existsSync(absolute) &&
          lstatSync(absolute).isFile()
        );
      })
      .toSorted();

    if (process.exitCode === undefined) {
      const prettier = path.join(root, 'node_modules', 'prettier', 'bin', 'prettier.cjs');
      if (!existsSync(prettier)) {
        process.stderr.write('repository-format: PRETTIER_UNAVAILABLE\n');
        process.exitCode = 2;
      } else {
        const batchSize = 40;
        for (let offset = 0; offset < files.length; offset += batchSize) {
          const batch = files.slice(offset, offset + batchSize);
          const result = spawnSync(
            process.execPath,
            [prettier, mode === 'check' ? '--check' : '--write', '--ignore-unknown', ...batch],
            { cwd: root, stdio: 'inherit', windowsHide: true },
          );
          if (result.status !== 0 || result.error) {
            process.exitCode = result.status ?? 2;
            break;
          }
        }
        if (process.exitCode === undefined) {
          process.stdout.write(`repository-format: PASS (${files.length} files inventoried)\n`);
        }
      }
    }
  }
}
