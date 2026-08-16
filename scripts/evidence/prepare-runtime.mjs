#!/usr/bin/env node
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
mkdirSync(resolve(workspaceRoot, 'output/evidence/runtime'), { recursive: true });
