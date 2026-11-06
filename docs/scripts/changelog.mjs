import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = readFileSync(join(root, '..', 'CHANGELOG.md'), 'utf8');
const body = source.replace(/^# Changelog\s*/, '');
const page = `---
title: Changelog
description: Notable changes to BoxKernel.
editUrl: false
lastUpdated: false
---

${body}`;
writeFileSync(join(root, 'src/content/docs/changelog.md'), page);
