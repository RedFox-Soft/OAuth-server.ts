import { describe, it, expect } from 'bun:test';
import { Glob } from 'bun';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { ENVIRONMENT_VARIABLES } from 'lib/docs_export/environment.ts';

/*
 * The inventory is hand-written because a variable's meaning is not in the code that reads it. What
 * the code can prove is the set of names: every `process.env.X` under lib/ must be documented, and
 * nothing documented may have stopped being read.
 */
describe('environment variable inventory', () => {
	const libRoot = resolve(import.meta.dir, '../../lib');
	const referenced = new Set<string>();
	for (const rel of new Glob('**/*.{ts,tsx}').scanSync({ cwd: libRoot })) {
		const source = readFileSync(resolve(libRoot, rel), 'utf8');
		for (const match of source.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)) {
			referenced.add(match[1] as string);
		}
	}

	it('documents exactly the variables the server reads', () => {
		const documented = ENVIRONMENT_VARIABLES.map((v) => v.name).sort();
		expect(documented).toEqual([...referenced].sort());
	});

	it('gives every variable a description and a requirement', () => {
		for (const variable of ENVIRONMENT_VARIABLES) {
			expect(variable.description.length).toBeGreaterThan(20);
			expect(['required', 'optional', 'test-only']).toContain(
				variable.requirement
			);
		}
	});
});
