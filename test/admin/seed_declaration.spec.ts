import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
	ADMIN_BUCKET_SEED,
	ADMIN_MCP_CLIENT_SEED,
	ADMIN_PROJECT_SEED,
	DEFAULT_BUCKET_SEED
} from 'lib/consts/admin_seed.js';

/*
 * One declaration, three seeders.
 *
 * `lib/admin/seed.ts` writes through the store abstractions and is test-only; `database/mongodb.ts`
 * writes raw documents because a one-shot script deliberately avoids the application's module graph;
 * the PostgreSQL script is the third. Their mechanisms differ legitimately and their values must not.
 *
 * This guard exists because the failure is silent and asymmetric: the suite exercises the copy
 * production never runs, so a seed change made in one place and not the other stays green forever and
 * only shows up as a deployment missing something. Both files used to carry a comment asking the next
 * author to remember the other one, which is the arrangement this replaces.
 */

const ROOT = resolve(import.meta.dir, '../..');

function source(path: string): string {
	return readFileSync(resolve(ROOT, path), 'utf8');
}

/* The values that would be re-inlined if somebody stopped importing the declaration. Drawn from the
 * declaration itself rather than typed out again, so this list cannot fall behind it. */
const SEEDED_LITERALS = [
	ADMIN_BUCKET_SEED.name,
	DEFAULT_BUCKET_SEED.name,
	ADMIN_PROJECT_SEED.name,
	ADMIN_PROJECT_SEED.slug,
	...ADMIN_MCP_CLIENT_SEED.redirectUris
];

describe('admin seed declaration', () => {
	const seeders = ['lib/admin/seed.ts', 'database/mongodb.ts'] as const;

	for (const path of seeders) {
		it(`${path} takes its values from the shared declaration`, () => {
			expect(source(path)).toContain('consts/admin_seed.js');
		});

		it(`${path} inlines none of the seeded values`, () => {
			const text = source(path);
			const inlined = SEEDED_LITERALS.filter((literal) =>
				text.includes(`'${literal}'`)
			);

			expect(inlined).toEqual([]);
		});
	}

	it('declares the reserved bucket closed to self-service registration', () => {
		// The one seeded value with a security consequence rather than a cosmetic one: an open admin
		// bucket would let anyone who can reach the console register themselves an operator account.
		expect(ADMIN_BUCKET_SEED.registrationOpen).toBe(false);
		expect(DEFAULT_BUCKET_SEED.registrationOpen).toBe(true);
	});

	it('keeps the reserved MCP client public with consent required', () => {
		// Public because a local agent has nowhere to keep a secret, and consent required because the
		// agent is acting for an administrator who should see what it asked for.
		expect(ADMIN_MCP_CLIENT_SEED.token_endpoint_auth_method).toBe('none');
		expect(ADMIN_MCP_CLIENT_SEED['consent.require']).toBe(true);
	});

	it('puts both reserved clients in the admin project', () => {
		// What routes them to the administrator bucket: resolveBucketForClient sends a client there only
		// if it belongs to a project whose bucket is the admin bucket. A client outside it falls through
		// to the default bucket and cannot authenticate an administrator at all.
		expect(ADMIN_PROJECT_SEED.clientIds).toContain(
			ADMIN_MCP_CLIENT_SEED.clientId
		);
		expect(ADMIN_PROJECT_SEED.bucketId).toBe(ADMIN_BUCKET_SEED._id);
	});
});
