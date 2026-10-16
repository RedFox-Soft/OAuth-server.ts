import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { MAX_REQUEST_BODY_BYTES } from 'lib/consts/request_limits.ts';
import { call, createProject, idOf, tenant, type Caller } from './admin.ts';

function post(path: string, bytes: number) {
	return elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			// Set as a client on the wire sets it; a Request built in-process carries none until it is sent.
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				'content-length': String(bytes)
			},
			body: 'a'.repeat(bytes)
		})
	);
}

async function project(owner: Caller): Promise<string> {
	return idOf(
		await createProject(owner, {
			slug: `rb-${Math.random().toString(36).slice(2, 10)}`
		})
	);
}

/**
 * @proves One caller cannot make the server hold an unbounded body, store unbounded values, or generate keys
 * without end: a body over a mebibyte is refused before it is read, in the addressed surface's error shape;
 * over-long names and lists are refused on save; and a project holds at most twelve keys and makes at most twenty a
 * day, revoked ones counted.
 */
describe('bounds on what one caller can make the server hold', () => {
	let owner: Caller;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tenant_hardening' });
		await ensureAdminSeed();
		owner = await tenant();
	});

	describe('a request body', () => {
		it('is refused over the bound at a protocol endpoint, as an OAuth error', async () => {
			const response = await post('/token', MAX_REQUEST_BODY_BYTES + 1);

			expect(response.status).toBe(413);
			expect(await response.json()).toEqual({
				error: 'invalid_request',
				error_description: 'request body too large'
			});
		});

		it('is refused over the bound on the admin plane, as an admin error', async () => {
			const response = await post(
				'/admin/api/teams',
				MAX_REQUEST_BODY_BYTES + 1
			);

			expect(response.status).toBe(413);
			expect(await response.json()).toEqual({
				error: 'admin_error',
				message: 'request body too large'
			});
		});

		it('is read as usual at the bound', async () => {
			const response = await post('/token', MAX_REQUEST_BODY_BYTES);

			expect(response.status).not.toBe(413);
		});
	});

	describe('stored values', () => {
		it('refuses an over-long application name and over-long redirect lists', async () => {
			const id = await project(owner);
			const path = `/admin/api/projects/${id}/clients`;

			const longName = await call('POST', path, owner.cookie, {
				clientName: 'x'.repeat(101)
			});
			const manyRedirects = await call('POST', path, owner.cookie, {
				redirectUris: Array.from(
					{ length: 51 },
					(_, n) => `https://app.test/cb/${String(n)}`
				)
			});
			const longRedirect = await call('POST', path, owner.cookie, {
				redirectUris: [`https://app.test/${'p'.repeat(2000)}`]
			});
			const manyOrigins = await call('POST', path, owner.cookie, {
				corsOrigins: Array.from(
					{ length: 51 },
					(_, n) => `https://o${String(n)}.test`
				)
			});

			expect(longName.status).toBe(422);
			expect(manyRedirects.status).toBe(422);
			expect(longRedirect.status).toBe(422);
			expect(manyOrigins.status).toBe(422);
		});

		it('refuses an over-long identity provider name, scope list and domain list', async () => {
			const id = await project(owner);
			const path = `/admin/api/projects/${id}/federation`;
			const base = {
				id: 'corp',
				displayName: 'Corp',
				issuer: 'https://idp.test',
				clientId: 'c',
				clientSecret: 's'
			};

			const longName = await call('POST', path, owner.cookie, {
				...base,
				displayName: 'x'.repeat(101)
			});
			const manyScopes = await call('POST', path, owner.cookie, {
				...base,
				scopes: Array.from({ length: 51 }, (_, n) => `s${String(n)}`)
			});
			const manyDomains = await call('POST', path, owner.cookie, {
				...base,
				allowedEmailDomains: Array.from(
					{ length: 101 },
					(_, n) => `d${String(n)}.test`
				)
			});

			expect(longName.status).toBe(422);
			expect(manyScopes.status).toBe(422);
			expect(manyDomains.status).toBe(422);
		});
	});

	describe('signing keys', () => {
		interface KeyRefusal {
			message: string;
			reason?: string;
		}

		const generate = (id: string) =>
			call('POST', `/admin/api/projects/${id}/keys`, owner.cookie, {
				alg: 'ES256'
			});

		async function heldKids(id: string): Promise<string[]> {
			const listed = await call(
				'GET',
				`/admin/api/projects/${id}/keys`,
				owner.cookie
			);
			return (listed.body as { keys: { kid: string; state: string }[] }).keys
				.filter((key) => key.state === 'published')
				.map((key) => key.kid);
		}

		it('refuses a thirteenth held key, then a twenty-first made in a day though some were revoked', async () => {
			const id = await project(owner);

			let answer = await generate(id);
			for (let made = 0; made < 20 && answer.status === 201; made += 1) {
				answer = await generate(id);
			}
			expect(answer.status).toBe(409);
			expect((answer.body as KeyRefusal).message).toBe(
				'12 keys are already held: retire one before adding another'
			);

			// Every published key, so room to hold is not what runs out next.
			for (const kid of await heldKids(id)) {
				await call(
					'POST',
					`/admin/api/projects/${id}/keys/${kid}/revoke`,
					owner.cookie,
					{ confirm: kid }
				);
			}
			let more = await generate(id);
			for (let made = 0; made < 20 && more.status === 201; made += 1) {
				more = await generate(id);
			}

			expect(more.status).toBe(409);
			expect((more.body as KeyRefusal).message).toBe(
				'20 keys were made here in the last day: try again later'
			);
		});
	});
});
