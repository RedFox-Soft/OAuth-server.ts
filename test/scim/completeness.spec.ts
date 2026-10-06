import { describe, it, beforeAll, expect } from 'bun:test';

import { adminAuditStore } from 'lib/adapters/index.js';
import { isScimRoute } from 'lib/consts/scim.js';
import { elysia } from 'lib/index.js';
import bootstrap from '../test_helper.js';
import {
	connect,
	patchOf,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/* Every SCIM route the running server serves, bare and beneath a bucket. */
function mountedScimRoutes(): { method: string; path: string }[] {
	return elysia.routes
		.filter((route) => isScimRoute(route.path))
		.map((route) => ({ method: route.method, path: route.path }));
}

async function entriesFor(targetId: string): Promise<number> {
	const { total } = await adminAuditStore.list({ targetId, limit: 1 });
	return total;
}

/**
 * @proves Across the whole SCIM surface as mounted — not as anybody remembered to list it — every change is
 * audited exactly once, a refusal is audited never, and every error answers in SCIM's own shape with nothing
 * internal in it (spec 070, FR-020, FR-040; IPSIE AL SCIM §8).
 */
describe('the SCIM surface as mounted', () => {
	let c: Connected;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
	});

	async function freshUser(): Promise<string> {
		const res = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser(`m-${Math.random()}@contoso.com`)
		});
		return res.json.id as string;
	}

	/*
	 * A successful and a refused request for each mutating route. A route mounted without an entry here fails
	 * the guard below, which is the point: a new way to change a user must say how it is audited.
	 */
	const cases: Record<
		string,
		(
			base: string
		) => Promise<{ ok: () => Promise<string>; refused: () => Promise<string> }>
	> = {
		'POST /Users': async (base) => ({
			ok: async () =>
				(
					await scim('POST', `${base}/Users`, {
						token: c.token,
						body: scimUser(`ok-${Math.random()}@contoso.com`)
					})
				).json.id as string,
			refused: async () => {
				const taken = await freshUser();
				const userName = (
					await scim('GET', `${base}/Users/${taken}`, { token: c.token })
				).json.userName as string;
				await scim('POST', `${base}/Users`, {
					token: c.token,
					body: scimUser(userName)
				});
				return taken;
			}
		}),
		'PUT /Users/:userId': async (base) => ({
			ok: async () => {
				const id = await freshUser();
				const current = (
					await scim('GET', `${base}/Users/${id}`, { token: c.token })
				).json;
				await scim('PUT', `${base}/Users/${id}`, {
					token: c.token,
					body: { ...current, displayName: 'Changed' }
				});
				return id;
			},
			refused: async () => {
				const id = await freshUser();
				await scim('PUT', `${base}/Users/${id}`, {
					token: c.token,
					body: { userName: '' }
				});
				return id;
			}
		}),
		'PATCH /Users/:userId': async (base) => ({
			ok: async () => {
				const id = await freshUser();
				await scim('PATCH', `${base}/Users/${id}`, {
					token: c.token,
					body: patchOf([
						{ op: 'replace', path: 'displayName', value: 'Changed' }
					])
				});
				return id;
			},
			refused: async () => {
				const id = await freshUser();
				await scim('PATCH', `${base}/Users/${id}`, {
					token: c.token,
					body: patchOf([{ op: 'replace', path: 'id', value: 'x' }])
				});
				return id;
			}
		}),
		'DELETE /Users/:userId': async (base) => ({
			ok: async () => {
				const id = await freshUser();
				await scim('DELETE', `${base}/Users/${id}`, { token: c.token });
				return id;
			},
			refused: async () => {
				const id = await freshUser();
				await scim('DELETE', `${base}/Users/${id}`, { token: 'not-a-token' });
				return id;
			}
		})
	};

	it('for every mutating SCIM route, writes exactly one audit entry on success and none on refusal', async () => {
		const mutating = mountedScimRoutes().filter((r) => MUTATING.has(r.method));
		expect(mutating.length).toBeGreaterThan(0);
		for (const route of mutating) {
			const relative = route.path
				.replace(/^\/:bucket/, '')
				.replace('/scim/v2', '');
			const make = cases[`${route.method} ${relative}`];
			expect(
				make,
				`${route.method} ${route.path} has no audit case`
			).toBeDefined();
			const { ok, refused } = await make(c.base);

			const done = await ok();
			const refusedId = await refused();

			/* The create itself and the change: a fresh user's own creation is one entry already. */
			const expected = route.method === 'POST' ? 1 : 2;
			expect(await entriesFor(done), `${route.method} ${route.path}`).toBe(
				expected
			);
			expect(
				await entriesFor(refusedId),
				`${route.method} ${route.path} refused`
			).toBe(1);
		}
	});

	it('for every SCIM route, answers an error in the SCIM format with nothing internal in it', async () => {
		const routes = mountedScimRoutes();
		expect(routes.length).toBeGreaterThan(0);
		for (const route of routes) {
			const path = route.path
				.replace('/:bucket', `/${c.bucket.slug}`)
				.replace(':userId', 'nobody')
				.replace(':schemaId', 'nothing')
				.replace(':resourceTypeId', 'nothing');
			const res = await elysia.handle(
				new Request(`http://e.ly${path}`, { method: route.method })
			);
			const text = await res.text();

			/* 401 beneath a bucket that serves SCIM; 404 at the root here, which has no bucket record. */
			expect(
				res.status,
				`${route.method} ${route.path}`
			).toBeGreaterThanOrEqual(400);
			expect(res.headers.get('content-type')).toStartWith(
				'application/scim+json'
			);
			expect(JSON.parse(text)).toMatchObject({
				schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
				status: String(res.status)
			});
			expect(text).not.toMatch(/at \S+ \(|\.ts:\d+|stack/);
		}
	});
});
