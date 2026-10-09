import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import '../test_helper.js';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { jwksRoutes } from 'lib/admin/jwks/routes.ts';
import { adminAuditStore, getBucketKeysStore } from 'lib/adapters/index.ts';
import {
	invalidateRootKeys,
	KEY_PUBLICATION_SECONDS,
	rootKeys
} from 'lib/keys/issuer_keys.ts';
import { ROOT_KEY_OWNER } from 'lib/consts/key_owner.ts';
import { generateJWKS } from 'lib/helpers/jwks.ts';
import type { SupportedAlg } from 'lib/admin/jwks/schema.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { send } from '../feature_gate/helpers.js';
import { testSigningKeys } from '../jwks/fixtures.js';
import { writeRootKeys } from '../root_keys.js';
import { shaped } from '../shape.js';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(jwksRoutes);

const PRIVATE_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];
const [bootRsa] = testSigningKeys;

const KeyView = Type.Object(
	{
		kid: Type.String(),
		alg: Type.String(),
		use: Type.String(),
		state: Type.String(),
		promotableAt: Type.Optional(Type.String()),
		removableAt: Type.Optional(Type.String())
	},
	{ additionalProperties: true }
);
const KeySet = Type.Object(
	{
		keys: Type.Array(KeyView),
		supportedAlgorithms: Type.Array(Type.String()),
		publicationSeconds: Type.Number()
	},
	{ additionalProperties: true }
);

async function call(
	method: string,
	path: string,
	cookie?: string,
	body?: unknown
) {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				'content-type': 'application/json',
				...(cookie ? { cookie } : {})
			},
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: (text ? JSON.parse(text) : {}) as Record<string, unknown>
	};
}

async function sessionCookieFor(kind: AdminKind) {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function view(cookie: string) {
	const res = await call('GET', '/admin/api/jwks', cookie);
	expect(res.status).toBe(200);
	return shaped(KeySet, res.body);
}

async function stateOf(cookie: string, kid: string) {
	return (await view(cookie)).keys.find((key) => key.kid === kid)?.state;
}

const generate = (cookie: string, alg: string) =>
	call('POST', '/admin/api/jwks', cookie, { alg });
const promote = (cookie: string, kid: string) =>
	call('POST', `/admin/api/jwks/${encodeURIComponent(kid)}/promote`, cookie);
const retire = (cookie: string, kid: string, confirm: string | null = kid) =>
	call(
		'DELETE',
		`/admin/api/jwks/${encodeURIComponent(kid)}`,
		cookie,
		confirm === null ? undefined : { confirm }
	);

/* Moves the clock forward by `seconds`, from the time it is called. */
function later(seconds: number) {
	const now = Date.now();
	spyOn(Date, 'now').mockReturnValue(now + seconds * 1000);
}

async function actions(targetId: string) {
	const { entries } = await adminAuditStore.list({ targetId });
	return entries.map((entry) => entry.action);
}

/* A generated key, past its publication window. */
async function publishedKey(cookie: string, alg: string) {
	const res = await generate(cookie, alg);
	expect(res.status).toBe(200);
	const kid = shaped(KeyView, res.body).kid;
	later(KEY_PUBLICATION_SECONDS + 1);
	return kid;
}

async function resetRootKeys() {
	await writeRootKeys(testSigningKeys);
	invalidateRootKeys();
	await rootKeys();
}

/**
 * @proves A super administrator rotates the root issuer's keys without a restart — a generated key is
 * published before it may sign, a promoted key signs in place of its predecessor in that algorithm, and
 * a key leaves service only when the retirement names it — while every step is audited before it takes
 * effect and nothing ever shows private key material.
 */
describe('the root key set, administered', () => {
	beforeEach(resetRootKeys);
	afterEach(() => {
		(Date.now as unknown as { mockRestore?: () => void }).mockRestore?.();
	});

	it('is refused to an anonymous caller', async () => {
		expect((await call('GET', '/admin/api/jwks')).status).toBe(401);
	});

	it('is refused to a project administrator', async () => {
		const { cookie } = await sessionCookieFor('plain');
		expect((await call('GET', '/admin/api/jwks', cookie)).status).toBe(403);
		expect((await generate(cookie, 'RS256')).status).toBe(403);
	});

	it('lists every root key with its state, and no private material', async () => {
		const { cookie } = await sessionCookieFor('super');
		const res = await call('GET', '/admin/api/jwks', cookie);
		const body = shaped(KeySet, res.body);

		expect(body.keys.map((key) => key.kid).sort()).toEqual(
			testSigningKeys.map((key) => key.kid).sort()
		);
		expect(body.keys.every((key) => key.state === 'signing')).toBe(true);
		expect(res.body).not.toHaveProperty('restartRequired');
		for (const key of body.keys) {
			for (const field of PRIVATE_FIELDS) {
				expect(key).not.toHaveProperty(field);
			}
		}
	});

	it('offers only algorithms it can actually produce a key for', async () => {
		const { cookie } = await sessionCookieFor('super');
		const { supportedAlgorithms } = await view(cookie);

		expect(supportedAlgorithms.length).toBeGreaterThan(0);
		for (const alg of supportedAlgorithms) {
			const {
				keys: [key]
			} = await generateJWKS(alg as SupportedAlg);
			const keyAlg: string = key.alg;
			expect(keyAlg).toBe(alg);
			expect(key.use).toBe('sig');
		}
	});

	it('refuses to generate a symmetric key', async () => {
		const { cookie } = await sessionCookieFor('super');
		expect((await generate(cookie, 'HS256')).status).toBe(422);
	});

	describe('generating', () => {
		it('publishes the new key without letting it sign', async () => {
			const { cookie } = await sessionCookieFor('super');

			const res = await generate(cookie, 'ES256');

			expect(res.status).toBe(200);
			const key = shaped(KeyView, res.body);
			expect(key.state).toBe('published');
			expect(key.promotableAt).toBeDefined();
			const root = await rootKeys();
			expect(root.publicJWKS.keys.map((k) => k.kid)).toContain(key.kid);
			const signingKids = [...root.signing].map((k) => k.kid);
			expect(signingKids).not.toContain(key.kid);
		});

		it('records the generation in the audit trail, naming the key', async () => {
			const { cookie } = await sessionCookieFor('super');
			const res = await generate(cookie, 'ES256');
			const { kid } = shaped(KeyView, res.body);

			expect(await actions(kid)).toContain('jwks.generate');
		});
	});

	describe('promoting', () => {
		it('is refused before the key has been published for the publication window', async () => {
			const { cookie } = await sessionCookieFor('super');
			const { kid } = shaped(KeyView, (await generate(cookie, 'RS256')).body);

			const res = await promote(cookie, kid);

			expect(res.status).toBe(409);
			expect(res.body.reason).toBe('too_soon');
			expect(res.body.promotableAt).toBeDefined();
		});

		it('is refused for the key that already signs', async () => {
			const { cookie } = await sessionCookieFor('super');

			const res = await promote(cookie, bootRsa.kid);

			expect(res.status).toBe(409);
			expect(res.body.reason).toBe('not_promotable');
		});

		it('makes the key sign, and returns the one it replaces in its algorithm to published', async () => {
			const { cookie } = await sessionCookieFor('super');
			const kid = await publishedKey(cookie, 'RS256');

			const res = await promote(cookie, kid);

			expect(res.status).toBe(200);
			expect(res.body.demoted).toBe(bootRsa.kid);
			expect(await stateOf(cookie, kid)).toBe('signing');
			expect(await stateOf(cookie, bootRsa.kid)).toBe('published');
		});

		it('advertises the algorithm of a promoted key the server did not boot with, without a restart', async () => {
			const { cookie } = await sessionCookieFor('super');
			const kid = await publishedKey(cookie, 'PS256');
			const before = shaped(
				Type.Object(
					{ id_token_signing_alg_values_supported: Type.Array(Type.String()) },
					{ additionalProperties: true }
				),
				await (
					await send('/.well-known/openid-configuration', { method: 'GET' })
				).json()
			);
			expect(before.id_token_signing_alg_values_supported).not.toContain(
				'PS256'
			);

			await promote(cookie, kid);

			const after = shaped(
				Type.Object(
					{ id_token_signing_alg_values_supported: Type.Array(Type.String()) },
					{ additionalProperties: true }
				),
				await (
					await send('/.well-known/openid-configuration', { method: 'GET' })
				).json()
			);
			expect(after.id_token_signing_alg_values_supported).toContain('PS256');
		});

		it('records the promotion in the audit trail, naming the key', async () => {
			const { cookie } = await sessionCookieFor('super');
			const kid = await publishedKey(cookie, 'RS256');

			await promote(cookie, kid);

			expect(await actions(kid)).toContain('jwks.promote');
		});

		it('answers 404 for a key the instance does not hold', async () => {
			const { cookie } = await sessionCookieFor('super');
			expect((await promote(cookie, 'no-such-kid')).status).toBe(404);
		});
	});

	describe('retiring', () => {
		for (const [label, confirm] of [
			['without a confirmation', null],
			['whose confirmation names another key', 'not-this-key']
		] as const) {
			it(`is refused ${label}, and nothing changes or is recorded`, async () => {
				const { cookie } = await sessionCookieFor('super');
				const { kid } = shaped(KeyView, (await generate(cookie, 'ES256')).body);

				const res = await retire(cookie, kid, confirm);

				expect(res.status).toBe(422);
				expect(res.body.reason).toBe('confirmation_mismatch');
				expect(await stateOf(cookie, kid)).toBe('published');
				expect(await actions(kid)).not.toContain('jwks.retire');
			});
		}

		it('is refused for the key that signs, so the server always keeps one', async () => {
			const { cookie } = await sessionCookieFor('super');

			const res = await retire(cookie, bootRsa.kid);

			expect(res.status).toBe(409);
			expect(res.body.reason).toBe('signing_key');
			expect(await stateOf(cookie, bootRsa.kid)).toBe('signing');
		});

		it('is refused for a key already retired', async () => {
			const { cookie } = await sessionCookieFor('super');
			const { kid } = shaped(KeyView, (await generate(cookie, 'ES256')).body);
			await retire(cookie, kid);

			const res = await retire(cookie, kid);

			expect(res.status).toBe(409);
			expect(res.body.reason).toBe('already_retired');
		});

		it('takes a confirmed key out of service with the time it will be hidden', async () => {
			const { cookie } = await sessionCookieFor('super');
			const { kid } = shaped(KeyView, (await generate(cookie, 'ES256')).body);

			const res = await retire(cookie, kid);

			expect(res.status).toBe(200);
			expect(res.body.state).toBe('retired');
			expect(res.body.removableAt).toBeDefined();
		});

		it('records the retirement in the audit trail, naming the key', async () => {
			const { cookie } = await sessionCookieFor('super');
			const { kid } = shaped(KeyView, (await generate(cookie, 'ES256')).body);

			await retire(cookie, kid);

			expect(await actions(kid)).toContain('jwks.retire');
		});
	});

	/*
	 * What the view reports against what the server actually does, after each step of a full rotation —
	 * the view is what an operator acts on, so it may never disagree with the key set.
	 */
	it('reports after every step exactly what the key set publishes and signs with', async () => {
		const { cookie } = await sessionCookieFor('super');
		const agree = async () => {
			const listed = (await view(cookie)).keys;
			invalidateRootKeys();
			const root = await rootKeys();
			const published = root.publicJWKS.keys.map((key) => key.kid).sort();
			const signing = [...root.signing].map((key) => String(key.kid)).sort();
			expect(listed.map((key) => key.kid).sort()).toEqual(published);
			expect(
				listed
					.filter((key) => key.state === 'signing')
					.map((key) => key.kid)
					.sort()
			).toEqual(signing);
		};

		const kid = await publishedKey(cookie, 'RS256');
		await agree();
		await promote(cookie, kid);
		await agree();
		await retire(cookie, bootRsa.kid);
		await agree();
		expect(
			(await getBucketKeysStore().find(ROOT_KEY_OWNER, bootRsa.kid))?.state
		).toBe('retired');
	});
});
