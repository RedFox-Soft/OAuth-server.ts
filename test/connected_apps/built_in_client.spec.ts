import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { addons } from 'lib/addon/index.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { addressedBucket, defaultBucket } from './helpers.ts';

const CALLBACK = `${ISSUER}/acme/account/apps/callback`;

async function call(url: string, init: RequestInit = {}): Promise<Response> {
	return elysia.handle(new Request(url, { redirect: 'manual', ...init }));
}

function authorize(origin: string, params: Record<string, string>) {
	return call(`${origin}/auth?${new URLSearchParams(params).toString()}`);
}

function errorOf(res: Response): string | null {
	return new URL(res.headers.get('location') ?? 'http://x/').searchParams.get(
		'error'
	);
}

function tokenRequest(fields: Record<string, string>) {
	return call(`${ISSUER}/acme/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams(fields).toString()
	});
}

/**
 * @proves The client a bucket's page signs people in through can do nothing but bring them back: it obtains
 * no code and no token, is refused at any other bucket's address, does not exist for the administrators' bucket
 * or one switched off, and no registration can take its name.
 */
describe('the page’s own sign-in client', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'connected_apps' });
		await ensureAdminSeed();
		await defaultBucket();
		await addressedBucket('acme-bucket', { slug: 'acme' });
		await addressedBucket('beta-bucket', { host: 'beta.example.test' });
	});

	it('is refused an authorization code', async () => {
		const res = await authorize(`${ISSUER}/acme`, {
			client_id: 'account.acme-bucket',
			response_type: 'code',
			scope: 'openid',
			redirect_uri: CALLBACK,
			state: 's',
			code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
			code_challenge_method: 'S256'
		});

		expect(res.headers.get('location') ?? '').not.toContain('code=');
		expect(errorOf(res)).toBe('invalid_request');
	});

	it('is refused at the token endpoint', async () => {
		const res = await tokenRequest({
			grant_type: 'authorization_code',
			client_id: 'account.acme-bucket',
			code: 'anything',
			code_verifier: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
			redirect_uri: CALLBACK
		});

		expect(res.status).toBe(400);
		expect(await res.json()).toMatchObject({ error: 'unauthorized_client' });
	});

	it('is refused at another bucket’s address', async () => {
		const res = await authorize('http://beta.example.test', {
			client_id: 'account.acme-bucket',
			response_type: 'none',
			scope: 'openid',
			redirect_uri: CALLBACK,
			state: 's'
		});

		expect(errorOf(res)).toBe('unauthorized_client');
	});

	it('does not exist for the administrators’ bucket', async () => {
		const res = await authorize(ISSUER, {
			client_id: 'account.admin',
			response_type: 'none',
			scope: 'openid',
			redirect_uri: `${ISSUER}/account/apps/callback`,
			state: 's'
		});

		expect(res.status).toBe(400);
		expect(await res.json()).toMatchObject({ error: 'invalid_client' });
	});

	it('does not exist for a bucket that does not exist', async () => {
		const res = await authorize(`${ISSUER}/acme`, {
			client_id: 'account.no-such-bucket',
			response_type: 'none',
			scope: 'openid',
			redirect_uri: CALLBACK,
			state: 's'
		});

		expect(res.status).toBe(400);
		expect(await res.json()).toMatchObject({ error: 'invalid_client' });
	});

	it('does not exist for a bucket scheduled for deletion', async () => {
		await getBucketStore().create({
			_id: 'doomed-bucket',
			name: 'doomed',
			ownerGroupId: 'unassigned'
		});
		await getBucketStore().scheduleDeletion('doomed-bucket', {
			scheduledAt: new Date(),
			purgeAt: new Date(Date.now() + 86_400_000),
			scheduledBy: { userId: 'someone' }
		});

		const res = await authorize(ISSUER, {
			client_id: 'account.doomed-bucket',
			response_type: 'none',
			scope: 'openid',
			redirect_uri: `${ISSUER}/account/apps/callback`,
			state: 's'
		});

		expect(res.status).toBe(400);
		expect(await res.json()).toMatchObject({ error: 'invalid_client' });
	});

	it('cannot be taken by a registration, even through a deployment’s own id factory', async () => {
		addons.override({ idFactory: () => 'account.redfox' });

		const res = await call(`${ISSUER}/reg`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://x.test/cb'] })
		});

		expect(res.status).toBe(400);
		expect(await res.json()).toMatchObject({
			error: 'invalid_client_metadata'
		});
	});
});
