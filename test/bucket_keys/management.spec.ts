import { afterEach, beforeAll, describe, expect, it, spyOn } from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getProjectStore } from 'lib/adapters/index.ts';
import {
	KEY_PUBLICATION_SECONDS,
	RETIRED_KEY_LIFETIME_SECONDS
} from 'lib/keys/issuer_keys.ts';
import { administrator, call, listed, ownedBucket } from './keys_admin.ts';

async function publishedKids(slug: string) {
	const response = await elysia.handle(new Request(`${ISSUER}/${slug}/jwks`));
	const { keys } = (await response.json()) as { keys: Array<{ kid: string }> };
	return keys.map((key) => key.kid);
}

/* Moves the clock forward by `seconds`, from the time it is called. */
function later(seconds: number) {
	const now = Date.now();
	spyOn(Date, 'now').mockReturnValue(now + seconds * 1000);
}

async function generate(bucketId: string, cookie: string, alg: string) {
	return call('POST', `/admin/api/buckets/${bucketId}/keys`, cookie, { alg });
}

async function promote(bucketId: string, cookie: string, kid: string) {
	return call(
		'POST',
		`/admin/api/buckets/${bucketId}/keys/${encodeURIComponent(kid)}/promote`,
		cookie
	);
}

async function retire(
	bucketId: string,
	cookie: string,
	kid: string,
	// null sends no body at all; a default parameter would stand in for an explicit undefined.
	confirm: string | null = kid
) {
	return call(
		'DELETE',
		`/admin/api/buckets/${bucketId}/keys/${encodeURIComponent(kid)}`,
		cookie,
		confirm === null ? undefined : { confirm }
	);
}

/**
 * @proves The administrator of a bucket's owning group rotates its keys end to end — a new key is
 * published before it may sign, the key it replaces keeps verifying, and a retired key stays published
 * until every token it signed has expired — and no step can leave the bucket unable to sign in an
 * algorithm its clients require; every step is audited before it takes effect.
 */
describe('the owning group administrator', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'bucket_keys' });
		await ensureAdminSeed();
	});

	afterEach(() => {
		(Date.now as unknown as { mockRestore?: () => void }).mockRestore?.();
	});

	it('generates a key that is published at once and does not sign', async () => {
		const { cookie, groupId } = await administrator('plain');
		const bucket = await ownedBucket(groupId);

		const res = await generate(bucket._id, cookie, 'ES256');

		expect(res.status).toBe(201);
		expect(res.body.state).toBe('published');
		expect(await publishedKids(bucket.slug ?? '')).toContain(
			String(res.body.kid)
		);
	});

	it('is refused promoting a key before its publication window has passed', async () => {
		const { cookie, groupId } = await administrator('plain');
		const bucket = await ownedBucket(groupId);
		const { body } = await generate(bucket._id, cookie, 'RS256');

		const res = await promote(bucket._id, cookie, String(body.kid));

		expect(res.status).toBe(409);
		expect(res.body.promotableAt).toBeDefined();
	});

	it('promotes a key to sign, and the key it replaces keeps verifying', async () => {
		const { cookie, groupId } = await administrator('plain');
		const bucket = await ownedBucket(groupId);
		const [initial] = await listed(bucket._id, cookie);
		const { body } = await generate(bucket._id, cookie, 'RS256');
		later(KEY_PUBLICATION_SECONDS + 1);

		const res = await promote(bucket._id, cookie, String(body.kid));

		expect(res.status).toBe(200);
		expect(res.body.demoted).toBe(initial.kid);
		const states = Object.fromEntries(
			(await listed(bucket._id, cookie)).map((key) => [key.kid, key.state])
		);
		expect(states).toEqual({
			[initial.kid]: 'published',
			[String(body.kid)]: 'signing'
		});
		expect(await publishedKids(bucket.slug ?? '')).toContain(initial.kid);
	});

	it('is refused retiring the key the bucket signs with', async () => {
		const { cookie, groupId } = await administrator('plain');
		const bucket = await ownedBucket(groupId);
		const [initial] = await listed(bucket._id, cookie);

		const res = await retire(bucket._id, cookie, initial.kid);

		expect(res.status).toBe(409);
	});

	/*
	 * Retirement ends a key once its window closes, so the operator has to name the key they mean. Checked
	 * before anything is recorded: a retire that does not name it is not a retire that happened.
	 */
	for (const [label, confirm] of [
		['without a confirmation', null],
		['whose confirmation names another key', 'not-this-key']
	] as const) {
		it(`is refused retiring a key ${label}, and the key keeps its state`, async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const { body } = await generate(bucket._id, cookie, 'ES256');
			const kid = String(body.kid);

			const res = await retire(bucket._id, cookie, kid, confirm);

			expect(res.status).toBe(422);
			expect(res.body.reason).toBe('confirmation_mismatch');
			const key = (await listed(bucket._id, cookie)).find((k) => k.kid === kid);
			expect(key?.state).toBe('published');
		});
	}

	it('retires a key that keeps being published until every token it signed has expired', async () => {
		const { cookie, groupId } = await administrator('plain');
		const bucket = await ownedBucket(groupId);
		const { body } = await generate(bucket._id, cookie, 'ES256');
		const kid = String(body.kid);

		const res = await retire(bucket._id, cookie, kid);

		expect(res.status).toBe(200);
		expect(res.body.removableAt).toBeDefined();
		expect(await publishedKids(bucket.slug ?? '')).toContain(kid);
		later(RETIRED_KEY_LIFETIME_SECONDS + 60);
		expect(await publishedKids(bucket.slug ?? '')).not.toContain(kid);
	});

	/*
	 * One signer per algorithm: a client relying on RS256 — here by default, having registered nothing — and a
	 * FAPI client wanting PS256 are both served, from two RSA keys at once. Promoting the PS256 key takes
	 * nothing away from the RS256 client.
	 */
	it('keeps signing in RS256 for a client relying on it when a key in another algorithm is promoted', async () => {
		const { cookie, groupId } = await administrator('plain');
		const bucket = await ownedBucket(groupId);
		const [initial] = await listed(bucket._id, cookie);
		const clientId = `keys-client-${Math.random().toString(36).slice(2)}`;
		seedClient({
			clientId,
			clientSecret: 'secret',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['https://keys.example.com/cb']
		});
		await getProjectStore().create({
			ownerGroupId: groupId,
			name: 'Relies on RS256',
			slug: `relies-${Math.random().toString(36).slice(2)}`,
			bucketId: bucket._id,
			clientIds: [clientId]
		});
		const { body } = await generate(bucket._id, cookie, 'PS256');
		later(KEY_PUBLICATION_SECONDS + 1);

		const res = await promote(bucket._id, cookie, String(body.kid));

		expect(res.status).toBe(200);
		expect(res.body.demoted).toBeUndefined();
		const states = Object.fromEntries(
			(await listed(bucket._id, cookie)).map((key) => [key.kid, key.state])
		);
		expect(states[initial.kid]).toBe('signing');
		expect(states[String(body.kid)]).toBe('signing');
	});

	it('records every key action in the audit trail', async () => {
		const { cookie, groupId, userId } = await administrator('plain');
		const bucket = await ownedBucket(groupId);
		const { body } = await generate(bucket._id, cookie, 'RS256');
		later(KEY_PUBLICATION_SECONDS + 1);
		await promote(bucket._id, cookie, String(body.kid));
		const [demoted] = (await listed(bucket._id, cookie)).filter(
			(key) => key.state === 'published'
		);
		await retire(bucket._id, cookie, demoted.kid);

		const { entries } = await adminAuditStore.list({ actor: userId });
		expect(entries.map((entry) => entry.action).sort()).toEqual([
			'bucket.key.generate',
			'bucket.key.promote',
			'bucket.key.retire'
		]);
		expect(new Set(entries.map((entry) => entry.targetId))).toEqual(
			new Set([bucket._id])
		);
	});
});
