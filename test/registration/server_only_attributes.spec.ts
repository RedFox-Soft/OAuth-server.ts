import { describe, beforeAll, it, expect } from 'bun:test';

import bootstrap, { agent, seedBucket } from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';
import { present } from 'test/shape.js';

/*
 * Which bucket an application belongs to, and which browser origins may read its responses, are an
 * administrator's to say. A bucket decides whose users the application signs in and whether its consent
 * waiver and machine tokens are honoured there; an origin list decides which pages may read its tokens
 * cross-origin. A registrant naming either would choose its own tenant or its own CORS reach, so neither
 * can arrive through dynamic registration under any spelling — whatever the body says, the bucket is the
 * one the registration address names, and there are no origins.
 */

const json = { 'content-type': 'application/json' };
const BUCKET = 'reg-tenant';
const SLUG = 'regtenant';
const OTHER_BUCKET = 'reg-other';

async function storedAfter(body: Record<string, unknown>) {
	const res = await agent.reg.post(
		{ redirect_uris: ['https://client.example.com/cb'], ...body },
		{ headers: json }
	);
	expect(res.status).toBe(201);
	return adapter('Client').find(present(res.data?.client_id, 'a client_id'));
}

/**
 * @proves A dynamic registration cannot choose the bucket the application belongs to or the browser
 * origins allowed to read its responses, at the root or at a bucket's own address.
 */
describe('a registration naming attributes only an administrator sets', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'registration' });
		await seedBucket({
			bucketId: BUCKET,
			slug: SLUG,
			clientId: 'reg-tenant-app',
			accountId: 'reg-tenant-user'
		});
		await seedBucket({
			bucketId: OTHER_BUCKET,
			clientId: 'reg-other-app',
			accountId: 'reg-other-user'
		});
	});

	it.each(['bucket_id', 'bucketId'])(
		'belongs to no bucket at the root when the body names one as %s',
		async (field) => {
			const stored = await storedAfter({ [field]: OTHER_BUCKET });

			expect(stored?.bucketId).toBeUndefined();
		}
	);

	it.each(['cors_origins', 'corsOrigins'])(
		'lists no origins when the body names them as %s',
		async (field) => {
			const stored = await storedAfter({
				[field]: ['https://attacker.example']
			});

			expect(stored?.corsOrigins).toBeUndefined();
		}
	);

	it('belongs to the bucket whose address it registered at, whatever bucket the body names', async () => {
		const res = await elysia.handle(
			new Request(`${ISSUER}/${SLUG}/reg`, {
				method: 'POST',
				headers: json,
				body: JSON.stringify({
					redirect_uris: ['https://client.example.com/cb'],
					bucket_id: OTHER_BUCKET,
					bucketId: OTHER_BUCKET
				})
			})
		);
		expect(res.status).toBe(201);
		const { client_id } = (await res.json()) as { client_id: string };

		const stored = await adapter('Client').find(client_id);

		expect(stored?.bucketId).toBe(BUCKET);
	});

	/* The registrant's own management endpoint is the other door: an update cannot do what creation could not. */
	it('keeps its bucket and lists no origins after an update naming them', async () => {
		const created = await agent.reg.post(
			{ redirect_uris: ['https://client.example.com/cb'] },
			{ headers: json }
		);
		const clientId = present(created.data?.client_id, 'a client_id');
		const token = present(
			created.data?.registration_access_token,
			'a registration access token'
		);

		const res = await elysia.handle(
			new Request(`${ISSUER}/reg/${encodeURIComponent(clientId)}`, {
				method: 'PUT',
				headers: { ...json, authorization: `Bearer ${token}` },
				body: JSON.stringify({
					client_id: clientId,
					redirect_uris: ['https://client.example.com/cb'],
					bucket_id: OTHER_BUCKET,
					bucketId: OTHER_BUCKET,
					cors_origins: ['https://attacker.example'],
					corsOrigins: ['https://attacker.example']
				})
			})
		);
		expect(res.status).toBe(200);

		const stored = await adapter('Client').find(clientId);
		expect(stored?.bucketId).toBeUndefined();
		expect(stored?.corsOrigins).toBeUndefined();
	});
});
