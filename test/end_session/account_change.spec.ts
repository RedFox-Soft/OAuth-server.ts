import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, {
	DEFAULT_SESSION_COOKIE,
	seedAccount
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.js';
import { Session } from 'lib/models/session.js';
import { Interaction } from 'lib/models/interaction.js';
import nanoid from '../../lib/helpers/nanoid.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { getBucketStore, getProjectStore } from 'lib/adapters/index.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.js';
import { sessionCookieName } from 'lib/consts/param_list.js';
import {
	forgetBucketAddresses,
	issuingBucket
} from 'lib/admin/auth/bucketAddress.js';

/**
 * @proves When a different account of the same bucket signs in during an interaction, the end user
 * is asked to sign out first, and confirming that sign-out carries it out.
 */
describe('an interaction completed by a different account of the same bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'end_session' });
		seedAccount('alice');
		seedAccount('bob');
	});

	/* Alice holds the browser's sign-in; the interaction she started was completed by Bob. */
	async function resumeAsAnotherAccount() {
		const session = new Session({
			jti: nanoid(),
			accountId: 'alice',
			bucketId: DEFAULT_BUCKET_ID,
			loginTs: epochTime()
		});
		const sessionId = await session.save();
		const uid = nanoid();
		await new Interaction(uid, {
			cookieID: 'interaction-cookie',
			params: {
				client_id: 'client',
				redirect_uri: 'https://client.example.com/cb',
				response_type: 'code',
				scope: 'openid'
			},
			session: { uid: session.payload.uid, accountId: 'alice' },
			result: { login: { accountId: 'bob' } }
		}).save(60);

		const cookie = `_interaction=interaction-cookie; ${DEFAULT_SESSION_COOKIE}=${sessionId}`;
		const page = await elysia.handle(
			new Request(`http://localhost/ui/${uid}/resume`, { headers: { cookie } })
		);
		const policy = page.headers.get('content-security-policy') ?? '';
		const xsrf = (await page.text()).match(/name="xsrf" value="([^"]+)"/)?.[1];
		return { uid, cookie, xsrf, policy };
	}

	/*
	 * Confirming starts a redirect chain — the confirmation, then the interaction's resume, then the client —
	 * and a browser checks every hop against this page's form-action. Without the client's origin there,
	 * switching to an account that needs no consent stopped on this page after the sign-out had happened.
	 */
	it('lets the confirmation hand the browser on to the client after switching accounts', async () => {
		const { policy } = await resumeAsAnotherAccount();

		const formAction = policy
			.split(';')
			.map((d) => d.trim())
			.find((d) => d.startsWith('form-action'));
		expect(formAction).toContain('https://client.example.com');
	});

	it('continues the interaction once the end user confirms the sign-out', async () => {
		const { uid, cookie, xsrf } = await resumeAsAnotherAccount();
		if (!xsrf) throw new Error('expected the sign-out confirmation form');

		const confirmed = await elysia.handle(
			new Request('http://localhost/logout/confirm', {
				method: 'POST',
				headers: {
					cookie,
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: `xsrf=${xsrf}&logout=true`
			})
		);

		expect(confirmed.status).toBe(303);
		expect(confirmed.headers.get('location')).toBe(
			`${ISSUER}/ui/${uid}/resume`
		);
	});
});

/**
 * @proves On a bucket with a hostname of its own, switching accounts during an interaction comes back to
 * that hostname after the sign-out, where the interaction lives — not to the server's root address.
 */
describe('an account change on a bucket with a hostname of its own', () => {
	const HOST = 'id.switch.test';
	let bucketId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'end_session' });
		forgetBucketAddresses();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Switch users',
			host: HOST
		});
		bucketId = bucket._id;
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Switch',
			slug: `switch-${Math.random().toString(36).slice(2)}`
		});
		await getProjectStore().update(project._id, {
			bucketId,
			clientIds: ['client']
		});
		seedAccount('carol', {}, bucketId);
		seedAccount('dave', {}, bucketId);
	});

	it('sends the browser back to the bucket’s own hostname after the sign-out is confirmed', async () => {
		const session = new Session({
			jti: nanoid(),
			accountId: 'carol',
			bucketId,
			loginTs: epochTime()
		});
		const sessionId = await session.save();
		const uid = nanoid();
		await new Interaction(uid, {
			cookieID: 'interaction-cookie',
			bucketId,
			params: {
				client_id: 'client',
				redirect_uri: 'https://client.example.com/cb',
				response_type: 'code',
				scope: 'openid'
			},
			session: { uid: session.payload.uid, accountId: 'carol' },
			result: { login: { accountId: 'dave' } }
		}).save(60);
		const cookie = `_interaction=interaction-cookie; ${sessionCookieName(await issuingBucket(bucketId))}=${sessionId}`;
		const page = await elysia.handle(
			new Request(`http://${HOST}/ui/${uid}/resume`, { headers: { cookie } })
		);
		const xsrf = (await page.text()).match(/name="xsrf" value="([^"]+)"/)?.[1];
		if (!xsrf) throw new Error('expected the sign-out confirmation form');

		const confirmed = await elysia.handle(
			new Request(`http://${HOST}/logout/confirm`, {
				method: 'POST',
				headers: {
					cookie,
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: `xsrf=${xsrf}&logout=true`
			})
		);

		expect(confirmed.status).toBe(303);
		const location = new URL(confirmed.headers.get('location') ?? '');
		expect(location.host).toBe(HOST);
		expect(location.pathname).toBe(`/ui/${uid}/resume`);
	});
});
