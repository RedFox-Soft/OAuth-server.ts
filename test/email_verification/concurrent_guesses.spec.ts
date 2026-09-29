import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getUserStore,
	getBucketStore,
	getProjectStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { CODE_MAX_ATTEMPTS } from 'lib/verification/consts.ts';
import { lastEmail, extractCode } from '../mail_capture.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { present } from 'test/shape.js';

/*
 * The attempt cap on an emailed code holds under concurrency, not only in sequence. Each wrong guess
 * read the attempt count and wrote back that count plus one, so a burst of parallel guesses all read
 * the same count and together advanced it by one: the cap of five never bound, and a six-digit code
 * was as guessable as the per-origin rate limiter allowed.
 */

const CLIENT_ID = 'verify-code-app';
const PASSWORD = 'correct horse battery';

let bucketId: string;

async function registerForCode(email: string) {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid'
	});
	const started = await agent.auth.get({ query: auth.params });
	const uid = getHeader(started.response, 'location').split('/')[2];
	const cookie = present(
		started.response.headers.get('set-cookie'),
		'an interaction cookie'
	);
	const { response } = await agent
		.ui({ uid })
		.registration.post(
			{ email, password: PASSWORD, confirmPassword: PASSWORD },
			{ headers: { cookie } }
		);
	const ref = present(
		new URL(getHeader(response, 'location'), 'http://e.ly').searchParams.get(
			'ref'
		),
		'a code-entry ref'
	);
	const code = present(extractCode(present(lastEmail(), 'an email')), 'a code');
	return { ref, code };
}

/**
 * @proves An emailed verification code accepts no more guesses than its cap however many arrive at
 * once, so a burst of wrong ones leaves even the right code refused.
 */
describe('an emailed verification code guessed concurrently', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'code' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Concurrent Code Bucket',
			emailVerificationRequired: true,
			verificationMethod: 'code'
		});
		bucketId = bucket._id;
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Concurrent Code',
			slug: `concurrent-code-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId,
			clientIds: [CLIENT_ID]
		});
	});

	it('refuses the right code after a burst of wrong ones', async () => {
		const email = `burst-${Math.random()}@x.io`;
		const { ref, code } = await registerForCode(email);
		const wrong = code === '000000' ? '111111' : '000000';

		await Promise.all(
			Array.from({ length: CODE_MAX_ATTEMPTS * 3 }, () =>
				agent['verify-email'].code.post({ ref, code: wrong })
			)
		);
		await agent['verify-email'].code.post({ ref, code });

		const user = await getUserStore(bucketId).findByEmail(email);
		expect(user?.verified).toBe(false);
	});
});
