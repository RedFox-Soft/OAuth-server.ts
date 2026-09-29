import {
	describe,
	it,
	expect,
	beforeAll,
	afterEach,
	jest,
	mock,
	spyOn
} from 'bun:test';

import bootstrap, {
	SESSION_COOKIE_PREFIX,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { present } from 'test/shape.js';

/*
 * The password door's failure cap holds under concurrency, not only in sequence. The door read the
 * counter before verifying and wrote one more failure after, so a burst of parallel guesses all found
 * the door open and every one of them had its password verified. The counter itself ended high
 * enough to shut the door afterwards, which is why the measure here is how many guesses were tested,
 * not whether the door is shut once the burst is over.
 */

/* Each attempt costs an argon2 verification; a burst of them is slower than bun's default allows. */
jest.setTimeout(30_000);

const CLIENT_ID = 'throttle-password-app';
const PASSWORD = 'correct horse battery';
const CAP = ApplicationConfig['loginThrottle.failureCap'];

async function attempt(email: string, password: string) {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = present(
		response.headers.get('set-cookie'),
		'an interaction cookie'
	);
	const res = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams({ username: email, password }).toString(),
			redirect: 'manual'
		})
	);
	return res.headers.get('set-cookie') ?? '';
}

/**
 * @proves The password door accepts no more wrong passwords per window than its cap however many
 * arrive at once, so a burst of wrong ones leaves even the right password refused.
 */
describe('a password guessed concurrently', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'login_throttle' });
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Concurrent Password Bucket'
		});
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Concurrent Password',
			slug: `concurrent-password-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId: bucket._id,
			clientIds: [CLIENT_ID]
		});
		for (const email of ['burst@x.io', 'burst-two@x.io']) {
			await getUserStore(bucket._id).create(
				email,
				await Bun.password.hash(PASSWORD),
				[],
				true
			);
		}
	});

	afterEach(() => {
		mock.restore();
	});

	it('tests no more guesses than the cap when they arrive at once', async () => {
		const verify = spyOn(Bun.password, 'verify');

		await Promise.all(
			Array.from({ length: CAP * 3 }, () =>
				attempt('burst@x.io', 'not the password')
			)
		);

		expect(verify.mock.calls.length).toBeLessThanOrEqual(CAP);
	});

	it('refuses the right password after a burst of wrong ones', async () => {
		await Promise.all(
			Array.from({ length: CAP * 3 }, () =>
				attempt('burst-two@x.io', 'not the password')
			)
		);

		expect(await attempt('burst-two@x.io', PASSWORD)).not.toContain(
			SESSION_COOKIE_PREFIX
		);
	});
});
