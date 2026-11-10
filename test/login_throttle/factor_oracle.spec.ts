import { describe, it, expect, beforeAll, jest } from 'bun:test';

import bootstrap, {
	bindClientToBucket,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { elysia } from 'lib/index.ts';
import { throttleKey } from 'lib/login_throttle/throttle.ts';
import { TestAdapter } from 'test/models.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

// Each case spends the cap twice, one argon2 verification per attempt (see signin.spec.ts).
jest.setTimeout(30_000);

const PASSWORD = 'correct horse battery';
const WRONG = 'not the password';
const CAP = ApplicationConfig['loginThrottle.failureCap'];

let bucketId: string;

async function attempt(email: string, password: string) {
	const auth = new AuthorizationRequest({
		client_id: 'throttle-password-app',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2] ?? '';
	const cookie = response.headers.get('set-cookie') ?? '';
	const res = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
			body: new URLSearchParams({ username: email, password }).toString(),
			redirect: 'manual'
		})
	);
	return {
		status: res.status,
		body: (await res.text()).replaceAll(uid, '<uid>')
	};
}

function windowOf(email: string) {
	const record = TestAdapter.for('LoginThrottle').syncFind(
		throttleKey(bucketId, email)
	) as { failures: number; step: number } | undefined;
	return { failures: record?.failures, step: record?.step };
}

/**
 * @proves The password limit treats an address whose account holds an authenticator app exactly as one whose account
 * does not, so guessing at it never tells anyone which accounts have a second factor.
 */
describe('the password limit and a person’s own second factor', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'login_throttle' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Factor oracle'
		});
		bucketId = bucket._id;
		await bindClientToBucket('throttle-password-app', bucketId);
	});

	it('holds both addresses to the same window and answers the right password the same way', async () => {
		const plain = `plain-${Math.random()}@x.io`;
		const protectedEmail = `protected-${Math.random()}@x.io`;
		for (const email of [plain, protectedEmail]) {
			await getUserStore(bucketId).create(
				email,
				await Bun.password.hash(PASSWORD),
				true
			);
		}
		const holder = await getUserStore(bucketId).findByEmail(protectedEmail);
		await getUserStore(bucketId).update(holder?._id ?? '', {
			totp: {
				secret: 'JBSWY3DPEHPK3PXP',
				enrolledAt: new Date(),
				lastStep: 0,
				via: 'self'
			}
		});

		for (let i = 0; i < CAP; i += 1) {
			await attempt(plain, WRONG);
			await attempt(protectedEmail, WRONG);
		}
		const plainAnswer = await attempt(plain, PASSWORD);
		const protectedAnswer = await attempt(protectedEmail, PASSWORD);

		expect(windowOf(protectedEmail)).toEqual(windowOf(plain));
		expect(protectedAnswer.status).toBe(plainAnswer.status);
		expect(protectedAnswer.body.replaceAll(protectedEmail, '<email>')).toBe(
			plainAnswer.body.replaceAll(plain, '<email>')
		);
	});
});
