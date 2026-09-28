import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { idpStub } from './idp_stub.ts';
import {
	CLIENT,
	provider,
	seedBucket,
	signedInAccountIds,
	startInteraction,
	walk
} from './harness.ts';

/*
 * An upstream assertion proves that its holder controls an address. It proves nothing about whoever set
 * the password of a local account that already carries that address: in a bucket that does not verify
 * addresses, anybody can register one. So an assertion matching such an account links only once the
 * account's own sign-in completes in the same interaction. Before this, somebody who registered a
 * victim's address with a password of their own had the victim's first federated sign-in attach to
 * that account, and kept signing in to it with the password afterwards.
 *
 * An account that already holds an upstream identity is a different case: its address was established
 * by a trusted assertion, so a second provider still links without asking.
 */

const PASSWORD = 'correct horse battery';
const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));

async function postForm(
	path: string,
	cookie: string,
	fields: Record<string, string>
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams(fields).toString(),
			redirect: 'manual'
		})
	);
	return { status: res.status, location: res.headers.get('location') ?? '' };
}

async function passwordAccount(bucketId: string, email: string) {
	return getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		[],
		true
	);
}

async function federatedWalk(origin: string, email: string) {
	const idp = await idpStub(origin);
	idp.expectDiscovery();
	const { uid, cookie } = await startInteraction();
	const { complete } = await walk(uid, cookie, {
		idp,
		claims: { email, email_verified: true }
	});
	return { uid, cookie, complete };
}

/**
 * @proves A trusted upstream assertion matching an account that holds only a password signs nobody
 * in and links nothing until that account's own sign-in completes, and then links to that account
 * alone.
 */
describe('a federated sign-in matching an account with a password', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
	});

	it('signs nobody in on the upstream assertion alone', async () => {
		const origin = 'https://idp-link-alone.test';
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(origin, { emailTrusted: true })]
		});
		const existing = await passwordAccount(bucketId, 'owner@acme.test');

		const { uid, complete } = await federatedWalk(origin, 'owner@acme.test');

		expect(signedInAccountIds()).not.toContain(existing._id);
		expect(complete?.location).toStartWith(`/ui/${uid}/login?notice=`);
		const stored = await getUserStore(bucketId).find(existing._id);
		expect(stored?.federated ?? []).toEqual([]);
	});

	it('links the upstream identity once the password sign-in of that account completes', async () => {
		const origin = 'https://idp-link-after.test';
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(origin, { emailTrusted: true })]
		});
		const existing = await passwordAccount(bucketId, 'owner@acme.test');

		const { uid, cookie } = await federatedWalk(origin, 'owner@acme.test');
		await postForm(`/ui/${uid}/login`, cookie, {
			username: 'owner@acme.test',
			password: PASSWORD
		});

		expect(signedInAccountIds()).toContain(existing._id);
		const stored = await getUserStore(bucketId).find(existing._id);
		expect(stored?.federated).toEqual([
			expect.objectContaining({
				providerId: 'acme-sso',
				sub: 'upstream-subject-1'
			})
		]);
	});

	it('links nothing when the password sign-in that follows is of another account', async () => {
		const origin = 'https://idp-link-other.test';
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(origin, { emailTrusted: true })]
		});
		const matched = await passwordAccount(bucketId, 'owner@acme.test');
		const other = await passwordAccount(bucketId, 'other@acme.test');

		const { uid, cookie } = await federatedWalk(origin, 'owner@acme.test');
		await postForm(`/ui/${uid}/login`, cookie, {
			username: 'other@acme.test',
			password: PASSWORD
		});

		const store = getUserStore(bucketId);
		expect((await store.find(matched._id))?.federated ?? []).toEqual([]);
		expect((await store.find(other._id))?.federated ?? []).toEqual([]);
	});

	it('links only after the second factor when the bucket requires one', async () => {
		const origin = 'https://idp-link-totp.test';
		const bucketId = await seedBucket(CLIENT, {
			totpRequired: true,
			federation: [provider(origin, { emailTrusted: true })]
		});
		const existing = await passwordAccount(bucketId, 'owner@acme.test');
		await getUserStore(bucketId).update(existing._id, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
		});

		const { uid, cookie } = await federatedWalk(origin, 'owner@acme.test');
		await postForm(`/ui/${uid}/login`, cookie, {
			username: 'owner@acme.test',
			password: PASSWORD
		});
		const store = getUserStore(bucketId);
		expect((await store.find(existing._id))?.federated ?? []).toEqual([]);

		await postForm(`/ui/${uid}/totp`, cookie, {
			code: hotp(decodeBase32(SECRET), stepFor(epochTime()))
		});
		expect((await store.find(existing._id))?.federated).toEqual([
			expect.objectContaining({ providerId: 'acme-sso' })
		]);
	});

	it('links without a password to an account that already holds an upstream identity', async () => {
		const origin = 'https://idp-link-second.test';
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(origin, { emailTrusted: true })]
		});
		const existing = await passwordAccount(bucketId, 'owner@acme.test');
		await getUserStore(bucketId).update(existing._id, {
			federated: [
				{ providerId: 'other-sso', sub: 'elsewhere', linkedAt: new Date() }
			]
		});

		await federatedWalk(origin, 'owner@acme.test');

		expect(signedInAccountIds()).toContain(existing._id);
	});
});
