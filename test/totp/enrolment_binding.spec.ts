import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap, {
	SESSION_COOKIE_PREFIX,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { decodeBase32, encodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { shaped } from 'test/shape.js';

/*
 * The password step can be submitted more than once inside one interaction, and each submission
 * replaces the account the half-finished sign-in belongs to. The secret offered for enrolment is keyed
 * by the interaction alone, so it has to be bound to the account it was minted for as well. Without
 * that, someone holding a victim's password but not their authenticator signed in first as an
 * unenrolled account of their own, took the secret shown to it, submitted the victim's password, and
 * then proved the first secret — enrolling their own account and leaving signed in as the victim.
 */

const PASSWORD = 'correct horse battery';
const VICTIM_SECRET = encodeBase32(
	Buffer.from('12345678901234567890', 'ascii')
);

let bucketId: string;

async function startInteraction() {
	const auth = new AuthorizationRequest({
		client_id: 'totp-required-app',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

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
	return {
		status: res.status,
		location: res.headers.get('location'),
		setCookie: res.headers.get('set-cookie')
	};
}

async function enrolmentSecret(uid: string, cookie: string): Promise<string> {
	const res = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/totp/enroll`, { headers: { cookie } })
	);
	const html = await res.text();
	const props = /window\.PROPS=(\{.*?\})<\/script>/s.exec(html)?.[1];
	if (!props) throw new Error('the enrolment page carried no props script');
	const parsed = shaped(
		Type.Object({ secretText: Type.Optional(Type.String()) }),
		JSON.parse(props)
	);
	if (!parsed.secretText) throw new Error('the props carried no secret');
	return parsed.secretText.replace(/\s+/g, '');
}

function codeFor(secret: string): string {
	return hotp(decodeBase32(secret), stepFor(epochTime()));
}

async function seedAccount(email: string, secret?: string) {
	const store = getUserStore(bucketId);
	const user = await store.create(
		email,
		await Bun.password.hash(PASSWORD),
		[],
		true
	);
	if (secret) {
		await store.update(user._id, {
			totp: { secret, enrolledAt: new Date(), lastStep: 0 }
		});
	}
	return user;
}

/**
 * @proves A secret offered for enrolment is proved only for the account it was offered to, so a
 * password alone never completes a sign-in in a bucket that requires a second factor.
 */
describe('an enrolment secret and the account it was offered to', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'TOTP Required',
			totpRequired: true
		});
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'TOTP Required',
			slug: `totp-binding-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId: bucket._id,
			clientIds: ['totp-required-app']
		});
		bucketId = bucket._id;
	});

	it('refuses to sign in an enrolled account with a secret offered to another account', async () => {
		const own = `own-${Math.random()}@x.io`;
		const victim = `victim-${Math.random()}@x.io`;
		await seedAccount(own);
		await seedAccount(victim, VICTIM_SECRET);

		const { uid, cookie } = await startInteraction();
		await postForm(`/ui/${uid}/login`, cookie, {
			username: own,
			password: PASSWORD
		});
		const ownSecret = await enrolmentSecret(uid, cookie);
		await postForm(`/ui/${uid}/login`, cookie, {
			username: victim,
			password: PASSWORD
		});

		const res = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(ownSecret)
		});

		expect(res.setCookie ?? '').not.toContain(SESSION_COOKIE_PREFIX);
	});

	it('offers a fresh secret when the half-finished sign-in moves to another unenrolled account', async () => {
		const first = `first-${Math.random()}@x.io`;
		const second = `second-${Math.random()}@x.io`;
		await seedAccount(first);
		await seedAccount(second);

		const { uid, cookie } = await startInteraction();
		await postForm(`/ui/${uid}/login`, cookie, {
			username: first,
			password: PASSWORD
		});
		const firstSecret = await enrolmentSecret(uid, cookie);
		await postForm(`/ui/${uid}/login`, cookie, {
			username: second,
			password: PASSWORD
		});

		expect(await enrolmentSecret(uid, cookie)).not.toBe(firstSecret);
	});

	it('enrols the account that is signing in, not the one a secret was first offered to', async () => {
		const first = `first-${Math.random()}@x.io`;
		const second = `second-${Math.random()}@x.io`;
		const firstUser = await seedAccount(first);
		const secondUser = await seedAccount(second);

		const { uid, cookie } = await startInteraction();
		await postForm(`/ui/${uid}/login`, cookie, {
			username: first,
			password: PASSWORD
		});
		await enrolmentSecret(uid, cookie);
		await postForm(`/ui/${uid}/login`, cookie, {
			username: second,
			password: PASSWORD
		});
		const secret = await enrolmentSecret(uid, cookie);
		await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secret)
		});

		const store = getUserStore(bucketId);
		expect((await store.find(secondUser._id))?.totp?.secret).toBe(secret);
		expect((await store.find(firstUser._id))?.totp).toBeUndefined();
	});
});
