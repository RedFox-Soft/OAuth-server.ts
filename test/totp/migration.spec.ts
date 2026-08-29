import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

const PASSWORD = 'correct horse battery';

let bucketId: string;

async function startInteraction(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
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
		text: await res.text(),
		location: res.headers.get('location'),
		setCookie: res.headers.get('set-cookie')
	};
}

async function getPage(path: string, cookie: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, { headers: { cookie } })
	);
	return {
		status: res.status,
		text: await res.text(),
		location: res.headers.get('location')
	};
}

function secretFrom(html: string): string {
	const props = /window\.PROPS=(\{.*?\})<\/script>/s.exec(html)?.[1];
	if (!props) throw new Error('the enrolment page carried no props script');
	const parsed = JSON.parse(props) as { secretText?: string };
	if (!parsed.secretText) throw new Error('the props carried no secret');
	return parsed.secretText.replace(/\s+/g, '');
}

function codeFor(secret: string): string {
	return hotp(decodeBase32(secret), stepFor(epochTime()));
}

async function signIn(email: string) {
	const { uid, cookie } = await startInteraction('totp-migrate-app');
	const res = await postForm(`/ui/${uid}/login`, cookie, {
		username: email,
		password: PASSWORD
	});
	return { uid, cookie, res };
}

async function raise(required: boolean) {
	await getBucketStore().update(bucketId, { totpRequired: required });
}

describe('bringing existing accounts under the requirement (US4)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Migrating',
			totpRequired: false
		});
		bucketId = bucket._id;
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Migrating',
			slug: `migrate-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId,
			clientIds: ['totp-migrate-app']
		});
	});

	async function existingAccount(label: string) {
		const email = `${label}-${Math.random()}@x.io`;
		await getUserStore(bucketId).create(
			email,
			await Bun.password.hash(PASSWORD),
			[],
			true
		);
		return email;
	}

	it('signs an existing account in with the password alone while the bucket is open', async () => {
		await raise(false);
		const email = await existingAccount('before');
		const { res } = await signIn(email);
		expect(res.status).toBe(303);
		expect(res.setCookie ?? '').toContain('_session=');
	});

	it('routes an unenrolled account to enrolment once the bucket is raised', async () => {
		const email = await existingAccount('raised');
		await raise(true);

		const { uid, res } = await signIn(email);
		expect(res.status).toBe(303);
		expect(res.location).toBe(`/ui/${uid}/totp/enroll`);
		// Not signed in on the way past.
		expect(res.setCookie ?? '').not.toContain('_session=');
	});

	it('completes that sign-in inline, without a second visit', async () => {
		const email = await existingAccount('inline');
		await raise(true);

		const { uid, cookie } = await signIn(email);
		const page = await getPage(`/ui/${uid}/totp/enroll`, cookie);
		const res = await postForm(`/ui/${uid}/totp/enroll`, cookie, {
			code: codeFor(secretFrom(page.text))
		});

		expect(res.status).toBe(303);
		expect(res.setCookie ?? '').toContain('_session=');
		expect(res.location ?? '').toMatch(/\/consent$|\/callback/);
	});

	it('asks only for the code at the next sign-in, not for enrolment again', async () => {
		const email = await existingAccount('second-visit');
		await raise(true);

		const first = await signIn(email);
		const page = await getPage(`/ui/${first.uid}/totp/enroll`, first.cookie);
		const secret = secretFrom(page.text);
		await postForm(`/ui/${first.uid}/totp/enroll`, first.cookie, {
			code: codeFor(secret)
		});

		const second = await signIn(email);
		expect(second.res.location).toBe(`/ui/${second.uid}/totp`);
	});

	it('leaves someone who abandons enrolment signed out', async () => {
		const email = await existingAccount('abandoning');
		await raise(true);

		const { uid, cookie } = await signIn(email);
		await getPage(`/ui/${uid}/totp/enroll`, cookie);

		// They walk away. A fresh attempt still demands enrolment, and no session exists.
		const again = await signIn(email);
		expect(again.res.location).toBe(`/ui/${again.uid}/totp/enroll`);
		expect(again.res.setCookie ?? '').not.toContain('_session=');

		const user = await getUserStore(bucketId).findByEmail(email);
		expect(user?.totp).toBeUndefined();
	});

	/*
	 * FR-029. Retention has to be a property of the code rather than an accident of what nobody wrote:
	 * discarding enrolments on the way down would make lowering the bucket a destructive act, and raising
	 * it again would drag everyone back through setup.
	 */
	it('keeps enrolments when the bucket is lowered, and honours them when raised again', async () => {
		const email = await existingAccount('retained');
		await raise(true);

		const first = await signIn(email);
		const page = await getPage(`/ui/${first.uid}/totp/enroll`, first.cookie);
		const secret = secretFrom(page.text);
		await postForm(`/ui/${first.uid}/totp/enroll`, first.cookie, {
			code: codeFor(secret)
		});

		await raise(false);
		const lowered = await signIn(email);
		// Straight through: no code demanded of an enrolled account in a bucket that does not ask.
		expect(lowered.res.setCookie ?? '').toContain('_session=');

		// The enrolment survived the round trip.
		const user = await getUserStore(bucketId).findByEmail(email);
		expect(user?.totp?.secret).toBe(secret);

		await raise(true);
		const reraised = await signIn(email);
		// The code step, not enrolment: they never have to set it up twice.
		expect(reraised.res.location).toBe(`/ui/${reraised.uid}/totp`);
	});
});
