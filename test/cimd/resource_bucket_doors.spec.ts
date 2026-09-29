import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, {
	SESSION_COOKIE_PREFIX,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	extractResetUrl,
	lastEmail,
	resetSentEmails,
	sentEmails
} from '../mail_capture.ts';
import { request as requestPasswordReset } from 'lib/password_reset/challenge.ts';
import { present } from 'test/shape.js';

/*
 * A client belonging to no project signs into the bucket of the declared resource it names — and every
 * door of that sign-in has to consult that bucket's policy, not only the one that looks the account up.
 * The password door, the reset door and the registration door each resolved the bucket from the client
 * alone, landed on the default bucket, and read *its* policy: so in a bucket whose users may sign in only
 * through their identity provider, a password was verified against its accounts, a reset link was mailed
 * that set a password on a federated account — bypassing the provider's own factors and offboarding —
 * and registration created password accounts. The enrolment page read the wrong bucket's second-factor
 * requirement too, and sent a required enrolment back to the login page for ever.
 */

const PASSWORD = 'correct horse battery';
const FEDERATED_ONLY = 'https://mcp.federated.example/mcp';
const SECOND_FACTOR = 'https://mcp.totp.example/mcp';

let federatedBucketId: string;
let totpBucketId: string;

async function bucketBehind(resource: string, fields: Record<string, unknown>) {
	const bucket = await getBucketStore().create({
		name: resource,
		ownerGroupId: UNASSIGNED_GROUP_ID,
		...fields
	});
	const project = await getProjectStore().create({
		name: resource,
		slug: `p-${Math.random().toString(36).slice(2)}`,
		ownerGroupId: UNASSIGNED_GROUP_ID,
		bucketId: bucket._id
	});
	await getProtectedResourceStore().create({
		_id: resource,
		projectId: project._id,
		name: resource,
		scopes: ['mcp:tools-basic']
	});
	return bucket._id;
}

async function interactionFor(resource: string) {
	const auth = new AuthorizationRequest({
		client_id: 'unaffiliated',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({
		query: { ...auth.params, resource: [resource] }
	});
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = present(
		response.headers.get('set-cookie'),
		'an interaction cookie'
	);
	return { uid, cookie };
}

async function send(
	method: 'GET' | 'POST',
	path: string,
	cookie: string,
	fields?: Record<string, string>
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				cookie,
				...(fields
					? { 'content-type': 'application/x-www-form-urlencoded' }
					: {})
			},
			body: fields ? new URLSearchParams(fields).toString() : undefined,
			redirect: 'manual'
		})
	);
	return {
		status: res.status,
		location: res.headers.get('location') ?? '',
		setCookie: res.headers.get('set-cookie') ?? ''
	};
}

/**
 * @proves A sign-in reaching a bucket through the resource it names is held to that bucket's password,
 * reset, registration and second-factor policy at every door.
 */
describe('the doors of a bucket reached through a declared resource', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'project_association' });
		resetAdminMemoryStores();
		await ensureAdminSeed();

		federatedBucketId = await bucketBehind(FEDERATED_ONLY, {
			passwordLogin: false,
			registrationOpen: true
		});
		await getUserStore(federatedBucketId).create(
			'federated@x.io',
			await Bun.password.hash(PASSWORD),
			[],
			true
		);

		totpBucketId = await bucketBehind(SECOND_FACTOR, { totpRequired: true });
		await getUserStore(totpBucketId).create(
			'enrolling@x.io',
			await Bun.password.hash(PASSWORD),
			[],
			true
		);
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('verifies no password where the bucket signs in only through a provider', async () => {
		const { uid, cookie } = await interactionFor(FEDERATED_ONLY);

		const res = await send('POST', `/ui/${uid}/login`, cookie, {
			username: 'federated@x.io',
			password: PASSWORD
		});

		expect(res.setCookie).not.toContain(SESSION_COOKIE_PREFIX);
	});

	it('mails no reset link where the bucket signs in only through a provider', async () => {
		const { uid, cookie } = await interactionFor(FEDERATED_ONLY);

		await send('POST', `/ui/${uid}/forgot-password`, cookie, {
			email: 'federated@x.io'
		});

		expect(sentEmails).toHaveLength(0);
	});

	/*
	 * A link issued before the bucket closed its password door must not be the way a password reaches an
	 * account whose bucket now accepts none.
	 */
	it('sets no password from a reset link where the bucket signs in only through a provider', async () => {
		const user = present(
			await getUserStore(federatedBucketId).findByEmail('federated@x.io'),
			'the federated account'
		);
		// Issued while the bucket still accepted passwords, then the door closed.
		await getBucketStore().update(federatedBucketId, { passwordLogin: true });
		await requestPasswordReset('federated@x.io', federatedBucketId);
		await getBucketStore().update(federatedBucketId, { passwordLogin: false });
		const link = present(
			extractResetUrl(present(lastEmail(), 'a reset email')),
			'a reset link'
		);
		const token = present(new URL(link).searchParams.get('token'), 'a token');

		await agent['reset-password'].post({
			token,
			password: 'a brand new password',
			confirmPassword: 'a brand new password'
		});

		const after = await getUserStore(federatedBucketId).find(user._id);
		expect(
			await Bun.password.verify('a brand new password', after?.password ?? '')
		).toBe(false);
	});

	it('creates no password account where the bucket signs in only through a provider', async () => {
		const { uid, cookie } = await interactionFor(FEDERATED_ONLY);

		await send('POST', `/ui/${uid}/registration`, cookie, {
			email: 'newcomer@x.io',
			password: PASSWORD,
			confirmPassword: PASSWORD
		});

		expect(
			await getUserStore(federatedBucketId).findByEmail('newcomer@x.io')
		).toBeFalsy();
	});

	it('offers enrolment where the bucket requires a second factor', async () => {
		const { uid, cookie } = await interactionFor(SECOND_FACTOR);
		const login = await send('POST', `/ui/${uid}/login`, cookie, {
			username: 'enrolling@x.io',
			password: PASSWORD
		});
		expect(login.location).toBe(`/ui/${uid}/totp/enroll`);

		const page = await send('GET', `/ui/${uid}/totp/enroll`, cookie);

		expect(page.status).toBe(200);
	});
});
