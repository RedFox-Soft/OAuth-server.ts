import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterAll
} from 'bun:test';

import {
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	emailsTo,
	extractVerifyUrl,
	resetSentEmails
} from '../mail_capture.ts';
import { present } from '../shape.ts';
import { adminCall, NO_MAIL, withMail } from './admin_call.ts';
import { adminCookie, defaultBucket } from './fixtures.ts';

const PASSWORD = 'a password of their own';

let cookie: string;
let previousMail: SmtpSettings | null;

async function freshBucket(): Promise<string> {
	const created = await getBucketStore().create({
		name: `Mark ${nanoid()}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	return created._id;
}

async function unverified(bucketId: string, email = `${nanoid()}@x.io`) {
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		false
	);
	return { id: user._id, email };
}

function mark(bucketId: string, uid: string) {
	return adminCall(
		cookie,
		'POST',
		`/admin/api/projects/${bucketId}/users/${uid}/verified`
	);
}

async function marksRecorded(uid: string) {
	return (
		await adminAuditStore.list({
			action: 'enduser.verified.mark',
			targetId: uid
		})
	).entries;
}

/* A password sign-in through `client`, which resolves to the default bucket. */
async function signInStatus(email: string) {
	const auth = new AuthorizationRequest({
		client_id: 'client',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const interaction = present(
		response.headers.get('set-cookie'),
		'an interaction cookie'
	);
	const res = await agent
		.ui({ uid })
		.login.post(
			{ username: email, password: PASSWORD },
			{ headers: { cookie: interaction } }
		);
	return res.response.status;
}

beforeAll(async () => {
	await bootstrap(import.meta.url);
	await defaultBucket();
	cookie = await adminCookie();
	previousMail = await withMail();
});

afterAll(async () => {
	await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
});

/**
 * @proves An administrator who confirmed a person's address another way marks it verified: the person can then
 * sign in where verification is required, a verification message still in their inbox stops working, and a
 * directory's person or an already verified one is refused with nothing recorded.
 */
describe('marking an address verified by hand', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	it('verifies the person and records who did it', async () => {
		const bucketId = await freshBucket();
		const person = await unverified(bucketId);

		const res = await mark(bucketId, person.id);

		expect(res.status).toBe(200);
		expect(res.body).toHaveProperty('verified', true);
		expect((await marksRecorded(person.id)).map((e) => e.targetScope)).toEqual([
			bucketId
		]);
	});

	it('kills a verification link still waiting in the inbox', async () => {
		const bucketId = await freshBucket();
		const person = await unverified(bucketId);
		await adminCall(
			cookie,
			'POST',
			`/admin/api/projects/${bucketId}/users/${person.id}/verification`
		);
		const link = present(
			extractVerifyUrl(present(emailsTo(person.email).at(-1), 'a message')),
			'a link'
		);
		const token = present(new URL(link).searchParams.get('token'), 'a token');

		await mark(bucketId, person.id);

		const opened = await agent['verify-email'].get({ query: { token } });
		const unknown = await agent['verify-email'].get({
			query: { token: 'never-issued' }
		});
		expect(opened.response.status).toBe(unknown.response.status);
	});

	it('lets the person sign in where the bucket requires verification', async () => {
		const bucket = await defaultBucket();
		await getBucketStore().update(bucket._id, {
			emailVerificationRequired: true
		});
		try {
			const person = await unverified(DEFAULT_BUCKET_ID);
			expect(await signInStatus(person.email)).not.toBe(303);

			await mark(DEFAULT_BUCKET_ID, person.id);

			expect(await signInStatus(person.email)).toBe(303);
		} finally {
			await getBucketStore().update(bucket._id, {
				emailVerificationRequired: false
			});
		}
	});

	it('refuses a person a directory provisions, recording nothing', async () => {
		const bucketId = await freshBucket();
		const bucket = present(await getBucketStore().find(bucketId), 'bucket');
		const user = await createEndUser(
			bucket,
			{ kind: 'connection', connectionId: 'conn-a' },
			{ id: nanoid(), email: `${nanoid()}@x.io`, verified: false },
			async () => {}
		);

		const res = await mark(bucketId, user._id);

		expect(res.status).toBe(409);
		expect(await marksRecorded(user._id)).toEqual([]);
	});

	it('refuses an address already verified, recording nothing', async () => {
		const bucketId = await freshBucket();
		const user = await getUserStore(bucketId).create(
			`${nanoid()}@x.io`,
			'h',
			true
		);

		const res = await mark(bucketId, user._id);

		expect(res.status).toBe(409);
		expect(await marksRecorded(user._id)).toEqual([]);
	});
});

/**
 * @proves A directory's person is not mailed a verification message on an administrator's request: whether
 * their address is trusted is their connection's setting.
 */
describe('resending verification to a directory’s person', () => {
	it('refuses, mailing nothing', async () => {
		const bucketId = await freshBucket();
		const bucket = present(await getBucketStore().find(bucketId), 'bucket');
		const email = `${nanoid()}@x.io`;
		const user = await createEndUser(
			bucket,
			{ kind: 'connection', connectionId: 'conn-a' },
			{ id: nanoid(), email, verified: false },
			async () => {}
		);
		resetSentEmails();

		const res = await adminCall(
			cookie,
			'POST',
			`/admin/api/projects/${bucketId}/users/${user._id}/verification`
		);

		expect(res.status).toBe(409);
		expect(emailsTo(email)).toEqual([]);
	});
});
