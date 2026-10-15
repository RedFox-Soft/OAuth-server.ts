import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterAll,
	afterEach,
	setSystemTime
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import {
	adapter,
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings, UserBucket } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import nanoid from 'lib/helpers/nanoid.js';
import { throttleKey } from 'lib/password_reset/challenge.ts';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { TestAdapter } from '../models.ts';
import { emailsTo, extractResetUrl, resetSentEmails } from '../mail_capture.ts';
import { present, shaped } from '../shape.ts';
import { adminCall, NO_MAIL, withMail } from './admin_call.ts';
import { adminCookie, defaultBucket } from './fixtures.ts';

const PASSWORD = 'a password of my own';
const DAY = 24 * 60 * 60 * 1000;

let cookie: string;
let previousMail: SmtpSettings | null;

async function freshBucket(
	settings: Partial<Pick<UserBucket, 'passwordLogin'>> = {}
): Promise<string> {
	const created = await getBucketStore().create({
		name: `Invite ${nanoid()}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	if (Object.keys(settings).length > 0) {
		await getBucketStore().update(created._id, settings);
	}
	return created._id;
}

/* A person an administrator created without a password, as the console's create does. */
async function passwordless(bucketId: string, email = `${nanoid()}@x.io`) {
	const { status, body } = await adminCall(
		cookie,
		'POST',
		`/admin/api/projects/${bucketId}/users`,
		{ email }
	);
	expect(status).toBe(201);
	return { id: shaped(Type.Object({ _id: Type.String() }), body)._id, email };
}

function invite(bucketId: string, uid: string) {
	return adminCall(
		cookie,
		'POST',
		`/admin/api/projects/${bucketId}/users/${uid}/invitation`
	);
}

/* The token as the person receives it: read out of the latest message to them, never out of storage. */
function tokenMailedTo(address: string): string {
	const url = present(
		extractResetUrl(present(emailsTo(address).at(-1), 'an invitation')),
		'an invitation link'
	);
	return present(new URL(url).searchParams.get('token'), 'a token');
}

function openLink(token: string) {
	return agent['reset-password'].get({ query: { token } });
}

function choosePassword(token: string, password = PASSWORD) {
	return agent['reset-password'].post({
		token,
		password,
		confirmPassword: password
	});
}

function pageOf(result: {
	data?: unknown;
	error?: { value?: unknown } | null;
}): string {
	if (typeof result.data === 'string') return result.data;
	return String(result.error?.value ?? result.data);
}

/*
 * What a datastore's expiry does once the clock has passed a record's `exp`: MongoDB's TTL monitor removes it.
 * The in-memory store keeps time of its own, which a moved test clock does not reach, so it is done here.
 */
async function reapIfExpired(area: string, id: string): Promise<void> {
	const exp = TestAdapter.for(area).syncFind(id)?.exp;
	if (typeof exp === 'number' && exp <= epochTime()) {
		await adapter(area).destroy(id);
	}
}

/* A password sign-in through `client`, which resolves to the default bucket. */
async function signInStatus(email: string, password: string) {
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
			{ username: email, password },
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
	setSystemTime();
	await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
});

/**
 * @proves An administrator invites a person to choose their own password: the person opens the emailed link,
 * sets a password, is verified and signs in — and the link works once, for seven days, only while it is the
 * latest and only while the person may sign in.
 */
describe('inviting a person to set their own password', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	/* A case that moves the clock outlives the console session it began with, so each starts with its own. */
	afterEach(async () => {
		setSystemTime();
		cookie = await adminCookie();
	});

	it('lets the invited person set a password, sign in, and be verified', async () => {
		const bucket = await defaultBucket();
		await getBucketStore().update(bucket._id, {
			emailVerificationRequired: true
		});
		try {
			const person = await passwordless(DEFAULT_BUCKET_ID);

			expect((await invite(DEFAULT_BUCKET_ID, person.id)).status).toBe(204);
			const chosen = await choosePassword(tokenMailedTo(person.email));

			expect(chosen.response.status).toBe(200);
			expect(
				(await getUserStore(DEFAULT_BUCKET_ID).find(person.id))?.verified
			).toBe(true);
			expect(await signInStatus(person.email, PASSWORD)).toBe(303);
		} finally {
			await getBucketStore().update(bucket._id, {
				emailVerificationRequired: false
			});
		}
	});

	it('shows the invitation’s words on the page the link opens, not a reset’s', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		await invite(bucketId, person.id);

		const page = pageOf(await openLink(tokenMailedTo(person.email)));

		expect(page).toContain('Set your password for');
		expect(page).not.toContain('Choose a new password');
	});

	it('refuses the link a second time', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		await invite(bucketId, person.id);
		const token = tokenMailedTo(person.email);
		await choosePassword(token);

		const again = await choosePassword(token, 'yet another password');

		expect(again.response.status).toBe(400);
	});

	it('works for seven days and not after', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		const sentAt = Date.now();
		await invite(bucketId, person.id);
		const token = tokenMailedTo(person.email);

		setSystemTime(new Date(sentAt + 7 * DAY - 60_000));
		expect((await openLink(token)).response.status).toBe(200);
		setSystemTime(new Date(sentAt + 7 * DAY + 60_000));
		expect((await openLink(token)).response.status).toBe(400);
	});

	it('kills the earlier link when sent again more than a day later', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		const sentAt = Date.now();
		await invite(bucketId, person.id);
		const first = tokenMailedTo(person.email);

		setSystemTime(new Date(sentAt + DAY + 60 * 60 * 1000));
		await reapIfExpired(
			'PasswordResetThrottle',
			throttleKey(bucketId, person.email)
		);
		cookie = await adminCookie();
		expect((await invite(bucketId, person.id)).status).toBe(204);
		const second = tokenMailedTo(person.email);

		expect((await openLink(first)).response.status).toBe(400);
		expect((await openLink(second)).response.status).toBe(200);
	});

	it('kills the link when the person is deactivated after it was sent', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		await invite(bucketId, person.id);
		const token = tokenMailedTo(person.email);

		await adminCall(
			cookie,
			'PATCH',
			`/admin/api/projects/${bucketId}/users/${person.id}`,
			{ active: false }
		);

		expect((await choosePassword(token)).response.status).toBe(400);
	});

	it('records the invitation against the person and the bucket', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);

		await invite(bucketId, person.id);

		const { entries } = await adminAuditStore.list({
			action: 'enduser.invitation.send',
			targetId: person.id
		});
		expect(entries.map((e) => e.targetScope)).toEqual([bucketId]);
	});
});

/**
 * @proves An administrator can create a person and invite them in one request, and is told when the account
 * was made but the message did not go.
 */
describe('creating a person with an invitation', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	it('creates the account without a password and mails the invitation', async () => {
		const bucketId = await freshBucket();
		const email = `${nanoid()}@x.io`;

		const { status, body } = await adminCall(
			cookie,
			'POST',
			`/admin/api/projects/${bucketId}/users`,
			{ email, invite: true }
		);

		expect(status).toBe(201);
		expect(body).toMatchObject({ invitation: 'sent', passwordSet: false });
		expect(
			emailsTo(email).map((m) => m.subject.startsWith('Set your password'))
		).toEqual([true]);
	});

	it('refuses an invitation together with a password, creating nobody', async () => {
		const bucketId = await freshBucket();
		const email = `${nanoid()}@x.io`;

		const { status } = await adminCall(
			cookie,
			'POST',
			`/admin/api/projects/${bucketId}/users`,
			{ email, invite: true, password: 'a chosen password' }
		);

		expect(status).toBe(422);
		expect(await getUserStore(bucketId).findByEmail(email)).toBeNull();
	});

	it('refuses to create an invited person while mail is not configured, creating nobody', async () => {
		const bucketId = await freshBucket();
		const email = `${nanoid()}@x.io`;
		await getSmtpSettingsStore().set(NO_MAIL);
		try {
			const { status } = await adminCall(
				cookie,
				'POST',
				`/admin/api/projects/${bucketId}/users`,
				{ email, invite: true }
			);

			expect(status).toBe(409);
			expect(await getUserStore(bucketId).findByEmail(email)).toBeNull();
		} finally {
			await withMail();
		}
	});
});

/**
 * @proves An invitation is refused, with nothing mailed and nothing recorded, where it could not or must not
 * set a password: a directory's person, a bucket without passwords or without mail, a person who cannot sign
 * in, and a person mailed a moment ago.
 */
describe('an invitation that cannot be sent', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	async function refusedWithNothingRecorded(
		bucketId: string,
		uid: string,
		email: string
	) {
		const res = await invite(bucketId, uid);
		const { entries } = await adminAuditStore.list({
			action: 'enduser.invitation.send',
			targetId: uid
		});
		expect(entries).toEqual([]);
		expect(emailsTo(email)).toEqual([]);
		return res;
	}

	it('refuses a person a directory provisions', async () => {
		const bucketId = await freshBucket();
		const bucket = present(await getBucketStore().find(bucketId), 'bucket');
		const email = `${nanoid()}@x.io`;
		const user = await createEndUser(
			bucket,
			{ kind: 'connection', connectionId: 'conn-a' },
			{ id: nanoid(), email },
			async () => {}
		);

		const res = await refusedWithNothingRecorded(bucketId, user._id, email);

		expect(res.status).toBe(409);
	});

	it('refuses while mail delivery is not configured', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		await getSmtpSettingsStore().set(NO_MAIL);
		try {
			const res = await refusedWithNothingRecorded(
				bucketId,
				person.id,
				person.email
			);

			expect(res.status).toBe(409);
		} finally {
			await withMail();
		}
	});

	it('refuses in a bucket whose password sign-in is off', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		await getBucketStore().update(bucketId, { passwordLogin: false });

		const res = await refusedWithNothingRecorded(
			bucketId,
			person.id,
			person.email
		);

		expect(res.status).toBe(409);
	});

	it('refuses a locked person', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		await adminCall(
			cookie,
			'POST',
			`/admin/api/projects/${bucketId}/users/${person.id}/lock`,
			{ reason: 'suspected compromise' }
		);

		const res = await refusedWithNothingRecorded(
			bucketId,
			person.id,
			person.email
		);

		expect(res.status).toBe(409);
	});

	it('refuses a second invitation inside the cooldown, saying when to retry', async () => {
		const bucketId = await freshBucket();
		const person = await passwordless(bucketId);
		await invite(bucketId, person.id);
		resetSentEmails();

		const res = await invite(bucketId, person.id);

		expect(res.status).toBe(429);
		expect(
			shaped(Type.Object({ retryAfter: Type.Number() }), res.body).retryAfter
		).toBeGreaterThan(0);
		expect(emailsTo(person.email)).toEqual([]);
	});
});
