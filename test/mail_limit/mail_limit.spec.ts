import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterAll,
	setSystemTime
} from 'bun:test';

import bootstrap, {
	bindClientToBucket,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { PLAIN_TEXTS } from 'lib/i18n/texts/plain/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { emailsTo, resetSentEmails } from '../mail_capture.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { saveSettings, superAdminCookie } from '../settings_apply/helpers.js';
import {
	PEER_HEADER,
	statePeerThroughHeader
} from '../caller_address/helper.ts';

const CLIENT_ID = 'mail-limit-app';
const PASSWORD = 'correct horse battery';
const LIMIT = 3;
const LIMITED = PLAIN_TEXTS.en.verify.messages.callerLimit;

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Accounts',
	fromEmail: 'accounts@example.test'
};

let bucketId: string;
let caller = 0;

/* A fresh public address per case, so no case starts with another's count. */
function nextCaller(): string {
	caller += 1;
	return `203.0.113.${caller}`;
}

async function startInteraction(peer: string) {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { [PEER_HEADER]: peer }
	});
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

/* A reset request, read as raw HTTP so the status, headers and page are all there to compare. */
async function requestReset(
	peer: string,
	email: string,
	interaction?: { uid: string; cookie: string }
): Promise<Response> {
	const { uid, cookie } = interaction ?? (await startInteraction(peer));
	return elysia.handle(
		new Request(`${ISSUER}/ui/${uid}/forgot-password`, {
			method: 'POST',
			headers: {
				cookie,
				[PEER_HEADER]: peer,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams({ email }).toString()
		})
	);
}

async function register(peer: string, email: string): Promise<Response> {
	const { uid, cookie } = await startInteraction(peer);
	return elysia.handle(
		new Request(`${ISSUER}/ui/${uid}/registration`, {
			method: 'POST',
			headers: {
				cookie,
				[PEER_HEADER]: peer,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams({
				email,
				password: PASSWORD,
				confirmPassword: PASSWORD
			}).toString()
		})
	);
}

async function resendVerification(peer: string): Promise<Response> {
	return elysia.handle(
		new Request(`${ISSUER}/verify-email/resend`, {
			method: 'POST',
			headers: {
				[PEER_HEADER]: peer,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams({ ref: 'no-such-request' }).toString()
		})
	);
}

/* `count` reset requests from one caller, each for a different address. */
async function spend(peer: string, count: number): Promise<void> {
	for (let i = 0; i < count; i += 1) {
		await requestReset(peer, `spent-${peer}-${i}@x.io`);
	}
}

async function seedUser(email: string) {
	return getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
}

beforeAll(async () => {
	await bootstrap(import.meta.url);
	resetAdminMemoryStores();
	await ensureAdminSeed();
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'Mail Limit Bucket',
		emailVerificationRequired: true,
		verificationMethod: 'link'
	});
	bucketId = bucket._id;
	await bindClientToBucket(CLIENT_ID, bucketId);
	await getSmtpSettingsStore().set(MAIL);
});

afterAll(async () => {
	await getSmtpSettingsStore().set({ ...MAIL, host: '', fromEmail: '' });
});

/**
 * @proves One caller address can make the instance send mail to addresses it names only up to the
 * hourly limit, across reset requests, sign-ups and verification resends; the refusal says nothing about
 * which addresses have accounts, and another caller, and mail an administrator sends, are unaffected.
 */
describe('the per-caller mail limit', () => {
	beforeEach(() => {
		// Mid-hour, so no case can straddle the hour the tally is counted in.
		const hour = 60 * 60 * 1000;
		setSystemTime(new Date(Math.floor(Date.now() / hour) * hour + hour / 2));
		statePeerThroughHeader();
		resetSentEmails();
		ApplicationConfig['mail.requestsPerCallerPerHour'] = LIMIT;
	});

	it('sends no mail past the limit and asks the visitor to try later', async () => {
		const peer = nextCaller();
		await seedUser('past-limit@x.io');
		await spend(peer, LIMIT);

		const response = await requestReset(peer, 'past-limit@x.io');

		expect({
			status: response.status,
			retryAfter: Number(response.headers.get('retry-after')) > 0,
			says: (await response.text()).includes(LIMITED),
			mailed: emailsTo('past-limit@x.io').length
		}).toEqual({ status: 429, retryAfter: true, says: true, mailed: 0 });
	});

	it('serves a caller under the limit as before', async () => {
		const peer = nextCaller();
		await seedUser('under-limit@x.io');
		await spend(peer, LIMIT - 1);

		const response = await requestReset(peer, 'under-limit@x.io');

		expect([response.status, emailsTo('under-limit@x.io').length]).toEqual([
			200, 1
		]);
	});

	it('serves a second caller while the first is at the limit', async () => {
		const first = nextCaller();
		await spend(first, LIMIT);
		await seedUser('second-caller@x.io');

		const response = await requestReset(nextCaller(), 'second-caller@x.io');

		expect([response.status, emailsTo('second-caller@x.io').length]).toEqual([
			200, 1
		]);
	});

	it('refuses an address with an account exactly as one without', async () => {
		const peer = nextCaller();
		await seedUser('has-account@x.io');
		const interaction = await startInteraction(peer);
		await spend(peer, LIMIT);

		const withAccount = await requestReset(
			peer,
			'has-account@x.io',
			interaction
		);
		const withoutAccount = await requestReset(
			peer,
			'no-account@x.io',
			interaction
		);

		expect({
			status: withoutAccount.status,
			retryAfter: withoutAccount.headers.get('retry-after'),
			body: await withoutAccount.text()
		}).toEqual({
			status: withAccount.status,
			retryAfter: withAccount.headers.get('retry-after'),
			body: await withAccount.text()
		});
	});

	it('creates no account for a sign-up past the limit', async () => {
		const peer = nextCaller();
		await spend(peer, LIMIT);

		await register(peer, 'late-sign-up@x.io');

		expect(await getUserStore(bucketId).findByEmail('late-sign-up@x.io')).toBe(
			null
		);
	});

	it('counts reset requests, sign-ups and verification resends against one tally', async () => {
		const peer = nextCaller();
		await requestReset(peer, 'mixed-reset@x.io');
		await register(peer, 'mixed-sign-up@x.io');
		await resendVerification(peer);

		const response = await requestReset(peer, 'mixed-again@x.io');

		expect(response.status).toBe(429);
	});

	it('admits the caller again within the hour once the limit is raised', async () => {
		const peer = nextCaller();
		await spend(peer, LIMIT);
		await saveSettings(await superAdminCookie(), {
			'mail.requestsPerCallerPerHour': LIMIT + 2
		});

		const response = await requestReset(peer, 'raised@x.io');

		expect(response.status).toBe(200);
	});

	it('does not count mail an administrator sends', async () => {
		const peer = nextCaller();
		await spend(peer, LIMIT);
		const person = await getUserStore(bucketId).create(
			'unverified-person@x.io',
			await Bun.password.hash(PASSWORD),
			false
		);
		const admin = await createAdministrator('super', `mail-${peer}@x.io`);
		const cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(admin))._id}`;

		const response = await elysia.handle(
			new Request(
				`${ISSUER}/admin/api/projects/${bucketId}/users/${person._id}/verification`,
				{ method: 'POST', headers: { cookie, [PEER_HEADER]: peer } }
			)
		);

		expect([
			response.status,
			emailsTo('unverified-person@x.io').length
		]).toEqual([204, 1]);
	});
});
