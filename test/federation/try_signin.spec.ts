import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach,
	setSystemTime
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import {
	adminSessionStore,
	getActivityStore,
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import type { User, UserBucket } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { monthOf } from 'lib/activity/periods.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { createEndUser } from 'lib/end_users/service.ts';
import { createConnection } from 'lib/provisioning/service.ts';
import { TestAdapter } from 'test/models.js';
import { shaped } from 'test/shape.js';
import { createAdministrator } from '../administrators.ts';
import { admin } from '../provisioning/helpers.ts';
import { idpStub } from './idp_stub.ts';
import {
	CLIENT,
	get,
	provider,
	seedBucket,
	signedInAccountIds,
	startInteraction,
	walk
} from './harness.ts';

const noAudit = async () => undefined;

const Started = Type.Object({
	tryRef: Type.String(),
	authorizationUrl: Type.String(),
	expiresAt: Type.String()
});
const Account = Type.Object({
	id: Type.String(),
	email: Type.Optional(Type.String())
});
const Result = Type.Object({
	providerEnabled: Type.Boolean(),
	callbackProvisional: Type.Boolean(),
	answer: Type.Optional(
		Type.Object({
			subject: Type.String(),
			email: Type.Optional(Type.String()),
			emailVerified: Type.Optional(Type.Boolean()),
			claims: Type.Record(Type.String(), Type.Unknown())
		})
	),
	outcome: Type.Optional(
		Type.Object({
			kind: Type.String(),
			reason: Type.Optional(Type.String()),
			account: Type.Optional(Account),
			verified: Type.Optional(Type.Boolean()),
			connection: Type.Optional(
				Type.Object({ id: Type.String(), displayName: Type.String() })
			)
		})
	),
	error: Type.Optional(
		Type.Object({
			stage: Type.String(),
			reason: Type.String(),
			description: Type.Optional(Type.String())
		})
	)
});
const Done = Type.Object({ status: Type.Literal('done'), result: Result });

/* A console session for `user` lasting an hour, so a case that moves the clock past a try outlives it. */
async function consoleSession(user: User): Promise<string> {
	const personal = await ensurePersonalGroup(user._id, user.email);
	const session = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		activeGroupId: personal._id,
		tokens: {},
		ttlSeconds: 3600,
		absoluteTtlSeconds: 7200
	});
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function bucketFor(
	origin: string,
	overrides: Parameters<typeof provider>[1] = {},
	fields: Record<string, unknown> = {}
): Promise<UserBucket> {
	/* No address of its own, so the suite's client reaches it at the root where its interactions start. */
	const id = await seedBucket(CLIENT, {
		federation: [provider(origin, overrides)],
		...fields
	});
	return (await getBucketStore().find(id)) as UserBucket;
}

function tryPath(bucket: UserBucket): string {
	return `/admin/api/projects/${bucket._id}/federation/acme-sso/try`;
}

async function start(bucket: UserBucket, cookie: string) {
	const reply = await admin('POST', tryPath(bucket), cookie);
	expect(reply.status).toBe(201);
	return shaped(Started, reply.body);
}

/* The provider sends the browser back, carrying no cookie, as a cross-site navigation does. */
async function comeBack(
	authorizationUrl: string,
	extra: Record<string, string> = {}
) {
	const state = new URL(authorizationUrl).searchParams.get('state') ?? '';
	return get(
		`/federation/callback?${new URLSearchParams({ code: 'upstream-code', state, ...extra }).toString()}`
	);
}

async function resultOf(bucket: UserBucket, tryRef: string, cookie: string) {
	return admin('GET', `${tryPath(bucket)}/${tryRef}`, cookie);
}

/* A whole try: started, answered by the provider with `claims`, and its result read. */
async function tryOnce(
	origin: string,
	bucket: UserBucket,
	cookie: string,
	claims: Record<string, unknown>
) {
	const idp = await idpStub(origin);
	idp.expectDiscovery();
	const started = await start(bucket, cookie);
	await idp.answerToken(new URL(started.authorizationUrl), claims);
	const page = await comeBack(started.authorizationUrl);
	const read = await resultOf(bucket, started.tryRef, cookie);
	expect(read.status).toBe(200);
	return { page, started, result: shaped(Done, read.body).result };
}

function handoffCount(): number {
	let count = 0;
	for (const [, value] of TestAdapter.for('FederationState').store) {
		if (
			typeof value === 'object' &&
			!Array.isArray(value) &&
			value.stage === 'complete'
		) {
			count += 1;
		}
	}
	return count;
}

/**
 * @proves An administrator can try a sign-in through a bucket's provider — enabled or not — and see what the
 * provider answered and what a real sign-in would do now, by the same rules, while nothing a sign-in writes is
 * written; the result belongs to the console session that started the try and to nobody else, for ten
 * minutes; and whether a round trip is a try is decided by what was stored, never by the returning request
 * (spec 088, User Story 3).
 */
describe('trying a sign-in through a provider', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
		cookie = await consoleSession(await createAdministrator('super'));
	});

	afterEach(() => {
		setSystemTime();
		ApplicationConfig['federation.enabled'] = true;
	});

	it('reports a link to the account holding the verified address, and stores no link', async () => {
		const bucket = await bucketFor(
			'https://idp-try-link.test',
			{ emailTrusted: true },
			{ passwordLogin: false }
		);
		const existing = await getUserStore(bucket._id).create(
			'owner@acme.test',
			'hash',
			true
		);

		const { result } = await tryOnce(
			'https://idp-try-link.test',
			bucket,
			cookie,
			{
				email: 'owner@acme.test',
				email_verified: true
			}
		);

		expect(result.outcome).toMatchObject({
			kind: 'link',
			account: { id: existing._id, email: 'owner@acme.test' }
		});
		expect(
			(await getUserStore(bucket._id).find(existing._id))?.federated ?? []
		).toEqual([]);
	});

	it('reports a new account for a provider that creates them, and creates none', async () => {
		const bucket = await bucketFor('https://idp-try-new.test', {
			emailTrusted: true
		});

		const { result } = await tryOnce(
			'https://idp-try-new.test',
			bucket,
			cookie,
			{
				email: 'new@acme.test',
				email_verified: true
			}
		);

		expect(result.outcome).toEqual({ kind: 'provision', verified: true });
		expect(await getUserStore(bucket._id).list()).toEqual([]);
	});

	it('reports what the provider answered, without the claims that describe only the exchange', async () => {
		const bucket = await bucketFor('https://idp-try-answer.test');

		const { result } = await tryOnce(
			'https://idp-try-answer.test',
			bucket,
			cookie,
			{
				email: 'who@acme.test',
				email_verified: false,
				name: 'Who Ever'
			}
		);

		expect(result.answer).toMatchObject({
			subject: 'upstream-subject-1',
			email: 'who@acme.test',
			emailVerified: false
		});
		expect(result.answer?.claims.name).toBe('Who Ever');
		expect(Object.keys(result.answer?.claims ?? {})).not.toContain('nonce');
	});

	it('reports the refusal of an address outside the allowed domains', async () => {
		const bucket = await bucketFor('https://idp-try-domain.test', {
			allowedEmailDomains: ['example.com']
		});

		const { result } = await tryOnce(
			'https://idp-try-domain.test',
			bucket,
			cookie,
			{
				email: 'someone@acme.org'
			}
		);

		expect(result.outcome).toEqual({
			kind: 'refuse',
			reason: 'domain_not_allowed'
		});
	});

	it('names the account a linked identity would sign in', async () => {
		const bucket = await bucketFor('https://idp-try-linked.test');
		const linked = await getUserStore(bucket._id).create(
			'l@acme.test',
			'h',
			true
		);
		await getUserStore(bucket._id).update(linked._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: 'upstream-subject-1',
					linkedAt: new Date()
				}
			]
		});

		const { result } = await tryOnce(
			'https://idp-try-linked.test',
			bucket,
			cookie,
			{
				email: 'l@acme.test'
			}
		);

		expect(result.outcome).toMatchObject({
			kind: 'signin',
			account: { id: linked._id }
		});
	});

	it('reports that the account’s password would be asked for first, and stores no pending link', async () => {
		const bucket = await bucketFor('https://idp-try-password.test', {
			emailTrusted: true
		});
		const existing = await getUserStore(bucket._id).create(
			'pw@acme.test',
			'hash',
			true
		);

		const { result } = await tryOnce(
			'https://idp-try-password.test',
			bucket,
			cookie,
			{
				email: 'pw@acme.test',
				email_verified: true
			}
		);

		expect(result.outcome).toMatchObject({
			kind: 'password_required',
			account: { id: existing._id }
		});
		expect(handoffCount()).toBe(0);
	});

	it('reports which provisioned person a provider bound to a directory would match', async () => {
		const bucket = await bucketFor('https://idp-try-correlate.test', {
			emailTrusted: true
		});
		const connection = await createConnection(
			bucket,
			{
				displayName: 'Contoso directory',
				providerId: 'acme-sso',
				correlation: { claim: 'oid', attribute: 'externalId' }
			},
			noAudit
		);
		const provisioned = await createEndUser(
			(await getBucketStore().find(bucket._id)) as UserBucket,
			{ kind: 'connection', connectionId: connection._id },
			{
				id: crypto.randomUUID().replaceAll('-', ''),
				email: 'rita@contoso.com',
				userName: 'rita@contoso.com',
				externalId: 'oid-rita',
				verified: true
			},
			noAudit
		);

		const { result } = await tryOnce(
			'https://idp-try-correlate.test',
			bucket,
			cookie,
			{
				oid: 'oid-rita',
				email: 'rita@contoso.com'
			}
		);

		expect(result.outcome).toMatchObject({
			kind: 'correlate',
			account: { id: provisioned._id },
			connection: { id: connection._id, displayName: 'Contoso directory' }
		});
		expect(
			(await getUserStore(bucket._id).find(provisioned._id))?.federated ?? []
		).toEqual([]);
	});

	it('signs nobody in, hands nothing back and records no sign-in activity', async () => {
		const bucket = await bucketFor('https://idp-try-nothing.test', {
			emailTrusted: true
		});
		const sessionsBefore = signedInAccountIds();
		const month = monthOf(new Date());

		const { page } = await tryOnce(
			'https://idp-try-nothing.test',
			bucket,
			cookie,
			{
				email: 'nobody@acme.test',
				email_verified: true
			}
		);

		expect(page.status).toBe(200);
		expect(page.location).toBe('');
		expect(page.text).toContain('Try finished');
		expect(signedInAccountIds()).toEqual(sessionsBefore);
		expect(handoffCount()).toBe(0);
		expect(
			(await getActivityStore().count(bucket._id, month, new Date())).total
		).toBe(0);
	});

	it('tries a disabled provider and says it is off', async () => {
		const bucket = await bucketFor('https://idp-try-off.test', {
			enabled: false,
			emailTrusted: true
		});

		const { result } = await tryOnce(
			'https://idp-try-off.test',
			bucket,
			cookie,
			{
				email: 'x@acme.test',
				email_verified: true
			}
		);

		expect(result.providerEnabled).toBe(false);
		expect(result.outcome?.kind).toBe('provision');
	});

	it('still refuses a real sign-in through a disabled provider that was tried', async () => {
		const bucket = await bucketFor('https://idp-try-off-real.test', {
			enabled: false
		});
		await tryOnce('https://idp-try-off-real.test', bucket, cookie, {
			email: 'x@acme.test'
		});
		const { uid, cookie: interaction } = await startInteraction();

		const begun = await get(
			`/ui/${uid}/federation/acme-sso/start`,
			interaction
		);

		expect(begun.location).not.toContain('idp-try-off-real.test');
		expect(begun.status).not.toBe(303);
	});

	it('shows the error the provider returned instead of an identity', async () => {
		const bucket = await bucketFor('https://idp-try-declined.test');
		const idp = await idpStub('https://idp-try-declined.test');
		idp.expectDiscovery();
		const started = await start(bucket, cookie);

		await comeBack(started.authorizationUrl, {
			error: 'access_denied',
			error_description: 'The user cancelled'
		});
		const read = await resultOf(bucket, started.tryRef, cookie);

		expect(shaped(Done, read.body).result.error).toEqual({
			stage: 'declined',
			reason: 'access_denied',
			description: 'The user cancelled'
		});
	});

	it('says it is still waiting until the provider sends the browser back', async () => {
		const bucket = await bucketFor('https://idp-try-waiting.test');
		const idp = await idpStub('https://idp-try-waiting.test');
		idp.expectDiscovery();
		const started = await start(bucket, cookie);

		const read = await resultOf(bucket, started.tryRef, cookie);

		expect(read.status).toBe(200);
		expect(read.json).toEqual({ status: 'waiting' });
	});

	it('shows the result to no other console session, even the same administrator’s', async () => {
		const user = await createAdministrator('super');
		const mine = await consoleSession(user);
		const another = await consoleSession(user);
		const bucket = await bucketFor('https://idp-try-session.test');
		const idp = await idpStub('https://idp-try-session.test');
		idp.expectDiscovery();
		const started = await start(bucket, mine);
		await idp.answerToken(new URL(started.authorizationUrl), {
			email: 's@acme.test'
		});
		await comeBack(started.authorizationUrl);

		const read = await resultOf(bucket, started.tryRef, another);

		expect(read.status).toBe(404);
	});

	it('shows no result once ten minutes have passed', async () => {
		const bucket = await bucketFor('https://idp-try-expired.test');
		const idp = await idpStub('https://idp-try-expired.test');
		idp.expectDiscovery();
		const now = new Date();
		setSystemTime(now);
		const started = await start(bucket, cookie);

		setSystemTime(new Date(now.getTime() + 11 * 60 * 1000));
		const read = await resultOf(bucket, started.tryRef, cookie);

		expect(read.status).toBe(404);
	});

	it('finishes a sign-in as a sign-in whatever the returning request claims to be', async () => {
		const origin = 'https://idp-try-inject.test';
		await bucketFor(origin);
		const idp = await idpStub(origin);
		idp.expectDiscovery();
		const { uid, cookie: interaction } = await startInteraction();

		const { callback } = await walk(
			uid,
			interaction,
			{ idp, claims: { email: 'inject@acme.test' } },
			{ extraReturnParams: { purpose: 'try', tryRef: 'forged' } }
		);

		expect(callback.location).toStartWith(`/ui/${uid}/federation/complete`);
	});

	it('finishes a try as a try, never inside an interaction', async () => {
		const bucket = await bucketFor('https://idp-try-not-signin.test');

		const { page } = await tryOnce(
			'https://idp-try-not-signin.test',
			bucket,
			cookie,
			{
				email: 'n@acme.test'
			}
		);

		expect(page.location).toBe('');
		expect(page.setCookies).toEqual([]);
	});

	it('refuses to start a try while federation is switched off', async () => {
		const bucket = await bucketFor('https://idp-try-switched-off.test');
		ApplicationConfig['federation.enabled'] = false;

		const reply = await admin('POST', tryPath(bucket), cookie);

		expect(reply.status).toBe(409);
	});

	it('tells the console a try cannot start while federation is switched off', async () => {
		const bucket = await bucketFor('https://idp-try-capability.test');
		ApplicationConfig['federation.enabled'] = false;

		const reply = await admin(
			'GET',
			`/admin/api/projects/${bucket._id}/federation/acme-sso`,
			cookie
		);

		expect(reply.json.capabilities).toMatchObject({ trySignIn: false });
	});

	it('refuses to start a try without a console session', async () => {
		const bucket = await bucketFor('https://idp-try-no-session.test');

		const reply = await admin('POST', tryPath(bucket), '');

		expect(reply.status).toBe(401);
	});
});
