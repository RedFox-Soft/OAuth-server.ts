import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	setSystemTime,
	spyOn
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import { adapter, adminAuditStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import bootstrap, {
	agent,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { mock as mockHttp } from '../fetch_mock.js';
import { createAdministrator } from '../administrators.ts';
import { sessionFor } from '../admin_session.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { present, shaped } from '../shape.ts';
import { adminCall } from './admin_call.ts';
import { adminCookie, defaultBucket } from './fixtures.ts';

const APPLICATIONS = {
	client: 'https://client.example.com',
	'second-client': 'https://second-client.example.com'
} as const;
type ClientId = keyof typeof APPLICATIONS;

const Row = Type.Object({
	clientId: Type.Union([Type.String(), Type.Null()]),
	clientName: Type.Union([Type.String(), Type.Null()]),
	signedInAt: Type.Union([Type.String(), Type.Null()]),
	lastTokenAt: Type.Union([Type.String(), Type.Null()]),
	offline: Type.Boolean()
});
const Applications = Type.Object({ applications: Type.Array(Row) });

interface SignedInTwice {
	accountId: string;
	sessionId: string;
	refreshTokens: Record<ClientId, string>;
}

/* A person signed in once and authorized at both applications, each holding an offline refresh token. */
async function signedInToBoth(setup: Setup): Promise<SignedInTwice> {
	spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	const scope = 'openid offline_access';
	const cookie = await setup.login({ scope });
	const refreshTokens = { client: '', 'second-client': '' };
	for (const clientId of Object.keys(APPLICATIONS) as ClientId[]) {
		const auth = new AuthorizationRequest({
			client_id: clientId,
			scope,
			prompt: 'consent',
			redirect_uri: `${APPLICATIONS[clientId]}/cb`
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});
		const { data } = await auth.getToken(redirectParameter(response, 'code'));
		refreshTokens[clientId] = present(data?.refresh_token, 'a refresh token');
	}
	return {
		accountId: present(setup.getSession().accountId, 'accountId'),
		sessionId: setup.getSessionId(),
		refreshTokens
	};
}

function refreshAs(clientId: ClientId, refreshToken: string) {
	return agent.token.post(
		{ grant_type: 'refresh_token', refresh_token: refreshToken },
		{ headers: AuthorizationRequest.basicAuthHeader(clientId, 'secret') }
	);
}

async function applicationsOf(cookie: string, uid: string) {
	const res = await adminCall(
		cookie,
		'GET',
		`/admin/api/buckets/${DEFAULT_BUCKET_ID}/users/${uid}/sessions`
	);
	expect(res.status).toBe(200);
	return { raw: res.body, ...shaped(Applications, res.body) };
}

function signOutOf(cookie: string, uid: string, clientId: string) {
	return adminCall(
		cookie,
		'POST',
		`/admin/api/buckets/${DEFAULT_BUCKET_ID}/users/${uid}/sessions/${encodeURIComponent(clientId)}/sign-out`
	);
}

/* Records which applications were sent a logout notice. */
function captureLogouts(): Set<string> {
	const told = new Set<string>();
	for (const [clientId, host] of Object.entries(APPLICATIONS)) {
		mockHttp(host)
			.intercept({
				path: '/backchannel_logout',
				method: 'POST',
				body() {
					told.add(clientId);
					return true;
				}
			})
			.reply(200);
	}
	return told;
}

function storedSession(id: string) {
	return adapter('Session').find(id);
}

/**
 * @proves An administrator sees which applications a person is signed in to, and signs them out of one: that
 * application's tokens stop working, offline ones included, and only it is told, while the person's other
 * application and their sign-in carry on as they were.
 */
describe('a person’s sessions, one application at a time', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await defaultBucket();
		cookie = await adminCookie();
	});

	afterEach(() => {
		setSystemTime();
		mock.restore();
		mockHttp.restore();
	});

	it('lists each application with its name and times', async () => {
		const person = await signedInToBoth(setup);

		const { applications } = await applicationsOf(cookie, person.accountId);

		expect(
			applications.map((row) => [row.clientId, row.clientName]).sort()
		).toEqual([
			['client', 'Checkout'],
			['second-client', null]
		]);
		for (const row of applications) {
			expect(row.signedInAt).not.toBeNull();
			expect(row.lastTokenAt).not.toBeNull();
			expect(row.offline).toBe(false);
		}
	});

	it('names no network address, browser or device', async () => {
		const person = await signedInToBoth(setup);

		const { raw } = await applicationsOf(cookie, person.accountId);

		expect(JSON.stringify(raw)).not.toMatch(/"(ip|userAgent|user_agent)"/i);
	});

	it('shows access an application keeps after the sign-in ended as offline', async () => {
		const person = await signedInToBoth(setup);
		await adapter('Session').destroy(person.sessionId);

		const { applications } = await applicationsOf(cookie, person.accountId);

		expect(applications.map((row) => row.offline)).toEqual([true, true]);
	});

	it('ends that application’s refresh token, offline access included', async () => {
		const person = await signedInToBoth(setup);
		captureLogouts();

		const res = await signOutOf(cookie, person.accountId, 'client');

		expect(res.status).toBe(204);
		const { error } = await refreshAs('client', person.refreshTokens.client);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
	});

	it('leaves the other application’s refresh token working', async () => {
		const person = await signedInToBoth(setup);
		captureLogouts();

		await signOutOf(cookie, person.accountId, 'client');

		const { data } = await refreshAs(
			'second-client',
			person.refreshTokens['second-client']
		);
		expect(data).toHaveProperty('access_token');
	});

	it('keeps the sign-in, with the other application in it and its lifetime unchanged', async () => {
		const person = await signedInToBoth(setup);
		captureLogouts();
		const expiresAt = present(
			await storedSession(person.sessionId),
			'session'
		).exp;
		/* An hour on, so a save that renewed the full lifetime would show in `exp`. */
		setSystemTime(new Date(Date.now() + 60 * 60 * 1000));
		const laterCookie = await adminCookie();

		await signOutOf(laterCookie, person.accountId, 'client');

		const after = present(await storedSession(person.sessionId), 'session');
		const authorizations = shaped(
			Type.Object({
				authorizations: Type.Record(Type.String(), Type.Unknown())
			}),
			after
		).authorizations;
		expect(Object.keys(authorizations)).toEqual(['second-client']);
		expect(after.exp).toBe(expiresAt);
	});

	it('tells only the application signed out of', async () => {
		const person = await signedInToBoth(setup);
		const told = captureLogouts();

		await signOutOf(cookie, person.accountId, 'client');

		expect([...told]).toEqual(['client']);
	});

	it('records the act naming the application', async () => {
		const person = await signedInToBoth(setup);
		captureLogouts();

		await signOutOf(cookie, person.accountId, 'client');

		const { entries } = await adminAuditStore.list({
			action: 'enduser.application.signout',
			targetId: person.accountId
		});
		expect(entries.map((e) => [e.targetScope, e.clientId])).toEqual([
			[DEFAULT_BUCKET_ID, 'client']
		]);
	});

	it('answers 404 for an application the person is not signed in to', async () => {
		const person = await signedInToBoth(setup);

		const res = await signOutOf(cookie, person.accountId, 'never-used-app');

		expect(res.status).toBe(404);
	});

	it('refuses an administrator without access to the bucket’s users', async () => {
		const person = await signedInToBoth(setup);
		const outsider = await createAdministrator();
		const outsiderCookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(outsider))._id}`;

		const read = await adminCall(
			outsiderCookie,
			'GET',
			`/admin/api/buckets/${DEFAULT_BUCKET_ID}/users/${person.accountId}/sessions`
		);
		const signOut = await signOutOf(outsiderCookie, person.accountId, 'client');

		expect([read.status, signOut.status]).toEqual([403, 403]);
	});
});
