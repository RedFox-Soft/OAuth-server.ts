import { spyOn } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.js';
import type { UserBucket } from 'lib/adapters/types.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { issuerFor } from 'lib/configs/issuer.js';
import type { FederationProvider } from 'lib/federation/types.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { elysia } from 'lib/index.js';
import { SessionPayload } from 'lib/models/session.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { present, shaped } from 'test/shape.js';
import { mock as mockHttp } from '../fetch_mock.js';
import { walk } from '../federation/harness.js';
import { idpStub, type IdpStub } from '../federation/idp_stub.js';
import {
	CLIENT_AT_IDP,
	defaultBucketWith,
	pathBucketWith,
	uniqueOrigin,
	upstreamProvider
} from '../global_token_revocation/helpers.js';
import { agent, findSessionSetCookie, getHeader } from '../test_helper.js';

/*
 * Shared scaffolding for the inbound back-channel logout suites: a bucket whose upstream provider is a stub
 * IdP with keys of its own, a real federated sign-in through it (the only way a session learns where it came
 * from), and a caller that delivers logout tokens the way Keycloak, Auth0 and Ping do.
 */

export { CLIENT_AT_IDP, uniqueOrigin };

export interface Upstream {
	stub: IdpStub;
	provider: FederationProvider;
	bucket: UserBucket;
}

/* A provider of the stub, opted in to back-channel logout, with our client id there as `CLIENT_AT_IDP`. */
export function logoutProvider(
	id: string,
	issuer: string,
	overrides: Partial<FederationProvider> = {}
): FederationProvider {
	return upstreamProvider(id, issuer, {
		acceptsGlobalTokenRevocation: false,
		acceptsBackChannelLogout: true,
		...overrides
	});
}

/*
 * A stub IdP as the opted-in provider of the default bucket — the bucket the spec's clients sign into. Its
 * discovery document is registered once here: the metadata cache is keyed by issuer, so every later read
 * for this origin, sign-in or logout, is served from it.
 */
export async function upstreamOfDefaultBucket(
	label: string,
	overrides: Partial<FederationProvider> = {},
	others: FederationProvider[] = []
): Promise<Upstream> {
	const origin = uniqueOrigin(label);
	const stub = await idpStub(origin);
	stub.expectDiscovery();
	const provider = logoutProvider(label, origin, overrides);
	const bucket = await defaultBucketWith([provider, ...others]);
	return { stub, provider, bucket };
}

/* The same provider as the only one of a path-addressed bucket nobody signs into. */
export async function pathBucketHolding(
	provider: FederationProvider
): Promise<UserBucket> {
	return pathBucketWith([provider]);
}

export function logoutEndpointOf(bucket: UserBucket): string {
	return `${issuerFor(bucket)}/federation/backchannel-logout`;
}

export interface SignedIn {
	accountId: string;
	sessionId: string;
	cookie: string;
	refreshToken: string;
	accessToken: string;
	idToken: string;
	/* Every cookie the server set on the way, as sent. */
	setCookies: string[];
}

/*
 * A person signing in to `client` through the provider, the way a browser does: the authorization request,
 * the three federation hops with the provider answering in between, then the code exchanged. `sid` is what
 * the provider's ID token carries; omit it for a provider that sends none. Consent is not prompted, so the
 * sign-in completes in one interaction.
 *
 * The provider's key set is published on the first sign-in against its origin only (the stub knows), and its
 * discovery document was registered by `upstreamOfDefaultBucket`.
 */
export async function signInThroughProvider(
	upstream: Upstream,
	options: {
		sub: string;
		sid?: string;
		email?: string;
		clientId?: string;
		scope?: string;
		cookie?: string;
	}
): Promise<SignedIn> {
	/* Restored on the way out, so a later authorization in the same case is prompted as a real one is. */
	const prompts = spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(
		false
	);
	try {
		return await federatedSignIn(upstream, options);
	} finally {
		prompts.mockRestore();
	}
}

async function federatedSignIn(
	upstream: Upstream,
	options: Parameters<typeof signInThroughProvider>[1]
): Promise<SignedIn> {
	const clientId = options.clientId ?? 'client';
	const scope = options.scope ?? 'openid offline_access';
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope,
		prompt: 'consent'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: options.cookie ? { cookie: options.cookie } : {}
	});
	const location = getHeader(response, 'location');
	const uid = present(location.split('/')[2], 'the interaction uid');
	const interactionCookie = present(
		response.headers.get('set-cookie'),
		'the interaction cookie'
	);

	const { complete } = await walk(
		uid,
		interactionCookie,
		{
			idp: upstream.stub,
			claims: {
				sub: options.sub,
				email: options.email ?? `${options.sub}@example.com`,
				...(options.sid ? { sid: options.sid } : {})
			},
			opts: { audience: CLIENT_AT_IDP }
		},
		{ providerId: upstream.provider.id }
	);
	if (complete?.status !== 303) {
		throw new Error(
			`the federated sign-in did not complete (status ${String(complete?.status)}): ${complete?.text.slice(0, 300) ?? 'no response'}`
		);
	}
	const consent = await consented(
		complete.location,
		complete.setCookies.map((set) => set.split(';')[0] ?? '')
	);
	const code = present(
		new URL(consent.location).searchParams.get('code'),
		'the authorization code'
	);
	const { data } = await auth.getToken(code);
	/* The last session cookie set wins: a resumed sign-in rotates the session's id. */
	const sessionCookie = present(
		present(
			findSessionSetCookie([...consent.setCookies, ...complete.setCookies]),
			'the session cookie'
		).split(';')[0],
		'the session cookie pair'
	);
	const sessionId = present(sessionCookie.split('=')[1], 'the session id');
	return {
		accountId: present(sessionRecord(sessionId)?.accountId, 'the account'),
		sessionId,
		cookie: sessionCookie,
		refreshToken: data?.refresh_token ?? '',
		accessToken: data?.access_token ?? '',
		idToken: data?.id_token ?? '',
		setCookies: [
			...response.headers.getSetCookie(),
			...complete.setCookies,
			...consent.setCookies
		]
	};
}

/*
 * A second relying party authorized in the same browser session, without offline access: no sign-in, only
 * its consent. Answers its access token, and the session's id afterwards — a resumed authorization rotates it.
 */
export async function authorizeInSession(
	signedIn: SignedIn,
	clientId: string
): Promise<{ accessToken: string; sessionId: string }> {
	const prompts = spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(
		false
	);
	try {
		return await consentedInSession(signedIn, clientId);
	} finally {
		prompts.mockRestore();
	}
}

async function consentedInSession(
	signedIn: SignedIn,
	clientId: string
): Promise<{ accessToken: string; sessionId: string }> {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		prompt: 'consent'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie: signedIn.cookie }
	});
	const consent = await consented(getHeader(response, 'location'), [
		signedIn.cookie,
		...response.headers.getSetCookie().map((set) => set.split(';')[0] ?? '')
	]);
	const code = present(
		new URL(consent.location).searchParams.get('code'),
		'the authorization code'
	);
	const { data } = await auth.getToken(code);
	const rotated = findSessionSetCookie([
		...consent.setCookies,
		...response.headers.getSetCookie()
	]);
	return {
		accessToken: present(data?.access_token, 'an access token'),
		sessionId: rotated
			? present(rotated.split(';')[0]?.split('=')[1], 'the session id')
			: signedIn.sessionId
	};
}

/*
 * Consent is its own interaction after the sign-in, under a uid of its own; a person allowing it is what
 * lets `offline_access` be granted. Answers where the browser goes next — the client's callback — and the
 * cookies set on the way.
 */
async function consented(
	location: string,
	cookies: string[]
): Promise<{ location: string; setCookies: string[] }> {
	const consentUid = /^\/ui\/([^/]+)\/consent/.exec(location)?.[1];
	if (!consentUid) return { location, setCookies: [] };
	const response = await elysia.handle(
		new Request(`http://e.ly/ui/${consentUid}/consent`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: cookies.filter(Boolean).join('; ')
			},
			body: new URLSearchParams({ action: 'allow' }).toString()
		})
	);
	return {
		location: present(response.headers.get('location'), 'where consent leads'),
		setCookies: response.headers.getSetCookie()
	};
}

/* A stored session, read as the server reads it; `undefined` once it has ended. */
export function sessionRecord(sessionId: string) {
	const stored = TestAdapter.for('Session').syncFind(sessionId);
	return stored === undefined ? undefined : shaped(SessionPayload, stored);
}

export interface LogoutResponse {
	status: number;
	text: string;
	json: Record<string, unknown>;
	headers: Headers;
}

/* POST a logout token to `url`, form-encoded, as Back-Channel Logout 1.0 §2.5 delivers it. */
export async function sendLogout(
	url: string,
	token: string | undefined,
	options: { rawBody?: string; contentType?: string } = {}
): Promise<LogoutResponse> {
	const response = await elysia.handle(
		new Request(url, {
			method: 'POST',
			headers: {
				'content-type':
					options.contentType ?? 'application/x-www-form-urlencoded'
			},
			body:
				options.rawBody ??
				(token === undefined
					? ''
					: new URLSearchParams({ logout_token: token }).toString())
		})
	);
	const text = await response.text();
	let json: Record<string, unknown>;
	try {
		json = text ? JSON.parse(text) : {};
	} catch {
		json = { raw: text };
	}
	return { status: response.status, text, json, headers: response.headers };
}

/* The relying party at `origin` accepting `times` logout notices, each recorded as it arrives. */
export function relyingPartyListening(
	origin: string,
	times = 1
): { delivered: string[] } {
	const delivered: string[] = [];
	for (let i = 0; i < times; i += 1) {
		mockHttp(origin)
			.intercept({
				path: '/backchannel_logout',
				method: 'POST',
				body(value) {
					delivered.push(value);
					return true;
				}
			})
			.reply(200);
	}
	return { delivered };
}

/* Links an account of the default bucket to a provider's subject, as an earlier federated sign-in would have. */
export async function linkTo(
	accountId: string,
	providerId: string,
	sub: string
): Promise<void> {
	await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
		federated: [{ providerId, sub, linkedAt: new Date() }]
	});
}

/* A refresh token redeemed by `client`, as the relying party would. */
export function refresh(refreshToken: string) {
	return agent.token.post(
		{ grant_type: 'refresh_token', refresh_token: refreshToken },
		{ headers: AuthorizationRequest.basicAuthHeader('client', 'secret') }
	);
}

/* An access token asked about by the relying party it was issued to. */
export async function introspect(clientId: string, token: string) {
	const { data } = await agent.token.introspect.post(
		{ token },
		{ headers: AuthorizationRequest.basicAuthHeader(clientId, 'secret') }
	);
	return data;
}

/*
 * The provider's key set, served once more for the logout: the receiver reads a presented token's keys
 * through a cache of its own, apart from the sign-in's (lib/federation/jwks.ts).
 */
export async function keysServedForLogout(stub: IdpStub): Promise<void> {
	await stub.expectJwks();
}

/* A new authorization request at `client` in this browser: where it sends the person. */
export async function nextAuthorization(cookie: string): Promise<string> {
	const auth = new AuthorizationRequest({
		client_id: 'client',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie }
	});
	return getHeader(response, 'location');
}

const PASSWORD = 'correct horse battery staple';

export function cookiesOf(response: Response): string[] {
	return response.headers.getSetCookie().map((set) => set.split(';')[0] ?? '');
}

/* An account holding a password, in the bucket the spec's clients sign into. */
export async function passwordAccount(email: string) {
	return getUserStore(DEFAULT_BUCKET_ID).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
}

/* The password form of an interaction, as a browser posts it; answers the session id the sign-in left. */
export async function passwordSignIn(
	uid: string,
	cookies: string[],
	email: string,
	fallbackSessionId?: string
): Promise<string> {
	const response = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: cookies.filter(Boolean).join('; ')
			},
			body: new URLSearchParams({ username: email, password: PASSWORD })
		})
	);
	const session = findSessionSetCookie(response.headers.getSetCookie());
	return present(
		session?.split(';')[0]?.split('=')[1] ?? fallbackSessionId,
		'the session the password sign-in left'
	);
}

/* A fresh browser signing in to `client` with a password; answers the session it made. */
export async function signInWithPassword(email: string): Promise<string> {
	const auth = new AuthorizationRequest({
		client_id: 'client',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = present(
		response.headers.get('location')?.split('/')[2],
		'the interaction'
	);
	return passwordSignIn(uid, cookiesOf(response), email);
}
