import { afterAll, afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	clearSeededBuckets,
	findSessionSetCookie,
	jsonToFormUrlEncoded,
	seedBucket
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { getUserStore } from 'lib/adapters/index.js';
import { decode } from 'lib/helpers/jwt.js';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import { present } from 'test/shape.js';
import { acmeClient } from './signed_responses.config.js';

const SLUG = 'acmesigned';
const BUCKET_ID = 'acme-signed-bucket';
const CLIENT_ID = 'acme-signed-app';
const CLIENT_SECRET = `${CLIENT_ID}-secret`;
const EMAIL = 'bob@acme-signed.example.com';
const PASSWORD = 'sup3rsecret';
const ACME_ISSUER = `${ISSUER}/${SLUG}`;

function at(path: string, init?: RequestInit) {
	return elysia.handle(new Request(`http://localhost/${SLUG}${path}`, init));
}

function issuerOf(jwt: string) {
	return decode(jwt).payload.iss;
}

/*
 * Whether a response verifies against the key set published at `url`. Every artefact below is also
 * checked against the bucket's own set and the root's, because the issuer a response names and the
 * key it was signed with have to agree: a resource server that trusts the bucket fetches the bucket's
 * keys, and one that skips `iss` must still find no key of the root's.
 */
async function verifiesAgainst(jwt: string, url: string): Promise<boolean> {
	const response = await elysia.handle(new Request(url));
	const set = (await response.json()) as JSONWebKeySet;
	try {
		await jwtVerify(jwt, createLocalJWKSet(set));
		return true;
	} catch {
		return false;
	}
}

async function signedByTheBucketAlone(jwt: string) {
	return {
		bucket: await verifiesAgainst(jwt, `${ACME_ISSUER}/jwks`),
		root: await verifiesAgainst(jwt, `${ISSUER}/jwks`)
	};
}

function authorizationRequest(extra: Record<string, string> = {}) {
	return new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid',
		redirect_uri: acmeClient.redirectUris[0],
		...extra
	});
}

/* Signs the end user in to the bucket through its own screens and returns the session cookie. */
async function signIn(): Promise<string> {
	const prompt = await at(
		`/auth?${jsonToFormUrlEncoded(authorizationRequest().params)}`
	);
	const uid = (prompt.headers.get('location') ?? '')
		.split('/ui/')[1]
		?.split('/')[0];
	const interaction = (prompt.headers.get('set-cookie') ?? '').split(';')[0];

	const loggedIn = await elysia.handle(
		new Request(`http://localhost/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: interaction
			},
			body: new URLSearchParams({ username: EMAIL, password: PASSWORD })
		})
	);
	return present(
		findSessionSetCookie(loggedIn.headers.getSetCookie()),
		'a session cookie'
	).split(';')[0];
}

async function authorize(cookie: string, extra: Record<string, string> = {}) {
	const auth = authorizationRequest(extra);
	const response = await at(`/auth?${jsonToFormUrlEncoded(auth.params)}`, {
		headers: { cookie }
	});
	return {
		auth,
		location: new URL(present(response.headers.get('location'), 'a redirect'))
	};
}

async function accessToken(cookie: string): Promise<string> {
	const { auth, location } = await authorize(cookie);
	const response = await at('/token', {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			grant_type: 'authorization_code',
			code: present(location.searchParams.get('code'), 'a code'),
			redirect_uri: acmeClient.redirectUris[0],
			code_verifier: auth.code_verifier,
			client_id: CLIENT_ID,
			client_secret: CLIENT_SECRET
		})
	});
	const body = (await response.json()) as { access_token?: string };
	return present(body.access_token, 'an access token');
}

/* Signs out at the bucket, following the confirmation page the browser is shown. */
async function signOut(cookie: string) {
	const page = await at('/logout', {
		headers: { cookie, accept: 'text/html' }
	});
	const pageCookie =
		findSessionSetCookie(page.headers.getSetCookie())?.split(';')[0] ?? cookie;
	const match =
		/name="xsrf"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="xsrf"/.exec(
			await page.text()
		);
	return at('/logout/confirm', {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
			cookie: `${cookie}; ${pageCookie}`,
			accept: 'text/html'
		},
		body: new URLSearchParams({
			xsrf: present(match?.[1] ?? match?.[2], 'the xsrf secret'),
			logout: 'true'
		})
	});
}

/**
 * @proves Every response the server signs at a named bucket names that bucket as its issuer and is
 * signed with that bucket's own key, so a relying party that checks `iss` against the bucket's metadata
 * accepts it and one trusting another issuer's keys does not.
 */
describe('a signed response from a named bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signed_responses' });
		await seedBucket({
			bucketId: BUCKET_ID,
			slug: SLUG,
			clientId: CLIENT_ID,
			accountId: 'bob',
			client: { ...acmeClient, clientSecret: CLIENT_SECRET }
		});
		await getUserStore(BUCKET_ID).create(
			EMAIL,
			await Bun.password.hash(PASSWORD)
		);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	it('carries the bucket issuer in a signed userinfo response', async () => {
		const token = await accessToken(await signIn());

		const response = await at('/userinfo', {
			headers: { authorization: `Bearer ${token}` }
		});

		expect(response.headers.get('content-type')).toStartWith('application/jwt');
		const jwt = await response.text();
		expect(issuerOf(jwt)).toBe(ACME_ISSUER);
		expect(await signedByTheBucketAlone(jwt)).toEqual({
			bucket: true,
			root: false
		});
	});

	it('carries the bucket issuer in a JWT introspection response', async () => {
		const token = await accessToken(await signIn());

		const response = await at('/token/introspect', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				accept: 'application/token-introspection+jwt'
			},
			body: new URLSearchParams({
				token,
				client_id: CLIENT_ID,
				client_secret: CLIENT_SECRET
			})
		});

		const jwt = await response.text();
		expect(issuerOf(jwt)).toBe(ACME_ISSUER);
		expect(await signedByTheBucketAlone(jwt)).toEqual({
			bucket: true,
			root: false
		});
	});

	it('carries the bucket issuer in a JWT-secured authorization response', async () => {
		const { location } = await authorize(await signIn(), {
			response_mode: 'jwt'
		});

		const jwt = present(
			location.searchParams.get('response'),
			'a JARM response'
		);
		expect(issuerOf(jwt)).toBe(ACME_ISSUER);
		expect(await signedByTheBucketAlone(jwt)).toEqual({
			bucket: true,
			root: false
		});
	});

	it('carries the bucket issuer in the logout token sent when the end user signs out', async () => {
		const cookie = await signIn();
		await authorize(cookie);

		let logoutToken: string | undefined;
		mockHttp('https://acme-signed.example.com')
			.intercept({
				path: '/backchannel',
				method: 'POST',
				body(value: string) {
					logoutToken =
						new URLSearchParams(value).get('logout_token') ?? undefined;
					return true;
				}
			})
			.reply(200);

		await signOut(cookie);

		const jwt = present(logoutToken, 'a logout token');
		expect(issuerOf(jwt)).toBe(ACME_ISSUER);
		expect(await signedByTheBucketAlone(jwt)).toEqual({
			bucket: true,
			root: false
		});
	});
});
