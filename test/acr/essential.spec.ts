import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, {
	agent,
	getHeader,
	locationParameter,
	SESSION_COOKIE_PREFIX
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { idTokenOf } from './response.ts';

const PASSWORD = 'correct horse battery';
const PWD = 'urn:example:acr:pwd';
const MFA = 'urn:example:acr:mfa';

let bucketId: string;

async function seedBucket(name: string, clientId: string): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug: `${clientId}-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	return bucket._id;
}

async function seedUser(email: string) {
	return getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		[],
		true
	);
}

function requiring(values: string[] | string, extra = {}) {
	return new AuthorizationRequest({
		client_id: 'acr-app',
		scope: 'openid',
		claims: {
			id_token: {
				acr: Array.isArray(values)
					? { essential: true, values }
					: { essential: true, value: values }
			}
		},
		...extra
	});
}

async function startInteraction(auth: AuthorizationRequest) {
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid: location.split('/')[2], cookie, location };
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

// Where a request ended up; fails the case when it was not redirected.
function redirectOf(res: { location: string | null }): string {
	if (!res.location) throw new Error('expected a redirect');
	return res.location;
}

/* Sign in with a password and report where the request ended up. */
async function signIn(auth: AuthorizationRequest, email: string) {
	const { uid, cookie } = await startInteraction(auth);
	const res = await postForm(`/ui/${uid}/login`, cookie, {
		username: email,
		password: PASSWORD
	});
	return { uid, cookie, res };
}

/**
 * @proves A relying party that requires a particular authentication context is answered — with a
 * code when the sign-in meets it, and with the registered refusal at its redirect_uri when it
 * cannot, rather than with another login page.
 */
describe('a required authentication context', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'acr' });
		resetAdminMemoryStores();
		bucketId = await seedBucket('ACR', 'acr-app');
	});

	it('returns an authorization code carrying the satisfied context when the sign-in meets it', async () => {
		const email = `met-${Math.random()}@x.io`;
		await seedUser(email);
		const auth = requiring([PWD]);

		const { res } = await signIn(auth, email);

		expect(res.status).toBe(303);
		expect(res.location ?? '').toContain('/acr/callback');
		const code = locationParameter(redirectOf(res), 'code');

		const token = await auth.getToken(code);
		expect(token.response.status).toBe(200);
		expect(decodeJWT(idTokenOf(token)).payload.acr).toBe(PWD);
	});

	it('ends at the redirect_uri with unmet_authentication_requirements when the sign-in cannot meet it', async () => {
		const email = `unmet-${Math.random()}@x.io`;
		await seedUser(email);
		const auth = requiring([MFA]);

		const { res } = await signIn(auth, email);

		expect(res.status).toBe(303);
		const location = new URL(redirectOf(res));
		expect(`${location.origin}${location.pathname}`).toBe(
			'http://e.ly/acr/callback'
		);
		expect(location.searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
		expect(Object.fromEntries(location.searchParams)).toHaveProperty(
			'state',
			auth.params.state
		);
		expect(location.searchParams.get('code')).toBeNull();
	});

	it('presents no second login page when the authentication just performed cannot meet it', async () => {
		const email = `noloop-${Math.random()}@x.io`;
		await seedUser(email);

		const { res } = await signIn(requiring([MFA]), email);

		// The end user's whole complaint: a correct password answered with the login form again.
		expect(res.location ?? '').not.toContain('/ui/');
	});

	it('refuses the single-valued form the same way', async () => {
		const email = `single-${Math.random()}@x.io`;
		await seedUser(email);

		const { res } = await signIn(requiring(MFA), email);

		expect(new URL(redirectOf(res)).searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
	});

	it('refuses without starting an interaction when no interaction was permitted', async () => {
		const email = `none-${Math.random()}@x.io`;
		await seedUser(email);

		// A session that exists and carries the password context, then a request requiring more.
		const first = await signIn(requiring([PWD]), email);
		const session = new RegExp(`(${SESSION_COOKIE_PREFIX}[^=]+=[^;]+)`).exec(
			first.res.setCookie ?? ''
		)?.[1];
		expect(session).toBeTruthy();

		const auth = requiring([MFA], { prompt: 'none' });
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie: session }
		});

		expect(response.status).toBe(303);
		const location = new URL(getHeader(response, 'location'));
		expect(`${location.origin}${location.pathname}`).toBe(
			'http://e.ly/acr/callback'
		);
		expect(location.searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
		expect(Object.fromEntries(location.searchParams)).toHaveProperty(
			'state',
			auth.params.state
		);
	});

	it('refuses a malformed requirement before any login page is shown', async () => {
		const auth = new AuthorizationRequest({
			client_id: 'acr-app',
			scope: 'openid',
			prompt: 'none',
			claims: { id_token: { acr: { essential: true, values: 'not a list' } } }
		});

		const { response } = await agent.auth.get({ query: auth.params });
		const location = new URL(getHeader(response, 'location'));

		expect(location.searchParams.get('error')).toBe('invalid_request');
		expect(location.pathname).not.toContain('/ui/');
	});

	it('issues no token carrying a context that does not match the requirement', async () => {
		const email = `invariant-${Math.random()}@x.io`;
		await seedUser(email);

		const { res } = await signIn(requiring([MFA]), email);
		const location = new URL(redirectOf(res));

		// Nothing to exchange: the refusal is what keeps a mismatched context out of a token.
		expect(location.searchParams.get('code')).toBeNull();
		expect(location.searchParams.get('id_token')).toBeNull();
	});
});
