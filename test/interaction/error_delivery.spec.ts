import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, {
	agent,
	changeClient,
	getHeader,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import {
	adapter,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.js';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.js';
import {
	AUDIENCE,
	REDIRECT_URI,
	SECOND_REDIRECT_URI
} from './error_delivery.config.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { decode } from 'lib/helpers/jwt.js';
import { ISSUER } from 'lib/configs/env.js';
let setup: Setup;

type RequestParameters = NonNullable<
	ConstructorParameters<typeof AuthorizationRequest>[0]
>;

/* An authorization request that needs consent, handed to the consent screen. */
async function atConsent(extra: RequestParameters = {}) {
	const login = await setup.login();
	const auth = new AuthorizationRequest({
		scope: 'openid',
		prompt: 'consent',
		...extra
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie: login }
	});
	const [, , uid] = getHeader(response, 'location').split('/');
	const cookie = [getHeader(response, 'set-cookie'), login].join('; ');
	return { auth, uid, cookie };
}

async function decide(uid: string, cookie: string, action: 'allow' | 'cancel') {
	return agent.ui({ uid }).consent.post({ action }, { headers: { cookie } });
}

/**
 * @proves An authorization request that ends after the end user reached the interaction pages is
 * answered at the client's redirect URI, in the response mode it asked for — and only while the
 * interaction and the client's registration can still be trusted.
 */
describe('an authorization error raised after the interaction', () => {
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'error_delivery' });
	});

	describe('a declined consent', () => {
		it('is delivered as a form post when the request asked for form_post', async () => {
			const { auth, uid, cookie } = await atConsent({
				response_mode: 'form_post'
			});

			const { response, data: page } = await decide(uid, cookie, 'cancel');

			expect(response.status).toBe(200);
			expect(page).toContain(
				`form action="${auth.params.redirect_uri}" method="post"`
			);
			expect(page).toContain(
				'input type="hidden" name="error" value="access_denied"'
			);
			expect(page).toContain(
				`input type="hidden" name="state" value="${auth.params.state}"`
			);
			expect(page).toContain(
				`input type="hidden" name="iss" value="${ISSUER}"`
			);
		});

		it('is delivered as a signed response JWT when the request asked for jwt', async () => {
			const { auth, uid, cookie } = await atConsent({ response_mode: 'jwt' });

			const { response } = await decide(uid, cookie, 'cancel');

			expect(response.status).toBe(303);
			auth.validateClientLocation(response);
			const { payload } = decode(redirectParameter(response, 'response'));
			expect(payload.error).toBe('access_denied');
			expect(payload.state).toBe(auth.params.state);
			expect(payload.iss).toBe(ISSUER);
			expect(payload.aud).toBe(auth.clientId);
			expect(payload.exp).toBeNumber();
		});
	});

	describe('a request that stops being valid before sign-in completes', () => {
		it('delivers invalid_target to the client when the requested resource is withdrawn', async () => {
			const project = await getProjectStore().create({
				name: 'Delivery',
				slug: `delivery-${Math.random()}`,
				ownerGroupId: UNASSIGNED_GROUP_ID
			});
			await getProtectedResourceStore().create({
				namespace: ROOT_NAMESPACE,
				identifier: AUDIENCE,
				projectId: project._id,
				name: 'Delivery API',
				scopes: []
			});
			const { auth, uid, cookie } = await atConsent({ resource: [AUDIENCE] });
			await getProtectedResourceStore().destroy(ROOT_NAMESPACE, AUDIENCE);

			const { response } = await decide(uid, cookie, 'allow');

			expect(response.status).toBe(303);
			auth.validateClientLocation(response);
			auth.validateError(response, 'invalid_target');
			auth.validateState(response);
			auth.validateIss(response);
		});

		it('does not redirect when the client is deleted', async () => {
			const { uid, cookie } = await atConsent();
			const stored = await adapter('Client').find('client');
			if (!stored) throw new Error('the config seeds this client');
			await adapter('Client').destroy('client');
			try {
				const { response, error } = await decide(uid, cookie, 'allow');

				expect(response.headers.get('location')).toBeNull();
				expect(error?.value).toMatchObject({ error: 'invalid_client' });
			} finally {
				await adapter('Client').upsert('client', stored);
			}
		});

		it('does not redirect when the redirect URI is deregistered', async () => {
			const { uid, cookie } = await atConsent({
				redirect_uri: SECOND_REDIRECT_URI
			});
			const undo = await changeClient('client', {
				redirectUris: [REDIRECT_URI]
			});
			try {
				const { response, error } = await decide(uid, cookie, 'allow');

				expect(response.headers.get('location')).toBeNull();
				expect(error?.value).toMatchObject({
					error: 'invalid_redirect_uri'
				});
			} finally {
				await undo();
			}
		});

		it('does not redirect a sign-in resumed from a session other than the one that began it', async () => {
			const { uid, cookie } = await atConsent();
			const interactionCookie = cookie.split('; ')[0];
			const otherSession = await setup.login();

			const { response, error } = await agent.ui({ uid }).resume.get({
				headers: { cookie: [interactionCookie, otherSession].join('; ') }
			});

			expect(response.headers.get('location')).toBeNull();
			expect(error?.value).toMatchObject({ error: 'invalid_request' });
		});
	});

	describe('a declined interaction', () => {
		it('is refused when it is resumed again', async () => {
			const { uid, cookie } = await atConsent();
			await decide(uid, cookie, 'cancel');

			const { response } = await agent
				.ui({ uid })
				.resume.get({ headers: { cookie } });

			expect(response.status).toBe(400);
			expect(response.headers.get('location')).toBeNull();
		});

		it('is refused when consent is submitted again', async () => {
			const { uid, cookie } = await atConsent();
			await decide(uid, cookie, 'cancel');

			const { response } = await decide(uid, cookie, 'allow');

			expect(response.status).toBe(400);
			expect(response.headers.get('location')).toBeNull();
		});
	});
});
