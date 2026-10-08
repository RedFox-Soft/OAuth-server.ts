import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';
import bootstrap, {
	agent,
	getHeader,
	locationParameter,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';
import { ISSUER } from 'lib/configs/env.js';
import { decode } from 'lib/helpers/jwt.js';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { serveDocument, mock } from '../cimd/document_host.js';
import {
	TRUSTED_REDIRECT,
	UNTRUSTED_REDIRECT,
	URL_ID,
	URL_ID_REDIRECT
} from './untrusted_redirect.config.js';

let setup: Setup;

/* A request this server refuses before anyone signs in: a response type it does not support. */
function malformed(extra: Record<string, unknown> = {}) {
	return new AuthorizationRequest({
		scope: 'openid',
		...extra,
		// @ts-expect-error the case sends a response type the schema refuses
		response_type: 'token'
	});
}

/* The link or form action a confirmation page offers, decoded from its HTML. */
function offeredLink(page: string): string {
	const href = /<a href="([^"]+)"/.exec(page)?.[1];
	if (!href) throw new Error('expected a link on the confirmation page');
	return href.replaceAll('&amp;', '&');
}

/**
 * @proves An authorization error for a client whose redirect URIs no operator vouched for is offered
 * on this server's page instead of being redirected, carrying exactly the answer the redirect would
 * have — while trusted clients and successful responses are redirected as before.
 */
describe('an authorization error for a client nobody here vouched for', () => {
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	describe('a request refused before sign-in', () => {
		it('is offered on a confirmation page instead of being redirected for a self-registered client', async () => {
			const auth = malformed({ client_id: 'self-registered' });

			const response = await auth.authorize();

			expect(response.status).toBeGreaterThanOrEqual(400);
			expect(response.headers.get('location')).toBeNull();
		});

		it('names the destination host and not the client’s own name', async () => {
			const auth = malformed({ client_id: 'self-registered' });

			const page = await (await auth.authorize()).text();

			expect(page).toContain('evil.example');
			expect(page).not.toContain('Trusted Bank');
		});

		it('carries the same error, state and issuer the redirect would have', async () => {
			const auth = malformed({ client_id: 'self-registered' });

			const link = offeredLink(await (await auth.authorize()).text());

			expect(link.startsWith(`${UNTRUSTED_REDIRECT}?`)).toBe(true);
			expect(locationParameter(link, 'error')).toBe('invalid_request');
			expect(locationParameter(link, 'state')).toBe(String(auth.params.state));
			expect(locationParameter(link, 'iss')).toBe(ISSUER);
		});

		it('is redirected immediately for a client an administrator created', async () => {
			const auth = malformed({ client_id: 'client' });

			const response = await auth.authorize();

			expect(response.status).toBe(303);
			expect(getHeader(response, 'location').startsWith(TRUSTED_REDIRECT)).toBe(
				true
			);
		});

		it('is redirected immediately for an administrator-created client whose identifier is a URL', async () => {
			const auth = malformed({ client_id: URL_ID });

			const response = await auth.authorize();

			expect(response.status).toBe(303);
			expect(getHeader(response, 'location').startsWith(URL_ID_REDIRECT)).toBe(
				true
			);
		});

		it('refuses to be framed even when its answer is a form posting to another origin', async () => {
			const auth = malformed({
				client_id: 'self-registered',
				response_mode: 'form_post'
			});

			const response = await auth.authorize();

			expect(response.headers.get('x-frame-options')).toBe('DENY');
			expect(response.headers.get('content-security-policy')).toContain(
				"frame-ancestors 'none'"
			);
		});

		it('offers a form-post answer as a form posting the same fields', async () => {
			const auth = malformed({
				client_id: 'self-registered',
				response_mode: 'form_post'
			});

			const page = await (await auth.authorize()).text();

			expect(page).toContain(
				`<form method="post" action="${UNTRUSTED_REDIRECT}">`
			);
			expect(page).toContain(
				'<input type="hidden" name="error" value="invalid_request"/>'
			);
			expect(page).toContain(
				`<input type="hidden" name="state" value="${present(auth.params.state, 'a state')}"/>`
			);
			expect(page).not.toContain('<script');
		});

		it('offers a JWT answer as a link carrying the response JWT', async () => {
			const auth = malformed({
				client_id: 'self-registered',
				response_mode: 'jwt'
			});

			const link = offeredLink(await (await auth.authorize()).text());
			const { payload } = decode(locationParameter(link, 'response'));

			expect(payload.error).toBe('invalid_request');
			expect(payload.state).toBe(auth.params.state);
			expect(payload.aud).toBe('self-registered');
		});
	});

	describe('a client described by a metadata document', () => {
		beforeEach(() => {
			clearDocumentCache();
			resolver.lookup = async () => ['93.184.216.34'];
		});

		afterEach(() => {
			mock.restore();
			resolver.lookup = resolver.realLookup;
		});

		it('has a refused request offered on a confirmation page', async () => {
			const { identifier } = serveDocument();
			const auth = malformed({
				client_id: identifier,
				redirect_uri: 'https://app.example.com/callback'
			});

			const response = await auth.authorize();

			expect(response.status).toBeGreaterThanOrEqual(400);
			expect(response.headers.get('location')).toBeNull();
			expect(await response.text()).toContain('app.example.com');
		});
	});

	describe('after the user has been asked', () => {
		it('offers a declined consent on a confirmation page', async () => {
			const login = await setup.login();
			const auth = new AuthorizationRequest({
				client_id: 'self-registered',
				scope: 'openid',
				prompt: 'consent'
			});
			const { response: started } = await agent.auth.get({
				query: auth.params,
				headers: { cookie: login }
			});
			const [, , uid] = getHeader(started, 'location').split('/');
			const cookie = [getHeader(started, 'set-cookie'), login].join('; ');

			const { response, error } = await agent
				.ui({ uid })
				.consent.post({ action: 'cancel' }, { headers: { cookie } });
			const page = String(error?.value);

			expect(response.status).toBeGreaterThanOrEqual(400);
			expect(response.headers.get('location')).toBeNull();
			expect(page).toContain('You declined the request');
			expect(page).toContain('evil.example');
		});

		it('offers a silent request’s login_required on a confirmation page', async () => {
			const auth = new AuthorizationRequest({
				client_id: 'self-registered',
				scope: 'openid',
				prompt: 'none'
			});

			const response = await auth.authorize();
			const link = offeredLink(await response.text());

			expect(response.status).toBeGreaterThanOrEqual(400);
			expect(locationParameter(link, 'error')).toBe('login_required');
		});

		it('redirects a successful response immediately', async () => {
			const login = await setup.login();
			const auth = new AuthorizationRequest({
				client_id: 'self-registered',
				scope: 'openid'
			});

			const response = await auth.authorize({ headers: { cookie: login } });

			expect(response.status).toBe(303);
			const location = getHeader(response, 'location');
			expect(location.startsWith(UNTRUSTED_REDIRECT)).toBe(true);
			expect(locationParameter(location, 'code')).toBeTruthy();
		});
	});
});
