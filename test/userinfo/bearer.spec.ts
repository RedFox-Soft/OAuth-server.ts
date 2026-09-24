import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent, formAgent } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';

/**
 * @proves UserInfo refuses an absent or malformed credential with a bearer challenge rather than
 * parsing it optimistically.
 */
describe('providing Bearer token', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	describe('invalid requests', () => {
		it('UserInfo without a credential is refused with a bearer challenge', async function () {
			const { error, response } = await agent.userinfo.get();
			if (!error) {
				throw new Error('Have to be exception');
			}
			expect(error.status).toBe(401);
			expect(response.headers.get('www-authenticate')).toBe(
				`Bearer realm="${ISSUER}"`
			);
			/*
			 * RFC 6750 §3.1: a request that carried no credentials at all is told nothing about an
			 * error, because it made none — it was never authenticated. Naming one invites a client to
			 * handle a failure that did not happen.
			 */
			expect(error.value).toBe('');
		});

		it('refuses an Authorization header with only one part', async function () {
			const { error } = await agent.userinfo.get({
				headers: {
					authorization: 'Bearer'
				}
			});
			if (!error) {
				throw new Error('Have to be exception');
			}
			expect(error.status).toBe(401);
			expect(error.value).toEqual({
				error: 'invalid_header_authorization',
				error_description: 'invalid authorization header value format'
			});
		});

		it('refuses an Authorization scheme other than Bearer', async function () {
			const { error } = await agent.userinfo.get({
				headers: {
					authorization: 'Basic some'
				}
			});
			if (!error) {
				throw new Error('Have to be exception');
			}
			expect(error.status).toBe(401);
			expect(error.value).toEqual({
				error: 'invalid_header_authorization',
				error_description: 'authorization header scheme must be `Bearer`'
			});
		});

		it('refuses an access token sent in both the header and the form body', async function () {
			const { error } = await formAgent.userinfo.post(
				{ access_token: 'from-body' },
				{ headers: { authorization: 'Bearer from-header' } }
			);
			if (!error) {
				throw new Error('Have to be exception');
			}
			/*
			 * RFC 6750 §3.1: using more than one mechanism to present the token is `invalid_request`.
			 * Which of the two the server would otherwise have believed is not a question worth
			 * answering — a request that asks two things is refused before it is read.
			 */
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'access token transmitted by more than one method'
			});
		});

		it('refuses a form-body access token accompanied by a DPoP proof', async function () {
			const { error } = await formAgent.userinfo.post(
				{ access_token: 'from-body' },
				{ headers: { dpop: 'a.proof.jwt' } }
			);
			if (!error) {
				throw new Error('Have to be exception');
			}
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'a DPoP-bound access token must be sent in the Authorization header'
			});
		});

		it('refuses an access token sent in a JSON body', async function () {
			const { error, response } = await agent.userinfo.post({
				access_token: 'from-body'
			});
			if (!error) {
				throw new Error('Have to be exception');
			}
			// The form-encoded method (RFC 6750 §2.2) is defined for that encoding and no other, so
			// this request carried no credential the server may read — and is answered as such.
			expect(error.status).toBe(401);
			expect(response.headers.get('www-authenticate')).toBe(
				`Bearer realm="${ISSUER}"`
			);
			expect(error.value).toBe('');
		});

		it('refuses an access token sent in the query string', async function () {
			const { error, response } = await agent.userinfo.get({
				query: { access_token: 'from-query' }
			});
			if (!error) {
				throw new Error('Have to be exception');
			}
			// RFC 6750 §2.3 is not implemented, and OAuth 2.1 removes it: a token in a URL reaches
			// access logs, the Referer header and browser history.
			expect(error.status).toBe(401);
			expect(response.headers.get('www-authenticate')).toBe(
				`Bearer realm="${ISSUER}"`
			);
			expect(error.value).toBe('');
		});
	});
});
