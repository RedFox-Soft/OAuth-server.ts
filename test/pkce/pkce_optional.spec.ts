import { parse as parseUrl } from 'node:url';
import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent, type Setup, formAgent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';

const POLICY_REFUSAL =
	'Authorization Server policy requires PKCE to be used for this request';

/**
 * @proves On a server that does not require a proof of possession, a client authenticating at the
 * token endpoint may omit the code challenge while one that presents no credentials may not, and
 * a challenge that is supplied still binds the code it issues.
 */
describe('PKCE not required', () => {
	let setup: Setup;
	let cookie = null;
	beforeAll(async function () {
		// Named explicitly: bootstrap derives the config from the DIRECTORY name, so the bare call
		// would load pkce.config.ts and every case here would pass against an instance that still
		// requires the proof — green, and proving nothing.
		setup = await bootstrap(import.meta.url, { config: 'pkce_optional' });
		cookie = await setup.login();
	});

	describe('a client that presents no credentials at the token endpoint', () => {
		it('is refused when it omits a code challenge', async function () {
			const auth = new AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			auth.params.code_challenge = undefined;
			auth.params.code_challenge_method = undefined;

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			auth.validatePresence(response, ['error', 'error_description', 'state']);
			auth.validateError(response, 'invalid_request');
			auth.validateErrorDescription(response, POLICY_REFUSAL);
		});

		it('is refused when it pushes a request omitting a code challenge', async function () {
			const { error } = await formAgent.par.post({
				scope: 'openid',
				response_type: 'code',
				client_id: 'client',
				redirect_uri: 'https://rp.example.com/cb'
			});

			if (!error) throw new Error('expected error response');
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty('error_description', POLICY_REFUSAL);
		});
	});

	describe('a client that authenticates at the token endpoint', () => {
		it('is issued a code when it omits a code challenge', async function () {
			const auth = new AuthorizationRequest({
				client_id: 'confidential-client',
				scope: 'openid'
			});
			auth.params.code_challenge = undefined;
			auth.params.code_challenge_method = undefined;

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			auth.validatePresence(response, ['code', 'state']);

			const {
				query: { code }
			} = parseUrl(response.headers.get('location'), true);
			const stored = TestAdapter.for('AuthorizationCode').syncFind(
				setup.getTokenJti(code)
			);
			expect(stored.codeChallenge).toBeUndefined();
			expect(stored.codeChallengeMethod).toBeUndefined();
		});

		it('is issued a code bound to the code challenge it supplies', async function () {
			const auth = new AuthorizationRequest({
				client_id: 'confidential-client',
				scope: 'openid',
				code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				code_challenge_method: 'S256'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});

			const {
				query: { code }
			} = parseUrl(response.headers.get('location'), true);
			const stored = TestAdapter.for('AuthorizationCode').syncFind(
				setup.getTokenJti(code)
			);
			expect(stored).toHaveProperty('codeChallengeMethod', 'S256');
			expect(stored).toHaveProperty(
				'codeChallenge',
				'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
			);
		});

		it('is refused a code challenge whose method is not S256', async function () {
			const auth = new AuthorizationRequest({
				client_id: 'confidential-client',
				scope: 'openid',
				code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				code_challenge_method: 'bar'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			auth.validatePresence(response, ['error', 'error_description', 'state']);
			auth.validateError(response, 'invalid_request');
			auth.validateErrorDescription(response, "Expected 'S256'");
		});

		it('may push a request omitting a code challenge', async function () {
			const { response } = await formAgent.par.post(
				{
					scope: 'openid',
					response_type: 'code',
					client_id: 'confidential-client',
					redirect_uri: 'https://confidential.example.com/cb'
				},
				{
					headers: {
						...AuthorizationRequest.basicAuthHeader(
							'confidential-client',
							'confidential-secret'
						)
					}
				}
			);

			expect(response.status).toBe(201);
		});
	});

	/*
	 * Support for the method is what this member advertises, and support has not changed — only whether
	 * a proof is demanded of some clients. No registered member states the latter, so a client learns
	 * it by being refused rather than by reading the document.
	 */
	it('offers S256 among the published proof methods', async function () {
		const doc = (await agent['.well-known']['openid-configuration'].get())
			.data as Record<string, string[]>;

		expect(doc.code_challenge_methods_supported).toEqual(['S256']);
	});

	describe('the code exchange', () => {
		it('refuses a code bound to a challenge presented without a verifier', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId('confidential-client'),
				scope: 'openid',
				clientId: 'confidential-client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'https://confidential.example.com/cb'
			});
			const code = await authCode.save();

			const { error } = await agent.token.post(
				{
					code,
					grant_type: 'authorization_code',
					redirect_uri: 'https://confidential.example.com/cb'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'confidential-client',
						'confidential-secret'
					)
				}
			);

			if (!error) throw new Error('expected error response');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		/*
		 * The downgrade guard, and the reason accepting an unbound code is safe: an instance that has
		 * stopped demanding proofs must not be talked into treating an unbound code as a proven one.
		 */
		it('refuses a verifier presented for a code that was never bound to a challenge', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId('confidential-client'),
				scope: 'openid',
				clientId: 'confidential-client',
				redirectUri: 'https://confidential.example.com/cb'
			});
			const code = await authCode.save();

			const { error } = await agent.token.post(
				{
					code,
					grant_type: 'authorization_code',
					redirect_uri: 'https://confidential.example.com/cb',
					code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'confidential-client',
						'confidential-secret'
					)
				}
			);

			if (!error) throw new Error('expected error response');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});
	});
});
