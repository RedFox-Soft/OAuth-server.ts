import { parse as parseUrl } from 'node:url';
import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';

describe('PKCE RFC7636', () => {
	let setup = null;
	let cookie = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
		cookie = await setup.login();
	});

	describe('authorization', () => {
		it('Should throw Exception in check on PSCE if code_challenge is not defined', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});
			auth.params.code_challenge = undefined;

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			auth.validatePresence(response, ['error', 'error_description', 'state']);
			auth.validateError(response, 'invalid_request');
			auth.validateErrorDescription(
				response,
				'Authorization Server policy requires PKCE to be used for this request'
			);
		});

		it('checks that codeChallenge is conform to its ABNF (too short)', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				code_challenge_method: 'S256',
				code_challenge: 'f'.repeat(42)
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			auth.validatePresence(response, ['error', 'error_description', 'state']);
			auth.validateError(response, 'invalid_request');
			auth.validateErrorDescription(
				response,
				"Expected string to match '^[A-Za-z0-9_-]{43}$'"
			);
		});

		it('checks that codeChallenge is conform to its ABNF (too long)', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				code_challenge_method: 'S256',
				code_challenge: 'f'.repeat(129)
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			auth.validatePresence(response, ['error', 'error_description', 'state']);
			auth.validateError(response, 'invalid_request');
			auth.validateErrorDescription(
				response,
				"Expected string to match '^[A-Za-z0-9_-]{43}$'"
			);
		});

		it('checks that codeChallenge is conform to its ABNF (charset)', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				code_challenge_method: 'S256',
				code_challenge: `${'f'.repeat(42)}&`
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			auth.validatePresence(response, ['error', 'error_description', 'state']);
			auth.validateError(response, 'invalid_request');
			auth.validateErrorDescription(
				response,
				"Expected string to match '^[A-Za-z0-9_-]{43}$'"
			);
		});

		it('validates the value of codeChallengeMethod if provided', async function () {
			const auth = new AuthorizationRequest({
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

		it('forces public clients using code flow to use pkce', async function () {
			const auth = new AuthorizationRequest({
				response_type: 'code',
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
			auth.validateErrorDescription(
				response,
				'Authorization Server policy requires PKCE to be used for this request'
			);
		});

		it('stores codeChallenge and codeChallengeMethod in the code', async function () {
			const auth = new AuthorizationRequest({
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
			const jti = setup.getTokenJti(code);
			const stored = TestAdapter.for('AuthorizationCode').syncFind(jti);
			expect(stored).toHaveProperty('codeChallengeMethod', 'S256');
			expect(stored).toHaveProperty(
				'codeChallenge',
				'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
			);
		});
	});

	describe('token grant_type=authorization_code', async () => {
		it('passes with S256 values', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'com.example.myapp:/localhost/cb'
			});
			const code = await authCode.save();

			const { response } = await agent.token.post({
				client_id: 'client',
				code,
				grant_type: 'authorization_code',
				redirect_uri: 'com.example.myapp:/localhost/cb',
				code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
			});
			expect(response).toHaveProperty('status', 200);
		});

		it('checks presence of code_verifier param if code has codeChallenge', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'com.example.myapp:/localhost/cb'
			});
			const code = await authCode.save();

			const { error } = await agent.token.post({
				client_id: 'client',
				code,
				grant_type: 'authorization_code',
				redirect_uri: 'com.example.myapp:/localhost/cb'
			});
			expect(error).toHaveProperty('status', 400);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('checks value of code_verifier when method = S256', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'com.example.myapp:/localhost/cb'
			});
			const code = await authCode.save();

			const { error } = await agent.token.post({
				client_id: 'client',
				code,
				grant_type: 'authorization_code',
				redirect_uri: 'com.example.myapp:/localhost/cb',
				code_verifier: '19Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
			});
			expect(error).toHaveProperty('status', 400);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('checks that code_verifier is conform to its ABNF (too short)', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'com.example.myapp:/localhost/cb'
			});
			const code = await authCode.save();

			const { error } = await agent.token.post({
				client_id: 'client',
				code,
				grant_type: 'authorization_code',
				redirect_uri: 'com.example.myapp:/localhost/cb',
				code_verifier: 'f'.repeat(42)
			});
			expect(error).toHaveProperty('status', 422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"Expected string to match '^[A-Za-z0-9_-]{43}$'"
			);
		});

		it('checks that code_verifier is conform to its ABNF (too long)', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'com.example.myapp:/localhost/cb'
			});
			const code = await authCode.save();

			const { error } = await agent.token.post({
				client_id: 'client',
				code,
				grant_type: 'authorization_code',
				redirect_uri: 'com.example.myapp:/localhost/cb',
				code_verifier: 'f'.repeat(129)
			});
			expect(error).toHaveProperty('status', 422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"Expected string to match '^[A-Za-z0-9_-]{43}$'"
			);
		});

		it('checks that code_verifier is conform to its ABNF (charset)', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'com.example.myapp:/localhost/cb'
			});
			const code = await authCode.save();

			const { error } = await agent.token.post({
				client_id: 'client',
				code,
				grant_type: 'authorization_code',
				redirect_uri: 'com.example.myapp:/localhost/cb',
				code_verifier: `${'f'.repeat(42)}&`
			});
			expect(error).toHaveProperty('status', 422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"Expected string to match '^[A-Za-z0-9_-]{43}$'"
			);
		});

		it('passes if S256 is used', async function () {
			const authCode = new AuthorizationCode({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client',
				codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				codeChallengeMethod: 'S256',
				redirectUri: 'com.example.myapp:/localhost/cb'
			});
			const code = await authCode.save();

			const { response } = await agent.token.post({
				client_id: 'client',
				code,
				grant_type: 'authorization_code',
				redirect_uri: 'com.example.myapp:/localhost/cb',
				code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
			});
			expect(response).toHaveProperty('status', 200);
		});
	});
});
