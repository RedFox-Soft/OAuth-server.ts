import {
	describe,
	it,
	beforeAll,
	afterEach,
	spyOn,
	mock,
	expect
} from 'bun:test';
import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AccessToken } from 'lib/models/access_token.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

describe('revocation features', () => {
	beforeAll(async function () {
		await bootstrap(import.meta.url)();
	});
	afterEach(function () {
		mock.restore();
	});

	it('enriched discovery shows the url now', async function () {
		const { data, status } =
			await agent['.well-known']['openid-configuration'].get();
		expect(status).toBe(200);
		expect(data.revocation_endpoint).toEndWith('/token/revocation');
	});

	describe('/token/revocation', () => {
		it('revokes access token', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const atDestroy = spyOn(
				AccessToken.prototype,
				'destroy'
			).mockResolvedValue();
			const token = await at.save();

			const { status } = await agent.token.revocation.post(
				{
					token
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(atDestroy).toHaveBeenCalledTimes(1);
		});

		it('revokes access token [correct hint]', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const stub = spyOn(AccessToken.prototype, 'destroy').mockResolvedValue();
			const token = await at.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'access_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes access token [wrong hint]', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const stub = spyOn(AccessToken.prototype, 'destroy').mockResolvedValue();
			const token = await at.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes access token [unrecognized hint]', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const stub = spyOn(AccessToken.prototype, 'destroy').mockResolvedValue();
			const token = await at.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'foobar'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('propagates exceptions on find', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			spyOn(AccessToken, 'find').mockRejectedValue(
				new Error('something went wrong')
			);
			const token = await at.save();

			const { error } = await agent.token.revocation.post(
				{
					token
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(500);
			expect(error.value).toEqual({
				error: 'server_error',
				error_description: 'An unexpected error occurred'
			});
		});

		it('revokes refresh token [no hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const rtDestroy = spyOn(
				RefreshToken.prototype,
				'destroy'
			).mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(rtDestroy).toHaveBeenCalledTimes(1);
		});

		it('revokes refresh token [correct hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const stub = spyOn(RefreshToken.prototype, 'destroy').mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'refresh_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes refresh token [wrong hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const stub = spyOn(RefreshToken.prototype, 'destroy').mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'client_credentials'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes refresh token [unrecognized hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client'),
				scope: 'scope'
			});

			const stub = spyOn(RefreshToken.prototype, 'destroy').mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'foobar'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes client credentials token [no hint]', async function () {
			const rt = new ClientCredentials({
				client: await Client.find('client')
			});

			const stub = spyOn(
				ClientCredentials.prototype,
				'destroy'
			).mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes client credentials token [correct hint]', async function () {
			const rt = new ClientCredentials({
				client: await Client.find('client')
			});

			const stub = spyOn(
				ClientCredentials.prototype,
				'destroy'
			).mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'client_credentials'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes client credentials token [wrong hint]', async function () {
			const rt = new ClientCredentials({
				client: await Client.find('client')
			});

			const stub = spyOn(
				ClientCredentials.prototype,
				'destroy'
			).mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'access_token'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('revokes client credentials token [unrecognized hint]', async function () {
			const rt = new ClientCredentials({
				client: await Client.find('client')
			});

			const stub = spyOn(
				ClientCredentials.prototype,
				'destroy'
			).mockResolvedValue();
			const token = await rt.save();

			const { status } = await agent.token.revocation.post(
				{
					token,
					token_type_hint: 'foobar'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(stub).toHaveBeenCalledTimes(1);
		});

		it('validates token param presence', async function () {
			const { error } = await agent.token.revocation.post(
				{},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(422);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: "Property 'token' is missing"
			});
		});

		it('rejects completely wrong tokens with the expected OK response', async function () {
			const { status } = await agent.token.revocation.post(
				{
					token: 'dsahjdasdsa'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
		});

		it('rejects wrong tokens', async function () {
			const { status } = await agent.token.revocation.post(
				{
					token:
						'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
		});

		it('does not revoke tokens of other clients', async function () {
			const spy = mock();
			provider.once('revocation.error', spy);
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: 'foo',
				client: await Client.find('client2'),
				scope: 'scope'
			});
			const token = await at.save();

			const { error } = await agent.token.revocation.post(
				{
					token
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'this token does not belong to you'
			});
			expect(spy).toHaveBeenCalledTimes(1);
		});

		it('does not allow to revoke the unrevokable (in case adapter is implemented wrong)', async function () {
			spyOn(AccessToken, 'find').mockResolvedValue({
				payload: { isValid: true, kind: 'AuthorizationCode' }
			});

			const { status } = await agent.token.revocation.post(
				{
					token: 'foo'
				},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
		});

		describe('populates ctx.oidc.entities', () => {
			it('when revoking an AccessToken', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');
				const at = new AccessToken({
					accountId: 'accountId',
					grantId: 'foo',
					client: await Client.find('client'),
					scope: 'scope'
				});
				const token = await at.save();

				const { status } = await agent.token.revocation.post(
					{
						token
					},
					{
						headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				);
				expect(status).toBe(200);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect(['Client', 'AccessToken']).toEqual(
					expect.arrayContaining(entities)
				);
			});

			it('when revoking a RefreshToken', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');
				const rt = new RefreshToken({
					accountId: 'accountId',
					grantId: 'foo',
					client: await Client.find('client'),
					scope: 'scope'
				});
				const token = await rt.save();

				const { status } = await agent.token.revocation.post(
					{
						token
					},
					{
						headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				);
				expect(status).toBe(200);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect(['Client', 'RefreshToken']).toEqual(
					expect.arrayContaining(entities)
				);
			});

			it('when revoking ClientCredentials', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');
				const rt = new ClientCredentials({
					client: await Client.find('client')
				});
				const token = await rt.save();

				const { status } = await agent.token.revocation.post(
					{
						token
					},
					{
						headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				);
				expect(status).toBe(200);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect(['Client', 'ClientCredentials']).toEqual(
					expect.arrayContaining(entities)
				);
			});
		});
	});
});
