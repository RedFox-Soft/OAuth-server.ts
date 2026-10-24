import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach,
	spyOn,
	mock
} from 'bun:test';
import { Type } from '@sinclair/typebox';
import { generateKeyPair } from 'jose';

import bootstrap, { type Setup } from '../test_helper.ts';
import { TestAdapter } from 'test/models.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.ts';
import { shaped } from 'test/shape.ts';
import { send } from '../feature_gate/helpers.ts';
import { discoveryDocument } from '../settings_apply/helpers.ts';
import {
	answer,
	proof,
	signedIn,
	tokenRequest,
	type KeyPair
} from './profile_flow.ts';

/**
 * @proves Under the IPSIE SL1 profile every access token the server issues is bound to the DPoP key of the
 * application that asked for it, at every grant, and a token that could only predate the profile is not refreshed.
 */
describe('access tokens under the IPSIE SL1 profile', () => {
	let setup: Setup;
	let keypair: KeyPair;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'profile' });
		keypair = await generateKeyPair('ES256');
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		mock.restore();
	});

	it('refuses a token request without a DPoP proof, for every grant the token endpoint serves', async () => {
		const { grant_types_supported } = shaped(
			Type.Object({ grant_types_supported: Type.Array(Type.String()) }),
			await discoveryDocument()
		);

		for (const grantType of grant_types_supported) {
			const res = await tokenRequest(
				{ grant_type: grantType },
				{ client: 'sl1-machine', secret: 'sl1-machine-secret' }
			);
			expect((await answer(res)).error, grantType).toBe('invalid_dpop_proof');
		}
	});

	it('binds an authorization code exchange to the proof, and userinfo accepts the token with it', async () => {
		const issued = await signedIn(setup, keypair, {
			client: 'sl1-web',
			secret: 'sl1-web-secret'
		});
		expect(issued.token_type).toBe('DPoP');
		const accessToken = issued.access_token ?? '';

		const userinfo = await send('/userinfo', {
			method: 'GET',
			headers: {
				authorization: `DPoP ${accessToken}`,
				dpop: await proof(keypair, {
					htu: `${ISSUER}/userinfo`,
					htm: 'GET',
					accessToken
				})
			}
		});

		expect(userinfo.status).toBe(200);
	});

	it('refuses to refresh a public application’s refresh token that is not bound to a key', async () => {
		const first = await signedIn(setup, keypair, { client: 'sl1-spa' });
		const refreshToken = first.refresh_token ?? '';
		TestAdapter.for('RefreshToken').syncUpdate(
			setup.getTokenJti(refreshToken),
			{ jkt: undefined }
		);

		const res = await tokenRequest(
			{ grant_type: 'refresh_token', refresh_token: refreshToken },
			{ client: 'sl1-spa', dpop: await proof(keypair) }
		);

		expect((await answer(res)).error).toBe('invalid_grant');
	});

	it('refreshes a confidential application’s token with a proof, binding the new access token', async () => {
		const first = await signedIn(setup, keypair, {
			client: 'sl1-web',
			secret: 'sl1-web-secret'
		});

		const res = await tokenRequest(
			{ grant_type: 'refresh_token', refresh_token: first.refresh_token ?? '' },
			{
				client: 'sl1-web',
				secret: 'sl1-web-secret',
				dpop: await proof(keypair)
			}
		);

		expect((await answer(res)).token_type).toBe('DPoP');
	});

	it('refuses an application registered for certificate-bound tokens, even with a proof', async () => {
		const res = await tokenRequest(
			{ grant_type: 'client_credentials' },
			{
				client: 'sl1-mtls',
				secret: 'sl1-mtls-secret',
				dpop: await proof(keypair)
			}
		);

		expect(res.status).toBe(400);
		expect((await answer(res)).error).toBe('invalid_client');
	});
});
