import {
	describe,
	beforeAll,
	beforeEach,
	afterEach,
	it,
	expect,
	mock,
	spyOn
} from 'bun:test';
import { decodeJwt } from 'jose';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { getBucketGroupStore, getUserStore } from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { pairwiseIdentifier } from 'lib/addon/index.js';
import { Client } from 'lib/models/client.js';
import { present as presentValue, shaped } from 'test/shape.js';
import { dpopKey, dpopProof } from '../assertion_grants/helpers.js';
import {
	ExchangeBody,
	ID_JAG_TOKEN_TYPE,
	REFRESH_TOKEN_TYPE,
	connect,
	exchange,
	signIn,
	verifiedIdJag
} from '../assertion_grants/issuing.js';

const TICKETS_AS = 'https://as.tickets.example';
const TICKETS_MCP = 'https://mcp.tickets.example/';
const WIKI_MCP = 'https://mcp.wiki.example/';
const REVIEWS_AS = 'https://as.reviews.example';
const REVIEWS_MCP = 'https://mcp.reviews.example/';

/**
 * @proves An application a project allows on an outside authorization server exchanges a person's ID token
 * or refresh token for an ID-JAG that outside server can verify against the project's published keys —
 * naming the person as that server knows them, the application as that server knows it, and no more
 * resources and scopes than the project's rules allow the person there.
 */
describe('a token exchange for an ID-JAG', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await connect({
			issuer: TICKETS_AS,
			clients: [
				{ clientId: 'globex-agent', externalClientId: 'f53f191f' },
				{ clientId: 'https://agent.globex.example/client.json' }
			],
			rules: [
				{
					appliesTo: 'everyone',
					resources: [
						{ identifier: TICKETS_MCP, scopes: ['read', 'write'] },
						{ identifier: WIKI_MCP, scopes: ['read'] }
					]
				}
			],
			signInClientId: 'tickets-sso'
		});
		await getBucketGroupStore().create(
			{
				_id: 'grp-eng',
				bucketId: DEFAULT_BUCKET_ID,
				displayName: 'Engineering'
			},
			['engineer-1']
		);
		await connect({
			issuer: REVIEWS_AS,
			rules: [
				{
					appliesTo: { groupIds: ['grp-eng'] },
					resources: [{ identifier: REVIEWS_MCP, scopes: ['read'] }]
				}
			],
			includeEmail: false
		});
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		mock.restore();
	});

	it('issues an ID-JAG the outside server verifies, with the granted resource and scope and no refresh token', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'person-1');

		const { status, data } = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS,
			resource: TICKETS_MCP,
			scope: 'read'
		});

		expect(status).toBe(200);
		const body = shaped(ExchangeBody, data);
		expect(body).toMatchObject({
			issued_token_type: ID_JAG_TOKEN_TYPE,
			token_type: 'N_A',
			expires_in: 300
		});
		expect(body.refresh_token).toBeUndefined();
		const { header, claims } = await verifiedIdJag(
			body.access_token,
			TICKETS_AS
		);
		expect(header.typ).toBe('oauth-id-jag+jwt');
		expect(claims).toMatchObject({
			iss: ISSUER,
			aud: TICKETS_AS,
			client_id: 'f53f191f',
			resource: TICKETS_MCP,
			scope: 'read'
		});
		expect(typeof claims.jti).toBe('string');
	});

	it('narrows the requested scopes to what the rules allow and says so', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'person-2');

		const { data } = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS,
			resource: TICKETS_MCP,
			scope: 'read admin'
		});

		const body = shaped(ExchangeBody, data);
		expect(body.scope).toBe('read');
		expect(decodeJwt(body.access_token).scope).toBe('read');
	});

	it('grants a member of a group what the rule for that group allows', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'engineer-1');

		const { status, data } = await exchange({
			subjectToken: id_token,
			audience: REVIEWS_AS,
			scope: 'read'
		});

		expect(status).toBe(200);
		expect(decodeJwt(shaped(ExchangeBody, data).access_token)).toMatchObject({
			resource: REVIEWS_MCP,
			scope: 'read'
		});
	});

	it('names every allowed MCP server and scope when the request names none', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'person-3');

		const { data } = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS
		});

		const claims = decodeJwt(shaped(ExchangeBody, data).access_token);
		expect(claims.resource).toEqual([TICKETS_MCP, WIKI_MCP]);
		expect(String(claims.scope).split(' ').sort()).toEqual(['read', 'write']);
	});

	it('names the person by the pairwise identifier the outside server signs them in with', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'person-4');

		const { data } = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS,
			resource: TICKETS_MCP
		});

		const sso = await Client.find('tickets-sso');
		expect(decodeJwt(shaped(ExchangeBody, data).access_token).sub).toBe(
			await pairwiseIdentifier('person-4', presentValue(sso, 'tickets-sso'))
		);
	});

	it('names the person by their own identifier when no sign-in application is named', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'engineer-1');

		const { data } = await exchange({
			subjectToken: id_token,
			audience: REVIEWS_AS
		});

		expect(decodeJwt(shaped(ExchangeBody, data).access_token).sub).toBe(
			'engineer-1'
		);
	});

	it('includes a verified address only where the connection includes email', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'engineer-1');
		await getUserStore(DEFAULT_BUCKET_ID).update('engineer-1', {
			email: 'engineer@globex.example',
			verified: true
		});

		const withEmail = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS,
			resource: TICKETS_MCP
		});
		const without = await exchange({
			subjectToken: id_token,
			audience: REVIEWS_AS
		});

		expect(
			decodeJwt(shaped(ExchangeBody, withEmail.data).access_token)
		).toMatchObject({ email: 'engineer@globex.example', email_verified: true });
		expect(
			decodeJwt(shaped(ExchangeBody, without.data).access_token).email
		).toBeUndefined();
	});

	it('names an application whose client id is a URL by that URL', async () => {
		const { id_token } = await signIn(
			setup,
			'https://agent.globex.example/client.json',
			'person-5'
		);

		const { data } = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS,
			resource: TICKETS_MCP,
			clientId: 'https://agent.globex.example/client.json'
		});

		expect(decodeJwt(shaped(ExchangeBody, data).access_token).client_id).toBe(
			'https://agent.globex.example/client.json'
		);
	});

	it('binds the ID-JAG to the key of a DPoP proof sent with the exchange', async () => {
		const { id_token } = await signIn(setup, 'globex-agent', 'person-6');
		const { keypair, thumbprint } = await dpopKey();

		const { data } = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS,
			resource: TICKETS_MCP,
			dpop: await dpopProof(keypair)
		});

		expect(decodeJwt(shaped(ExchangeBody, data).access_token).cnf).toEqual({
			jkt: thumbprint
		});
	});

	it('issues an ID-JAG from a refresh token without spending it', async () => {
		const { refresh_token } = await signIn(setup, 'globex-agent', 'person-7');
		const refreshToken = presentValue(refresh_token, 'the refresh token');

		const exchanged = await exchange({
			subjectToken: refreshToken,
			subjectTokenType: REFRESH_TOKEN_TYPE,
			audience: TICKETS_AS,
			resource: TICKETS_MCP
		});
		const refreshed = await agent.token.post(
			{ grant_type: 'refresh_token', refresh_token: refreshToken },
			{
				headers: AuthorizationRequest.basicAuthHeader(
					'globex-agent',
					'globex-agent-secret'
				)
			}
		);

		expect(exchanged.status).toBe(200);
		expect(refreshed.status).toBe(200);
	});
});
