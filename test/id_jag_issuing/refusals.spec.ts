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

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { getUserStore } from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { present as presentValue, shaped } from 'test/shape.js';
import { OAuthError } from '../assertion_grants/helpers.js';
import {
	REFRESH_TOKEN_TYPE,
	connect,
	exchange,
	signIn
} from '../assertion_grants/issuing.js';

const TICKETS_AS = 'https://as.tickets.example';
const TICKETS_MCP = 'https://mcp.tickets.example/';

type Result = Awaited<ReturnType<typeof exchange>>;

function refusal(res: Result) {
	expect(res.status).toBe(400);
	return shaped(OAuthError, res.error?.value);
}

/**
 * @proves A project never vouches for a person to an outside server, an MCP server or a scope its
 * administrator did not allow, to an application not allowed or unable to authenticate, or from a subject
 * token it cannot vouch for — and refuses each with the code RFC 8693 §2.2.2 gives it.
 */
describe('a token exchange the project must refuse', () => {
	let setup: Setup;
	let idToken: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'id_jag_issuing' });
		await connect({
			issuer: TICKETS_AS,
			rules: [
				{
					appliesTo: { groupIds: ['grp-nobody'] },
					resources: [
						{ identifier: 'https://mcp.secret.example/', scopes: ['read'] }
					]
				},
				{
					appliesTo: 'everyone',
					resources: [{ identifier: TICKETS_MCP, scopes: ['read'] }]
				}
			]
		});
	});

	beforeEach(async () => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		({ id_token: idToken } = await signIn(setup, 'globex-agent', 'person-1'));
	});

	afterEach(() => {
		mock.restore();
	});

	it('is refused with invalid_target for an outside server the project has not connected', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: 'https://as.unconnected.example'
		});

		expect(refusal(res).error).toBe('invalid_target');
	});

	it('is refused with invalid_target for more than one audience', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: [TICKETS_AS, 'https://as.other.example']
		});

		expect(refusal(res).error).toBe('invalid_target');
	});

	it('is refused with invalid_target for an MCP server no rule allows the person', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: TICKETS_AS,
			resource: 'https://mcp.secret.example/'
		});

		expect(refusal(res).error).toBe('invalid_target');
	});

	it('is refused with invalid_scope when every requested scope lies outside the rules', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: TICKETS_AS,
			resource: TICKETS_MCP,
			scope: 'admin'
		});

		expect(refusal(res).error).toBe('invalid_scope');
	});

	it('is refused with unauthorized_client for an application not on the connection', async () => {
		const { id_token } = await signIn(setup, 'other-agent', 'person-2');

		const res = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS,
			clientId: 'other-agent'
		});

		expect(refusal(res).error).toBe('unauthorized_client');
	});

	it('is refused with unauthorized_client for an application that does not authenticate', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: TICKETS_AS,
			clientId: 'spa',
			secret: null
		});

		expect(refusal(res).error).toBe('unauthorized_client');
	});

	it('is refused with invalid_request for an ID token issued to another application', async () => {
		const { id_token } = await signIn(setup, 'other-agent', 'person-3');

		const res = await exchange({
			subjectToken: id_token,
			audience: TICKETS_AS
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request for an access token presented as the subject', async () => {
		const res = await exchange({
			subjectToken: idToken,
			subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
			audience: TICKETS_AS
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request for a SAML assertion presented as the subject', async () => {
		const res = await exchange({
			subjectToken: 'PHNhbWw+PC9zYW1sPg',
			subjectTokenType: 'urn:ietf:params:oauth:token-type:saml2',
			audience: TICKETS_AS
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request for an ID token that is not one', async () => {
		const res = await exchange({
			subjectToken: 'not.a.token',
			audience: TICKETS_AS
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request for a person who can no longer sign in', async () => {
		await getUserStore(DEFAULT_BUCKET_ID).update('person-1', { active: false });

		const res = await exchange({ subjectToken: idToken, audience: TICKETS_AS });

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request for a refresh token issued to another application', async () => {
		const { refresh_token } = await signIn(setup, 'other-agent', 'person-4');

		const res = await exchange({
			subjectToken: presentValue(refresh_token, 'the refresh token'),
			subjectTokenType: REFRESH_TOKEN_TYPE,
			audience: TICKETS_AS
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request for a refresh token that was revoked', async () => {
		const { refresh_token } = await signIn(setup, 'globex-agent', 'person-5');
		const refreshToken = presentValue(refresh_token, 'the refresh token');
		await agent.token.revocation.post(
			{ token: refreshToken },
			{
				headers: AuthorizationRequest.basicAuthHeader(
					'globex-agent',
					'globex-agent-secret'
				)
			}
		);

		const res = await exchange({
			subjectToken: refreshToken,
			subjectTokenType: REFRESH_TOKEN_TYPE,
			audience: TICKETS_AS
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request when an actor token is sent', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: TICKETS_AS,
			actorToken: idToken
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request when no token type is requested', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: TICKETS_AS,
			requestedTokenType: null
		});

		expect(refusal(res).error).toBe('invalid_request');
	});

	it('is refused with invalid_request when another token type is requested', async () => {
		const res = await exchange({
			subjectToken: idToken,
			audience: TICKETS_AS,
			requestedTokenType: 'urn:ietf:params:oauth:token-type:access_token'
		});

		expect(refusal(res).error).toBe('invalid_request');
	});
});
