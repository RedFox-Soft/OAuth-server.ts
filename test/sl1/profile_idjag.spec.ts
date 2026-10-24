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
import { decodeProtectedHeader, generateKeyPair } from 'jose';

import bootstrap, { type Setup } from '../test_helper.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.ts';
import { shaped } from 'test/shape.ts';
import {
	ExchangeBody,
	connect,
	exchange
} from '../assertion_grants/issuing.ts';
import { proof, signedIn, type KeyPair } from './profile_flow.ts';

const TICKETS_AS = 'https://as.tickets.example';
const TICKETS_MCP = 'https://mcp.tickets.example/';

/**
 * @proves Under the IPSIE SL1 profile an ID-JAG this server issues for an outside authorization server is signed with
 * PS256, as the profile requires of everything the server signs.
 */
describe('an ID-JAG under the IPSIE SL1 profile', () => {
	let setup: Setup;
	let keypair: KeyPair;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'profile_idjag' });
		keypair = await generateKeyPair('ES256');
		await connect({
			issuer: TICKETS_AS,
			clients: [{ clientId: 'globex-agent', externalClientId: 'f53f191f' }],
			rules: [
				{
					appliesTo: 'everyone',
					resources: [{ identifier: TICKETS_MCP, scopes: ['read'] }]
				}
			]
		});
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		mock.restore();
	});

	it('is signed with PS256', async () => {
		const { id_token } = await signedIn(setup, keypair, {
			client: 'globex-agent',
			secret: 'globex-agent-secret',
			accountId: 'sl1-person'
		});

		const { status, data } = await exchange({
			subjectToken: id_token ?? '',
			audience: TICKETS_AS,
			resource: TICKETS_MCP,
			scope: 'read',
			dpop: await proof(keypair)
		});

		expect(status).toBe(200);
		expect(
			decodeProtectedHeader(shaped(ExchangeBody, data).access_token).alg
		).toBe('PS256');
	});
});
