import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	spyOn
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, {
	agent,
	type Setup,
	redirectParameter
} from '../test_helper.js';
import { grantStore } from 'lib/actions/grants/index.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present, shaped } from 'test/shape.js';

const SCOPES = ApplicationConfig.scopes;
const FLAGS = [
	'clientCredentials.enabled',
	'deviceFlow.enabled',
	'ciba.enabled'
] as const;

type Combination = { offlineAccess: boolean } & Record<
	(typeof FLAGS)[number],
	boolean
>;

// Every assignment of the four inputs that decide which grants the server supports.
const combinations: Combination[] = Array.from({ length: 16 }, (_, bits) => ({
	offlineAccess: Boolean(bits & 1),
	'clientCredentials.enabled': Boolean(bits & 2),
	'deviceFlow.enabled': Boolean(bits & 4),
	'ciba.enabled': Boolean(bits & 8)
}));

function apply(combination: Combination) {
	ApplicationConfig.scopes = combination.offlineAccess
		? ['openid', 'offline_access']
		: ['openid'];
	for (const flag of FLAGS) ApplicationConfig[flag] = combination[flag];
}

function restore() {
	ApplicationConfig.scopes = SCOPES;
	for (const flag of FLAGS) ApplicationConfig[flag] = false;
}

async function advertised(): Promise<string[]> {
	const { data } = await agent['.well-known']['openid-configuration'].get();
	return present(data?.grant_types_supported, 'grant_types_supported');
}

async function refusedAsUnsupported(grantType: string): Promise<boolean> {
	const { error } = await agent.token.post(
		{ grant_type: grantType },
		{ headers: AuthorizationRequest.basicAuthHeader('client', 'secret') }
	);
	const body = shaped(Type.Object({ error: Type.String() }), error?.value);
	return body.error === 'unsupported_grant_type';
}

/**
 * @proves For every configuration, the grant types a client reads in discovery are exactly the grant
 * types the token endpoint will process — nothing advertised is refused as unsupported, and nothing
 * refused as unsupported is advertised.
 */
describe('the grant types the server advertises', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'grants' });
	});

	afterAll(restore);

	for (const combination of combinations) {
		const label = Object.entries(combination)
			.map(([key, on]) => `${key}=${on}`)
			.join(', ');

		it(`are the grant types the token endpoint accepts, with ${label}`, async () => {
			apply(combination);

			const accepted: string[] = [];
			for (const grantType of grantStore.keys()) {
				if (!(await refusedAsUnsupported(grantType))) accepted.push(grantType);
			}

			expect([...(await advertised())].sort()).toEqual(accepted.sort());
		});
	}
});

/**
 * @proves Withdrawing offline access withdraws the refresh-token grant: a refresh token issued while
 * it was supported is no longer exchanged.
 */
describe('a refresh token issued before offline access was withdrawn', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'grants' });
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		mock.restore();
		restore();
	});

	it('is refused as an unsupported grant', async () => {
		const authReq = new AuthorizationRequest({
			client_id: 'offline',
			scope: 'openid offline_access',
			prompt: 'consent',
			redirect_uri: 'https://offline.example.com/cb'
		});
		const cookie = await setup.login({ scope: 'openid offline_access' });
		const auth = await agent.auth.get({
			query: authReq.params,
			headers: { cookie }
		});
		const { data } = await authReq.getToken(
			redirectParameter(auth.response, 'code')
		);
		const { refresh_token } = shaped(
			Type.Object({ refresh_token: Type.String() }),
			data
		);

		ApplicationConfig.scopes = ['openid'];

		const { error } = await agent.token.post(
			{ grant_type: 'refresh_token', refresh_token },
			{ headers: AuthorizationRequest.basicAuthHeader('offline', 'secret') }
		);
		expect(error?.status).toBe(400);
		expect(error?.value).toMatchObject({ error: 'unsupported_grant_type' });
	});
});
