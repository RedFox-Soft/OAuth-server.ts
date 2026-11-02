import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	spyOn
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { unique } from '../connected_services/stubs.ts';
import {
	API_SCOPE,
	allowAccount,
	connected,
	exchange,
	githubService,
	granted,
	refused,
	signIn
} from './harness.ts';

async function declareApi(
	tokenFormat: 'jwt' | 'opaque',
	exchangedBy?: string
): Promise<string> {
	const identifier = `https://${unique('mcp')}.example/`;
	await getProtectedResourceStore().create({
		namespace: ROOT_NAMESPACE,
		identifier,
		bucketId: DEFAULT_BUCKET_ID,
		name: 'Repositories MCP server',
		scopes: [API_SCOPE],
		tokenFormat
	});
	if (exchangedBy) {
		await getProtectedResourceStore().update(ROOT_NAMESPACE, identifier, {
			exchangedBy
		});
	}
	return identifier;
}

/**
 * @proves The application an administrator linked to an API exchanges the access token that API received, opaque
 * or JWT, under the consent the person gave the agent; an application not linked to it cannot.
 */
describe('an MCP server exchanging the access token an agent called it with', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'upstream_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	for (const format of ['jwt', 'opaque'] as const) {
		it(`receives the person’s token for a ${format} access token issued for its API`, async () => {
			const api = await declareApi(format, 'mcp-server');
			const person = unique('person');
			const service = await githubService(['mcp-server']);
			const record = await connected(person, service);
			const signedIn = await signIn(setup, 'agent', person, api);
			await allowAccount(signedIn.grantId, record);

			const body = granted(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id,
					clientId: 'mcp-server'
				})
			);

			expect(body.access_token).toBe(present(record.accessToken, 'a token'));
		});
	}

	it('refuses an application that is not the API’s exchanging application', async () => {
		const api = await declareApi('jwt', 'mcp-server');
		const person = unique('person');
		const service = await githubService(['mcp-server', 'other-agent']);
		const record = await connected(person, service);
		const signedIn = await signIn(setup, 'agent', person, api);
		await allowAccount(signedIn.grantId, record);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				clientId: 'other-agent'
			})
		);

		expect(body.error).toBe('invalid_grant');
		expect(body.reason).toBeUndefined();
	});
});
