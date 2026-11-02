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
import {
	adapter,
	getBucketStore,
	getConnectedAccountStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { EndUserPatch } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { MCP_RESOURCE } from 'lib/mcp/consts.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { unique } from '../connected_services/stubs.ts';
import { addService } from '../connected_services/harness.ts';
import {
	allowAccount,
	connected,
	exchange,
	githubService,
	refused,
	signIn
} from './harness.ts';

/**
 * @proves Every condition for handing out a person's upstream token is checked on every exchange: the
 * administrator's allow-list, the person's consent, the person and the project, the token presented and who presents
 * it. A refusal returns no token and reaches no provider.
 */
describe('an exchange the project must refuse', () => {
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

	/* A person, an allowed and consented agent, everything in place but what the case takes away. */
	async function allowed(applications: string[] = ['agent']) {
		const person = unique('person');
		const service = await githubService(applications);
		const record = await connected(person, service);
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);
		return { person, service, record, signedIn };
	}

	it('refuses an application not on the service’s allow-list, whatever the person allowed', async () => {
		const { service, signedIn } = await allowed(['other-agent']);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.error).toBe('invalid_target');
		expect(body.reason).toBe('not_permitted');
	});

	it('refuses an agent the person never allowed to use the account as needing consent', async () => {
		const person = unique('person');
		const service = await githubService();
		await connected(person, service);
		const signedIn = await signIn(setup, 'agent', person);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.error).toBe('invalid_grant');
		expect(body.reason).toBe('consent_required');
	});

	const lockouts: [string, EndUserPatch][] = [
		[
			'locked',
			{ lockedLocally: { at: new Date(), reason: 'a test', by: 'admin' } }
		],
		['deactivated', { active: false }]
	];
	for (const [label, change] of lockouts) {
		it(`gives a ${label} person no upstream token and keeps the account`, async () => {
			const { person, service, record, signedIn } = await allowed();
			await getUserStore(DEFAULT_BUCKET_ID).update(person, change);

			const body = refused(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			);

			expect(body.error).toBe('invalid_grant');
			expect(body.reason).toBeUndefined();
			expect(
				await getConnectedAccountStore().find(DEFAULT_BUCKET_ID, record._id)
			).not.toBeNull();
		});
	}

	it('refuses a revoked access token', async () => {
		const { service, signedIn } = await allowed();
		await present(
			await AccessToken.tryFind(signedIn.accessToken),
			'the token'
		).destroy();

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.error).toBe('invalid_grant');
	});

	it('refuses an access token whose grant was removed', async () => {
		const { service, signedIn } = await allowed();
		await present(await Grant.tryFind(signedIn.grantId), 'the grant').destroy();

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.error).toBe('invalid_grant');
	});

	it('refuses a value that is no access token of this project', async () => {
		const { service } = await allowed();

		const body = refused(
			await exchange({ subjectToken: unique('forged'), audience: service.id })
		);

		expect(body.error).toBe('invalid_grant');
	});

	it('refuses a service of another project as not permitted', async () => {
		const { signedIn } = await allowed();
		const elsewhere = await getBucketStore().create({
			name: unique('elsewhere'),
			ownerGroupId: 'unassigned'
		});
		const foreign = await addService(
			{
				kind: 'catalogue',
				catalogueId: 'github',
				applications: ['agent']
			},
			elsewhere._id
		);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: foreign.id
			})
		);

		expect(body.reason).toBe('not_permitted');
	});

	it('refuses a public application', async () => {
		const { service, signedIn } = await allowed(['spa']);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				clientId: 'spa',
				secret: null
			}),
			400
		);

		expect(body.error).toBe('unauthorized_client');
	});

	it('refuses an application that registered itself', async () => {
		const { service, signedIn } = await allowed(['self-registered']);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				clientId: 'self-registered'
			})
		);

		expect(body.error).toBe('unauthorized_client');
	});

	it('refuses an application that presents another application’s access token', async () => {
		const { service, signedIn } = await allowed(['agent', 'other-agent']);

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

	/*
	 * Without a keyring the application's own sealed secret cannot be read either, so the request ends at client
	 * authentication; what matters is that no upstream token leaves.
	 */
	it('hands out nothing while no keyring is in use', async () => {
		const { service, signedIn } = await allowed();
		resetKeyringForTests(null);

		const answer = await exchange({
			subjectToken: signedIn.accessToken,
			audience: service.id
		});

		expect(answer.status).not.toBe(200);
		expect(JSON.stringify(answer.error?.value)).not.toContain('access_token');
	});

	it('refuses a deleted service as not permitted', async () => {
		const { service, signedIn } = await allowed();
		const bucket = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the project'
		);
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			connectedServices: (bucket.connectedServices ?? []).filter(
				(item) => item.id !== service.id
			)
		});

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('not_permitted');
	});

	it('refuses an access token for the administrative MCP endpoint', async () => {
		const { service, signedIn } = await allowed();
		const stored = present(
			await adapter('AccessToken').find(signedIn.accessToken),
			'the stored token'
		);
		await adapter('AccessToken').upsert(
			signedIn.accessToken,
			{ ...stored, aud: MCP_RESOURCE },
			3600
		);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.error).toBe('invalid_grant');
	});

	it('refuses more than one audience, and a resource in place of one', async () => {
		const { service, signedIn } = await allowed();

		const twice = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: [service.id, service.id]
			})
		);
		const resource = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				resource: 'https://api.github.com/'
			})
		);

		expect(twice.error).toBe('invalid_target');
		expect(resource.error).toBe('invalid_target');
	});
});
