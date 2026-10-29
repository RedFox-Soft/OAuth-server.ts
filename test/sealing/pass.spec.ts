import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { agent } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { TestAdapter } from '../models.js';
import { TEST_KEYRING } from './fixtures.ts';
import { getBucketStore, getSealingStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { bindingOf } from 'lib/consts/sealed_fields.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { runPass } from 'lib/sealing/pass.ts';
import { seal } from 'lib/sealing/seal.ts';

/* A client stored as an older release stored it: in plaintext, beside the sealed ones. */
function storePlaintextClient(clientId: string, secret: string): void {
	void TestAdapter.for('Client').upsert(
		clientId,
		{
			clientId,
			clientSecret: secret,
			grantTypes: ['client_credentials'],
			responseTypes: [],
			redirectUris: [],
			scope: 'api:read'
		},
		0
	);
}

/**
 * @proves Secrets stored before a keyring was in use keep working, are counted until they are sealed, and are
 * sealed by a pass that can run any number of times and never undoes an edit made while it ran.
 */
describe('the encryption pass', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	it('a second encryption pass changes nothing', async () => {
		storePlaintextClient('pass-twice', 'pass-twice-secret');
		await runPass();
		const once = await getSealingStore().scan('clientSecret');

		await runPass();

		expect(await getSealingStore().scan('clientSecret')).toEqual(once);
	});

	it('a plaintext secret still works while a keyring is in use', async () => {
		storePlaintextClient('pass-plaintext', 'pass-plaintext-secret');

		const { status } = await agent.token.post(
			{ grant_type: 'client_credentials', scope: 'api:read' },
			{
				headers: AuthorizationRequest.basicAuthHeader(
					'pass-plaintext',
					'pass-plaintext-secret'
				)
			}
		);

		expect(status).toBe(200);
	});

	it('a plaintext secret is counted as not yet sealed by a pass that cannot seal it', async () => {
		storePlaintextClient('pass-counted', 'pass-counted-secret');
		resetKeyringForTests(null);

		const report = await runPass();

		expect(report?.mode).toBe('count');
		expect(report?.plaintext).toBeGreaterThan(0);
	});

	it('the encryption pass does not overwrite a secret written after it read the record', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `pass-race-${Math.random()}`
		});
		await getBucketStore().update(bucket._id, {
			federation: [
				{
					id: 'race-sso',
					displayName: 'Race SSO',
					enabled: true,
					issuer: 'https://sso.example.com',
					clientId: 'race-client',
					clientSecret: 'secret-the-pass-read',
					scopes: ['openid'],
					emailTrusted: false,
					provisioning: 'jit',
					allowedEmailDomains: [],
					emailClaim: 'email'
				}
			]
		});
		const read = (await getSealingStore().scan('providerSecret')).find(
			(leaf) =>
				leaf.target.kind === 'providerSecret' &&
				leaf.target.bucketId === bucket._id
		);
		if (!read) throw new Error('the provider secret was not stored');

		// An administrator re-enters the secret between the pass's read and its write.
		const current = await getBucketStore().find(bucket._id);
		await getBucketStore().update(bucket._id, {
			federation: (current?.federation ?? []).map((provider) => ({
				...provider,
				clientSecret: 'secret-the-administrator-entered'
			}))
		});
		await getSealingStore().sealAt(
			read.target,
			read.value,
			await seal('secret-the-pass-read', bindingOf(read.target))
		);

		const after = await getBucketStore().find(bucket._id);
		expect(after?.federation[0]?.clientSecret).toBe(
			'secret-the-administrator-entered'
		);
	});
});
