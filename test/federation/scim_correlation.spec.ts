import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import fc from 'fast-check';

import bootstrap from '../test_helper.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import {
	createEndUser,
	lockEndUser,
	updateEndUser
} from 'lib/end_users/service.ts';
import { resolveFederatedAccount } from 'lib/federation/resolve.ts';
import { createConnection } from 'lib/provisioning/service.ts';
import { idpStub } from './idp_stub.ts';
import {
	CLIENT,
	provider,
	seedBucket,
	signedInAccountIds,
	startInteraction,
	walk
} from './harness.ts';

const noAudit = async () => undefined;

async function boundBucket(
	origin: string,
	connection: { emailTrust?: 'trusted' | 'untrusted' } = {},
	bucketFields: Record<string, unknown> = {}
): Promise<{ bucket: UserBucket; connectionId: string }> {
	const bucketId = await seedBucket(CLIENT, {
		federation: [provider(origin, { emailTrusted: true })],
		...bucketFields
	});
	const bucket = (await getBucketStore().find(bucketId)) as UserBucket;
	const created = await createConnection(
		bucket,
		{
			displayName: 'Directory',
			providerId: 'acme-sso',
			correlation: { claim: 'oid', attribute: 'externalId' },
			...connection
		},
		noAudit
	);
	return {
		bucket: (await getBucketStore().find(bucketId)) as UserBucket,
		connectionId: created._id
	};
}

async function provision(
	bucket: UserBucket,
	connectionId: string,
	fields: { email: string; externalId: string; verified?: boolean }
) {
	return createEndUser(
		bucket,
		{ kind: 'connection', connectionId },
		{
			id: crypto.randomUUID().replaceAll('-', ''),
			email: fields.email,
			userName: fields.email,
			externalId: fields.externalId,
			verified: fields.verified ?? true
		},
		noAudit
	);
}

/*
 * One stub per issuer, with discovery expected once: the server caches a provider's discovery document, so a
 * second expectation for the same issuer is never consumed and would surface as a pending interceptor in
 * whichever spec runs next.
 */
const stubs = new Map<string, Awaited<ReturnType<typeof idpStub>>>();

async function signInAs(origin: string, claims: Record<string, unknown>) {
	let idp = stubs.get(origin);
	if (!idp) {
		idp = await idpStub(origin);
		idp.expectDiscovery();
		stubs.set(origin, idp);
	}
	const { uid, cookie } = await startInteraction();
	return walk(uid, cookie, { idp, claims });
}

/**
 * @proves A person a directory provisioned signs in through the same directory into the account it
 * provisioned, matched by the connection's correlation rule and never by email, and nobody else gets in
 * that way (spec 070, User Story 3; FR-038, FR-039; SC-003).
 */
describe('signing in at a provider bound to a provisioning connection', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
	});

	it('lands in the provisioned user its correlation claim names, creating no account', async () => {
		const origin = 'https://idp-corr-match.test';
		const { bucket, connectionId } = await boundBucket(origin);
		const user = await provision(bucket, connectionId, {
			email: 'rita@contoso.com',
			externalId: 'oid-rita'
		});

		await signInAs(origin, { oid: 'oid-rita', email: 'rita@contoso.com' });

		expect(signedInAccountIds()).toContain(user._id);
		expect(await getUserStore(bucket._id).list()).toHaveLength(1);
		const stored = await getUserStore(bucket._id).find(user._id);
		expect(stored?.federated).toEqual([
			expect.objectContaining({
				providerId: 'acme-sso',
				sub: 'upstream-subject-1'
			})
		]);
	});

	it('signs a returning user in through the link', async () => {
		const origin = 'https://idp-corr-return.test';
		const { bucket, connectionId } = await boundBucket(origin);
		const user = await provision(bucket, connectionId, {
			email: 'sam@contoso.com',
			externalId: 'oid-sam'
		});
		await signInAs(origin, { oid: 'oid-sam' });

		/* The correlation claim is gone; the link alone must carry the second sign-in. */
		await signInAs(origin, { email: 'sam@contoso.com' });

		expect(signedInAccountIds().filter((id) => id === user._id)).toHaveLength(
			2
		);
	});

	it('refuses a sign-in no provisioned user answers to, even when its email matches an existing user', async () => {
		const origin = 'https://idp-corr-email.test';
		const { bucket } = await boundBucket(origin);
		const local = await getUserStore(bucket._id).create(
			'tess@contoso.com',
			'hash',
			true
		);

		const { callback } = await signInAs(origin, {
			oid: 'oid-unknown',
			email: 'tess@contoso.com',
			email_verified: true
		});

		expect(signedInAccountIds()).not.toContain(local._id);
		expect(callback.status).toBeGreaterThanOrEqual(400);
		expect(await getUserStore(bucket._id).list()).toHaveLength(1);
		expect(
			(await getUserStore(bucket._id).find(local._id))?.federated ?? []
		).toEqual([]);
	});

	it('refuses a provisioned user who is deactivated or locked', async () => {
		const origin = 'https://idp-corr-frozen.test';
		const { bucket, connectionId } = await boundBucket(origin);
		const inactive = await provision(bucket, connectionId, {
			email: 'uma@contoso.com',
			externalId: 'oid-uma'
		});
		await updateEndUser(
			bucket,
			{ kind: 'connection', connectionId },
			inactive._id,
			{ active: false },
			noAudit
		);
		const locked = await provision(bucket, connectionId, {
			email: 'vic@contoso.com',
			externalId: 'oid-vic'
		});
		await lockEndUser(
			bucket,
			locked._id,
			{ by: 'admin', reason: 'incident' },
			noAudit
		);

		await signInAs(origin, { oid: 'oid-uma' });
		await signInAs(origin, { oid: 'oid-vic', sub: 'upstream-subject-2' });

		expect(signedInAccountIds()).not.toContain(inactive._id);
		expect(signedInAccountIds()).not.toContain(locked._id);
	});

	it('does not re-link a provisioned user already linked to another subject', async () => {
		const origin = 'https://idp-corr-conflict.test';
		const { bucket, connectionId } = await boundBucket(origin);
		const user = await provision(bucket, connectionId, {
			email: 'walt@contoso.com',
			externalId: 'oid-walt'
		});
		await getUserStore(bucket._id).update(user._id, {
			federated: [
				{ providerId: 'acme-sso', sub: 'someone-else', linkedAt: new Date() }
			]
		});

		await signInAs(origin, { oid: 'oid-walt' });

		expect(signedInAccountIds()).not.toContain(user._id);
		expect((await getUserStore(bucket._id).find(user._id))?.federated).toEqual([
			expect.objectContaining({ sub: 'someone-else' })
		]);
	});

	it('sends an untrusted connection’s user through the bucket’s email verification on first sign-in', async () => {
		const origin = 'https://idp-corr-verify.test';
		const { bucket, connectionId } = await boundBucket(
			origin,
			{ emailTrust: 'untrusted' },
			{ emailVerificationRequired: true }
		);
		const user = await provision(bucket, connectionId, {
			email: 'xena@contoso.com',
			externalId: 'oid-xena',
			verified: false
		});

		const { complete } = await signInAs(origin, { oid: 'oid-xena' });

		expect(signedInAccountIds()).not.toContain(user._id);
		expect(complete?.location ?? '').toContain('verify');
	});

	it('for every generated population and sign-in, lands in the user the rule names or refuses, creating nothing and never matching by email', async () => {
		const origin = 'https://idp-corr-property.test';
		const { bucket, connectionId } = await boundBucket(origin);
		const store = getUserStore(bucket._id);
		const population = new Map<string, string>();
		for (let i = 0; i < 6; i++) {
			const user = await provision(bucket, connectionId, {
				email: `p${i}@contoso.com`,
				externalId: `oid-${i}`
			});
			population.set(`oid-${i}`, user._id);
		}
		const before = (await store.list()).length;
		const provider = bucket.federation?.[0];
		if (!provider) throw new Error('expected the bound provider');

		await fc.assert(
			fc.asyncProperty(
				fc.oneof(
					fc.constantFrom(...population.keys()),
					fc.string({ maxLength: 12 })
				),
				fc.constantFrom(
					...[...population.keys()].map((k) => k.replace('oid', 'p'))
				),
				fc.uuid(),
				async (oid, emailLocal, sub) => {
					const resolution = await resolveFederatedAccount({
						bucket,
						provider,
						subject: sub,
						claims: {
							oid,
							email: `${emailLocal}@contoso.com`,
							email_verified: true
						}
					});
					const expected = population.get(oid);
					if (resolution.ok) {
						expect(resolution.account._id).toBe(expected as string);
						expect(resolution.provisioned).toBe(false);
						/* Undo the link, so the next run of this account correlates afresh. */
						await store.update(resolution.account._id, {
							federated: undefined
						});
					} else {
						expect(
							expected === undefined || resolution.reason === 'link_conflict'
						).toBe(true);
					}
					expect((await store.list()).length).toBe(before);
				}
			),
			{ numRuns: 60 }
		);
	});
});
