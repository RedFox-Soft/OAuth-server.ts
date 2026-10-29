import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	OTHER_KEYRING,
	ROTATED_KEYRING,
	STAGED_KEYRING,
	TEST_KEYRING
} from './fixtures.ts';
import { client } from './sealing.config.ts';
import {
	adapter,
	dpopNonceSecretStore,
	errorOriginSaltStore,
	getBucketKeysStore,
	getBucketStore,
	getKeyringStateStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	clientCredential,
	CredentialError
} from 'lib/federation/credential.ts';
import { generateJWKS } from 'lib/helpers/jwks.ts';
import { invalidateBucketKeys, keysFor } from 'lib/keys/issuer_keys.ts';
import { mailDeliveryConfigured } from 'lib/mail/mailer.ts';
import { resolveNonceSecret } from 'lib/configs/nonceSecret.ts';
import { captureOrigin, resetOriginSalt } from 'lib/error_store/redact.ts';
import { decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import { verifyForAccount } from 'lib/totp/verify.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { keyringStatus } from 'lib/sealing/status.ts';
import { resetUnreadableForTests } from 'lib/sealing/unreadable.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import type { FederationProvider } from 'lib/federation/types.ts';

const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

function provider(id: string, clientSecret: string): FederationProvider {
	return {
		id,
		displayName: id,
		enabled: true,
		issuer: 'https://sso.example.com',
		clientId: `${id}-client`,
		clientSecret,
		scopes: ['openid'],
		emailTrusted: false,
		provisioning: 'jit',
		allowedEmailDomains: [],
		emailClaim: 'email'
	};
}

async function tokenStatus(clientId: string, secret: string): Promise<number> {
	const { status } = await agent.token.post(
		{ grant_type: 'client_credentials', scope: 'api:read' },
		{ headers: AuthorizationRequest.basicAuthHeader(clientId, secret) }
	);
	return status;
}

async function enrolledPerson(bucketId: string) {
	const users = getUserStore(bucketId);
	const user = await users.create(`lost-${Math.random()}@x.io`, 'x');
	await users.update(user._id, {
		totp: { secret: TOTP_SECRET, enrolledAt: new Date(), lastStep: 0 }
	});
	return user;
}

async function listed(kind: string, field: string, value: string) {
	return (await keyringStatus()).unreadable.some(
		(entry) => entry.kind === kind && entry.owner[field] === value
	);
}

/**
 * @proves When the keyring lacks the key some secrets were sealed with, the instance keeps serving, every check
 * that needs such a secret fails closed, the status names each one and the key it needs, and each has a way
 * back.
 */
describe('a keyring that lacks a key in use', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		resetUnreadableForTests();
	});

	afterEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	it('an application whose secret is unreadable is refused as invalid_client', async () => {
		resetKeyringForTests(OTHER_KEYRING);

		expect(await tokenStatus(client.clientId, client.clientSecret)).toBe(401);
	});

	it('a person whose TOTP secret is unreadable is refused the second factor', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `lost-totp-${Math.random()}`
		});
		const person = await enrolledPerson(bucket._id);
		resetKeyringForTests(OTHER_KEYRING);

		const outcome = await verifyForAccount(
			bucket._id,
			person._id,
			hotp(decodeBase32(TOTP_SECRET), stepFor(epochTime()))
		);

		expect(outcome.ok).toBe(false);
	});

	it('a provider whose credential is unreadable is refused as not configured, and another provider still has its own', async () => {
		resetKeyringForTests(ROTATED_KEYRING);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `lost-provider-${Math.random()}`,
			federation: [provider('sealed-under-next', 'next-secret')]
		});
		resetKeyringForTests(TEST_KEYRING);
		const stored = await getBucketStore().find(bucket._id);
		await getBucketStore().update(bucket._id, {
			federation: [
				...(stored?.federation ?? []),
				provider('sealed-under-test', 'test-secret')
			]
		});

		const [lost, kept] =
			(await getBucketStore().find(bucket._id))?.federation ?? [];

		await expect(clientCredential(lost)).rejects.toBeInstanceOf(
			CredentialError
		);
		expect(await clientCredential(kept)).toBe('test-secret');
	});

	it('mail is refused as unconfigured when the SMTP password is unreadable', async () => {
		await getSmtpSettingsStore().set({
			host: 'smtp.example.com',
			port: 587,
			secure: false,
			username: 'mailer',
			password: 'mail-password',
			fromName: 'FoxAuth',
			fromEmail: 'noreply@example.com'
		});
		resetKeyringForTests(OTHER_KEYRING);

		expect(await mailDeliveryConfigured()).toBe(false);
	});

	it('a project whose newest signing key is unreadable signs with its other key of that algorithm', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `lost-keys-${Math.random()}`,
			slug: `lost-keys-${Math.floor(Math.random() * 1e9)}`
		});
		const now = new Date();
		const record = async (state: 'signing' | 'published') => {
			const [jwk] = (await generateJWKS('RS256')).keys;
			await getBucketKeysStore().createIfAbsent({
				_id: `${bucket._id} ${jwk.kid}`,
				bucketId: bucket._id,
				kid: jwk.kid,
				jwk,
				alg: 'RS256',
				use: 'sig',
				state,
				createdAt: now,
				stateChangedAt: now
			});
			return jwk.kid;
		};
		resetKeyringForTests(ROTATED_KEYRING);
		await record('signing');
		resetKeyringForTests(STAGED_KEYRING);
		const standby = await record('published');
		resetKeyringForTests(TEST_KEYRING);
		invalidateBucketKeys(bucket._id);

		const keys = await keysFor(bucket);

		expect(
			keys.signing.selectForSign({ alg: 'RS256' }).map((key) => key.kid)
		).toEqual([standby]);
	});

	it('an unreadable DPoP nonce secret and error-origin salt are regenerated at start', async () => {
		resetKeyringForTests(ROTATED_KEYRING);
		await dpopNonceSecretStore.replace(
			await dpopNonceSecretStore.read(),
			Buffer.alloc(32, 3)
		);
		const salt = await errorOriginSaltStore.read();
		if (salt === null) await errorOriginSaltStore.create(Buffer.alloc(32, 4));
		else await errorOriginSaltStore.replace(salt, Buffer.alloc(32, 4));
		resetKeyringForTests(TEST_KEYRING);
		resetOriginSalt();

		const nonce = await resolveNonceSecret(dpopNonceSecretStore, undefined);
		const origin = await captureOrigin('203.0.113.7', 'anonymized');

		expect(nonce).toHaveLength(32);
		expect(origin).toMatch(/^[0-9a-f]{16}$/);
		expect(
			(await getKeyringStateStore().read())?.regenerated?.errorOriginSalt
		).toBeDefined();
	});

	it('the status lists each unreadable value with its owner and the key it needs', async () => {
		resetKeyringForTests(OTHER_KEYRING);
		await adapter('Client').find(client.clientId);

		const entry = (await keyringStatus()).unreadable.find(
			(candidate) =>
				candidate.kind === 'clientSecret' &&
				candidate.owner.clientId === client.clientId
		);

		expect(entry?.needsKid).toBe(TEST_KEYRING.write);
	});

	describe('each reset path removes its entry from the unreadable list', () => {
		it('rotating an application secret', async () => {
			await adapter('Client').upsert('reset-client', {
				clientId: 'reset-client',
				clientSecret: 'old',
				grantTypes: ['client_credentials'],
				responseTypes: [],
				redirectUris: []
			});
			resetKeyringForTests(OTHER_KEYRING);
			const stored = await adapter('Client').find('reset-client');
			expect(await listed('clientSecret', 'clientId', 'reset-client')).toBe(
				true
			);

			await adapter('Client').upsert('reset-client', {
				...stored,
				clientSecret: 'rotated'
			});

			expect(await listed('clientSecret', 'clientId', 'reset-client')).toBe(
				false
			);
		});

		it('re-entering a provider secret', async () => {
			const bucket = await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: `reset-provider-${Math.random()}`,
				federation: [provider('reset-sso', 'old')]
			});
			resetKeyringForTests(OTHER_KEYRING);
			await getBucketStore().find(bucket._id);
			expect(await listed('providerSecret', 'bucketId', bucket._id)).toBe(true);

			await getBucketStore().update(bucket._id, {
				federation: [provider('reset-sso', 're-entered')]
			});

			expect(await listed('providerSecret', 'bucketId', bucket._id)).toBe(
				false
			);
		});

		it('re-entering the mail password', async () => {
			const settings = {
				host: 'smtp.example.com',
				port: 587,
				secure: false,
				username: 'mailer',
				password: 'old',
				fromName: 'FoxAuth',
				fromEmail: 'noreply@example.com'
			};
			await getSmtpSettingsStore().set(settings);
			resetKeyringForTests(OTHER_KEYRING);
			await getSmtpSettingsStore().get();
			expect(
				(await keyringStatus()).unreadable.some(
					(e) => e.kind === 'smtpPassword'
				)
			).toBe(true);

			await getSmtpSettingsStore().set({ ...settings, password: 're-entered' });

			expect(
				(await keyringStatus()).unreadable.some(
					(e) => e.kind === 'smtpPassword'
				)
			).toBe(false);
		});

		it('clearing an authenticator', async () => {
			const bucket = await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: `reset-totp-${Math.random()}`
			});
			const person = await enrolledPerson(bucket._id);
			resetKeyringForTests(OTHER_KEYRING);
			await getUserStore(bucket._id).find(person._id);
			expect(await listed('totpSecret', 'userId', person._id)).toBe(true);

			await getUserStore(bucket._id).update(person._id, { totp: undefined });

			expect(await listed('totpSecret', 'userId', person._id)).toBe(false);
		});

		it('revoking an unreadable project key', async () => {
			const [jwk] = (await generateJWKS('ES256')).keys;
			const now = new Date();
			await getBucketKeysStore().createIfAbsent({
				_id: `reset-keys ${jwk.kid}`,
				bucketId: 'reset-keys',
				kid: jwk.kid,
				jwk,
				alg: 'ES256',
				use: 'sig',
				state: 'published',
				createdAt: now,
				stateChangedAt: now
			});
			resetKeyringForTests(OTHER_KEYRING);
			await getBucketKeysStore().listByBucket('reset-keys');
			expect(await listed('privateKey', 'kid', jwk.kid)).toBe(true);

			await getBucketKeysStore().setState(
				'reset-keys',
				jwk.kid,
				'revoked',
				now
			);

			expect(await listed('privateKey', 'kid', jwk.kid)).toBe(false);
		});
	});
});
