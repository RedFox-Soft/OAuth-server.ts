import { beforeAll, describe, expect, it } from 'bun:test';
import { decodeProtectedHeader } from 'jose';

import bootstrap from '../test_helper.ts';
import { TEST_KEYRING } from './fixtures.ts';
import {
	adapter,
	dpopNonceSecretStore,
	errorOriginSaltStore,
	getBucketKeysStore,
	getBucketStore,
	getConnectedAccountStore,
	getSealingStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import {
	bindingOf,
	SEALED_FIELDS,
	type SealKind,
	type SealTarget
} from 'lib/consts/sealed_fields.ts';
import { ROOT_KEY_OWNER } from 'lib/consts/key_owner.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { generateJWKS } from 'lib/helpers/jwks.ts';
import { SEALED_PREFIX } from 'lib/sealing/seal.ts';

/*
 * One write per declared kind, through the store every caller uses, returning which stored leaf it made. A
 * `Record` over `SealKind`, so a kind declared without a writer here does not compile.
 */
const writers: Record<
	SealKind,
	() => Promise<(target: SealTarget) => boolean>
> = {
	async providerSecret() {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `sealed-provider-${Math.random()}`,
			federation: [
				{
					id: 'sealed-sso',
					displayName: 'Sealed SSO',
					enabled: true,
					issuer: 'https://sso.example.com',
					clientId: 'sealed-client',
					clientSecret: 'provider-secret-value',
					signingKey:
						'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----',
					scopes: ['openid'],
					emailTrusted: false,
					provisioning: 'jit',
					allowedEmailDomains: [],
					emailClaim: 'email'
				}
			]
		});
		return (target) =>
			target.kind === 'providerSecret' && target.bucketId === bucket._id;
	},
	async providerSigningKey() {
		const found = (await getBucketStore().list()).find((bucket) =>
			bucket.federation.some((provider) => provider.id === 'sealed-sso')
		);
		return (target) =>
			target.kind === 'providerSigningKey' && target.bucketId === found?._id;
	},
	async clientSecret() {
		await adapter('Client').upsert('sealed-declared-client', {
			clientId: 'sealed-declared-client',
			clientSecret: 'client-secret-value',
			grantTypes: ['client_credentials'],
			responseTypes: [],
			redirectUris: []
		});
		return (target) =>
			target.kind === 'clientSecret' &&
			target.clientId === 'sealed-declared-client';
	},
	async smtpPassword() {
		await getSmtpSettingsStore().set({
			host: 'smtp.example.com',
			port: 587,
			secure: false,
			username: 'mailer',
			password: 'smtp-password-value',
			fromName: 'FoxAuth',
			fromEmail: 'noreply@example.com'
		});
		return (target) => target.kind === 'smtpPassword';
	},
	async privateKey() {
		const [jwk] = (await generateJWKS('ES256')).keys;
		const now = new Date();
		await getBucketKeysStore().createIfAbsent({
			_id: `${ROOT_KEY_OWNER} ${jwk.kid}`,
			bucketId: ROOT_KEY_OWNER,
			kid: jwk.kid,
			jwk,
			alg: 'ES256',
			use: 'sig',
			state: 'published',
			createdAt: now,
			stateChangedAt: now
		});
		return (target) => target.kind === 'privateKey' && target.kid === jwk.kid;
	},
	async totpSecret() {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `sealed-totp-${Math.random()}`
		});
		const users = getUserStore(bucket._id);
		const user = await users.create('totp@example.com', 'x');
		await users.update(user._id, {
			totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 }
		});
		return (target) =>
			target.kind === 'totpSecret' && target.userId === user._id;
	},
	async totpPending() {
		await adapter('TotpEnrollment').upsert(
			'sealed-uid',
			{
				accountId: 'pending-person',
				bucketId: 'pending-bucket',
				secret: 'KRSXG5CTMVRXEZLU',
				exp: Math.floor(Date.now() / 1000) + 600
			},
			600
		);
		return (target) =>
			target.kind === 'totpPending' && target.uid === 'sealed-uid';
	},
	async dpopNonceSecret() {
		await dpopNonceSecretStore.replace(
			await dpopNonceSecretStore.read(),
			Buffer.alloc(32, 1)
		);
		return (target) => target.kind === 'dpopNonceSecret';
	},
	async errorOriginSalt() {
		const current = await errorOriginSaltStore.read();
		if (current === null)
			await errorOriginSaltStore.create(Buffer.alloc(32, 2));
		else await errorOriginSaltStore.replace(current, Buffer.alloc(32, 2));
		return (target) => target.kind === 'errorOriginSalt';
	},
	async connectedServiceSecret() {
		const now = new Date().toISOString();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `sealed-service-${Math.random()}`
		});
		await getBucketStore().update(bucket._id, {
			connectedServices: [
				{
					id: 'sealed-github',
					kind: 'catalogue',
					catalogueId: 'github',
					clientId: 'sealed-github-client',
					clientSecret: 'service-secret-value',
					scopes: ['read:user'],
					displayName: 'GitHub',
					createdAt: now,
					updatedAt: now
				}
			]
		});
		return (target) =>
			target.kind === 'connectedServiceSecret' &&
			target.bucketId === bucket._id;
	},
	async connectedAccountToken() {
		const now = new Date().toISOString();
		await getConnectedAccountStore().put({
			_id: 'sealed-connected-account',
			bucketId: 'sealed-bucket',
			serviceId: 'sealed-github',
			accountId: 'sealed-person',
			upstreamId: '42',
			label: 'octocat',
			refreshToken: 'ghr_refresh-value',
			accessToken: 'gho_access-value',
			tokenType: 'bearer',
			scopes: ['read:user'],
			scopesInferred: false,
			connectedAt: now,
			updatedAt: now
		});
		return (target) =>
			target.kind === 'connectedAccountToken' &&
			target.id === 'sealed-connected-account';
	}
};

function headerOf(value: string | Uint8Array) {
	const text =
		typeof value === 'string' ? value : Buffer.from(value).toString('utf8');
	return decodeProtectedHeader(text.slice(SEALED_PREFIX.length));
}

/**
 * @proves Every secret the server must read back is stored sealed with the keyring when written through the
 * stores every caller uses, bound to the record and field it belongs to.
 */
describe('secrets written with a keyring in use', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('for every declared sealed field, a value written through its store is stored sealed and bound to its record', async () => {
		for (const field of SEALED_FIELDS) {
			const isOurs = await writers[field.kind]();
			const leaves = (await getSealingStore().scan(field.kind)).filter((leaf) =>
				isOurs(leaf.target)
			);
			expect(leaves.length, field.kind).toBeGreaterThan(0);
			for (const leaf of leaves) {
				const text =
					typeof leaf.value === 'string'
						? leaf.value
						: Buffer.from(leaf.value).toString('utf8');
				expect(text.startsWith(SEALED_PREFIX), field.kind).toBe(true);
				const header = headerOf(leaf.value);
				expect(header.bnd, field.kind).toBe(bindingOf(leaf.target));
				expect(header.kid, field.kind).toBe(TEST_KEYRING.write);
			}
		}
	});
});
