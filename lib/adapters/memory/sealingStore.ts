import { getStorage } from './storage.js';
import { PRIVATE_JWK_MEMBERS } from '../../consts/sealed_fields.js';
import { ROOT_KEY_OWNER } from '../../consts/key_owner.js';
import type { SealKind, SealTarget } from '../../consts/sealed_fields.js';
import type {
	BucketKeysStoreInstance,
	SealedLeaf,
	SealingStoreInstance,
	SecretStoreInstance,
	SmtpSettingsStoreInstance,
	UserBucketStoreInstance,
	UserStoreInstance
} from '../types.js';

/*
 * The undecorated stores the in-memory pass reads through: the encryption pass works on values as they are
 * stored, so it must never be handed the stores that open them.
 */
export interface MemorySealingSources {
	buckets(): UserBucketStoreInstance;
	users(bucketId: string): UserStoreInstance;
	keys(): BucketKeysStoreInstance;
	smtp(): SmtpSettingsStoreInstance;
	secret(kind: 'dpopNonceSecret' | 'errorOriginSalt'): SecretStoreInstance;
}

function same(a: unknown, b: string | Uint8Array): boolean {
	if (typeof a === 'string' || typeof b === 'string') return a === b;
	return a instanceof Uint8Array && Buffer.from(a).equals(Buffer.from(b));
}

function modelRecords(model: string): [string, Record<string, unknown>][] {
	const storage = getStorage();
	const prefix = `${model}:`;
	const found: [string, Record<string, unknown>][] = [];
	for (const key of storage.keys()) {
		if (!key.startsWith(prefix)) continue;
		const value = storage.get(key);
		if (typeof value === 'object' && !Array.isArray(value)) {
			found.push([key.slice(prefix.length), value]);
		}
	}
	return found;
}

/*
 * Single-process: a compare and its write have no other request between them that matters, so the
 * conditional writes of the persistent backends are a plain comparison here.
 */
export class SealingStore implements SealingStoreInstance {
	constructor(private readonly sources: MemorySealingSources) {}

	private async bucketIds(): Promise<string[]> {
		return (await this.sources.buckets().list()).map((bucket) => bucket._id);
	}

	async scan(kind: SealKind): Promise<SealedLeaf[]> {
		const leaves: SealedLeaf[] = [];
		switch (kind) {
			case 'providerSecret':
			case 'providerSigningKey': {
				const field = kind === 'providerSecret' ? 'clientSecret' : 'signingKey';
				for (const bucket of await this.sources.buckets().list()) {
					for (const provider of bucket.federation) {
						const value = provider[field];
						if (typeof value === 'string' && value !== '') {
							leaves.push({
								target: { kind, bucketId: bucket._id, providerId: provider.id },
								value
							});
						}
					}
				}
				return leaves;
			}
			case 'clientSecret':
				for (const [clientId, record] of modelRecords('Client')) {
					if (
						typeof record.clientSecret === 'string' &&
						record.clientSecret !== ''
					) {
						leaves.push({
							target: { kind, clientId },
							value: record.clientSecret
						});
					}
				}
				return leaves;
			case 'totpPending':
				for (const [uid, record] of modelRecords('TotpEnrollment')) {
					if (
						typeof record.secret === 'string' &&
						typeof record.bucketId === 'string' &&
						typeof record.accountId === 'string'
					) {
						leaves.push({
							target: {
								kind,
								uid,
								bucketId: record.bucketId,
								accountId: record.accountId
							},
							value: record.secret
						});
					}
				}
				return leaves;
			case 'smtpPassword': {
				const settings = await this.sources.smtp().get();
				if (settings && settings.password !== '') {
					leaves.push({ target: { kind }, value: settings.password });
				}
				return leaves;
			}
			case 'privateKey':
				for (const owner of [ROOT_KEY_OWNER, ...(await this.bucketIds())]) {
					for (const key of await this.sources.keys().listByBucket(owner)) {
						for (const member of PRIVATE_JWK_MEMBERS) {
							const value = (key.jwk as Record<string, unknown>)[member];
							if (typeof value === 'string') {
								leaves.push({
									target: {
										kind,
										keyId: key._id,
										bucketId: key.bucketId,
										kid: key.kid,
										member
									},
									value,
									revoked: key.state === 'revoked'
								});
							}
						}
					}
				}
				return leaves;
			case 'totpSecret':
				for (const bucketId of await this.bucketIds()) {
					for (const user of await this.sources.users(bucketId).list()) {
						if (typeof user.totp?.secret === 'string') {
							leaves.push({
								target: { kind, bucketId, userId: user._id },
								value: user.totp.secret
							});
						}
					}
				}
				return leaves;
			case 'dpopNonceSecret':
			case 'errorOriginSalt': {
				const value = await this.sources.secret(kind).read();
				if (value instanceof Uint8Array) {
					leaves.push({ target: { kind }, value });
				}
				return leaves;
			}
		}
	}

	async sealAt(
		target: SealTarget,
		observed: string | Uint8Array,
		next: string | Uint8Array
	): Promise<boolean> {
		switch (target.kind) {
			case 'providerSecret':
			case 'providerSigningKey': {
				const field =
					target.kind === 'providerSecret' ? 'clientSecret' : 'signingKey';
				const bucket = await this.sources.buckets().find(target.bucketId);
				const provider = bucket?.federation.find(
					(candidate) => candidate.id === target.providerId
				);
				if (!bucket || !provider || !same(provider[field], observed))
					return false;
				await this.sources.buckets().update(bucket._id, {
					federation: bucket.federation.map((candidate) =>
						candidate.id === target.providerId
							? { ...candidate, [field]: next as string }
							: candidate
					)
				});
				return true;
			}
			case 'clientSecret':
			case 'totpPending': {
				const model =
					target.kind === 'clientSecret' ? 'Client' : 'TotpEnrollment';
				const field =
					target.kind === 'clientSecret' ? 'clientSecret' : 'secret';
				const id =
					target.kind === 'clientSecret' ? target.clientId : target.uid;
				const record = getStorage().get(`${model}:${id}`);
				if (
					typeof record !== 'object' ||
					Array.isArray(record) ||
					!same(record[field], observed)
				) {
					return false;
				}
				record[field] = next;
				return true;
			}
			case 'smtpPassword': {
				const settings = await this.sources.smtp().get();
				if (!settings || !same(settings.password, observed)) return false;
				await this.sources
					.smtp()
					.set({ ...settings, password: next as string });
				return true;
			}
			case 'privateKey': {
				const store = this.sources.keys();
				const key = await store.find(target.bucketId, target.kid);
				const jwk = key?.jwk as Record<string, unknown> | undefined;
				if (!key || !jwk || !same(jwk[target.member], observed)) return false;
				await store.destroy(target.bucketId, target.kid);
				await store.createIfAbsent({
					...key,
					jwk: { ...key.jwk, [target.member]: next as string }
				});
				return true;
			}
			case 'totpSecret': {
				const users = this.sources.users(target.bucketId);
				const user = await users.find(target.userId);
				if (!user?.totp || !same(user.totp.secret, observed)) return false;
				await users.update(target.userId, {
					totp: { ...user.totp, secret: next as string }
				});
				return true;
			}
			case 'dpopNonceSecret':
			case 'errorOriginSalt': {
				const store = this.sources.secret(target.kind);
				const written = await store.replace(observed, Buffer.from(next));
				return written instanceof Uint8Array && same(written, next);
			}
		}
	}
}
