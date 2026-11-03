import crypto from 'crypto';
import { ObjectId } from 'mongodb';

import { db } from './db.js';
import { SingletonSecretStore } from './singletonSecretStore.js';
import { STORE_AREAS, userAreaFor } from '../../consts/storage_inventory.js';
import {
	CONNECTED_ACCOUNT_TOKEN_FIELDS,
	PRIVATE_JWK_MEMBERS
} from '../../consts/sealed_fields.js';
import type {
	PrivateJwkMember,
	SealKind,
	SealTarget
} from '../../consts/sealed_fields.js';
import { isRecord } from '../../helpers/_/object.js';
import type { SealedLeaf, SealingStoreInstance } from '../types.js';

type Raw = { _id: string } & Record<string, unknown>;

function stringTo24CharHex(value: string): string {
	return crypto
		.createHash('sha256')
		.update(value)
		.digest('hex')
		.substring(0, 24);
}

function same(a: unknown, b: string | Uint8Array): boolean {
	if (typeof a === 'string' || typeof b === 'string') return a === b;
	return a instanceof Uint8Array && Buffer.from(a).equals(Buffer.from(b));
}

function text(value: string | Uint8Array): string {
	if (typeof value !== 'string') {
		throw new Error(
			'a sealed text leaf can only be compared with or set to text'
		);
	}
	return value;
}

/* The member becomes part of a field path, so it is checked against the list rather than trusted from the type. */
function jwkPath(member: PrivateJwkMember): string {
	if (!(PRIVATE_JWK_MEMBERS as readonly string[]).includes(member)) {
		throw new Error(`'${member}' is not a private JWK member`);
	}
	return `jwk.${member}`;
}

function filled(value: unknown): value is string {
	return typeof value === 'string' && value !== '';
}

/*
 * The encryption pass's own view of the datastore (specs/116 R8): every leaf read as it is stored, and every
 * write a compare-and-set of that one leaf, so an edit made between the pass's read and its write is never
 * undone. Reads the collections directly, never through the stores the sealing decorators wrap.
 *
 * Each write answers whether its filter matched, which, with the observed value in the filter, is whether it
 * wrote: the same answer the in-memory pass gives for a value sealed to itself.
 */
export class SealingStore implements SealingStoreInstance {
	private settingsId = new ObjectId(stringTo24CharHex('smtpSettings'));

	private collection(name: string) {
		return db.collection<Raw>(name);
	}

	private async bucketIds(): Promise<string[]> {
		const buckets = await this.collection(STORE_AREAS.userBuckets)
			.find({}, { projection: { _id: 1 } })
			.toArray();
		return buckets.map((bucket) => bucket._id);
	}

	async scan(kind: SealKind): Promise<SealedLeaf[]> {
		const leaves: SealedLeaf[] = [];
		switch (kind) {
			case 'providerSecret':
			case 'providerSigningKey': {
				const field = kind === 'providerSecret' ? 'clientSecret' : 'signingKey';
				const buckets = await this.collection(STORE_AREAS.userBuckets)
					.find(
						{ federation: { $elemMatch: { [field]: { $type: 'string' } } } },
						{ projection: { federation: 1 } }
					)
					.toArray();
				for (const bucket of buckets) {
					const federation = Array.isArray(bucket.federation)
						? (bucket.federation as unknown[])
						: [];
					for (const provider of federation) {
						if (!isRecord(provider) || typeof provider.id !== 'string')
							continue;
						const value = provider[field];
						if (filled(value)) {
							leaves.push({
								target: { kind, bucketId: bucket._id, providerId: provider.id },
								value
							});
						}
					}
				}
				return leaves;
			}
			case 'clientSecret': {
				const clients = await this.collection('Client')
					.find(
						{ 'payload.clientSecret': { $type: 'string' } },
						{ projection: { 'payload.clientSecret': 1 } }
					)
					.toArray();
				for (const client of clients) {
					const value = isRecord(client.payload)
						? client.payload.clientSecret
						: undefined;
					if (filled(value)) {
						leaves.push({ target: { kind, clientId: client._id }, value });
					}
				}
				return leaves;
			}
			case 'totpPending': {
				const enrolments = await this.collection('TotpEnrollment')
					.find(
						{ 'payload.secret': { $type: 'string' } },
						{
							projection: {
								'payload.secret': 1,
								'payload.bucketId': 1,
								'payload.accountId': 1
							}
						}
					)
					.toArray();
				for (const enrolment of enrolments) {
					const payload = isRecord(enrolment.payload) ? enrolment.payload : {};
					if (
						typeof payload.secret === 'string' &&
						typeof payload.bucketId === 'string' &&
						typeof payload.accountId === 'string'
					) {
						leaves.push({
							target: {
								kind,
								uid: enrolment._id,
								bucketId: payload.bucketId,
								accountId: payload.accountId
							},
							value: payload.secret
						});
					}
				}
				return leaves;
			}
			case 'signInTokenInTransit': {
				const handoffs = await this.collection('FederationState')
					.find(
						{ 'payload.kept.tokens': { $type: 'string' } },
						{
							projection: {
								'payload.kept.tokens': 1,
								'payload.accountId': 1
							}
						}
					)
					.toArray();
				for (const handoff of handoffs) {
					const payload = isRecord(handoff.payload) ? handoff.payload : {};
					const kept = isRecord(payload.kept) ? payload.kept : {};
					if (
						typeof kept.tokens === 'string' &&
						typeof payload.accountId === 'string'
					) {
						leaves.push({
							target: { kind, id: handoff._id, accountId: payload.accountId },
							value: kept.tokens
						});
					}
				}
				return leaves;
			}
			case 'smtpPassword': {
				const found = await db
					.collection(STORE_AREAS.serviceConfig)
					.findOne({ _id: this.settingsId });
				const value = isRecord(found?.settings)
					? found.settings.password
					: undefined;
				if (filled(value)) leaves.push({ target: { kind }, value });
				return leaves;
			}
			case 'privateKey': {
				const keys = await this.collection(STORE_AREAS.bucketKeys)
					.find({})
					.toArray();
				for (const key of keys) {
					const { bucketId, kid, jwk, state } = key;
					if (
						typeof bucketId !== 'string' ||
						typeof kid !== 'string' ||
						!isRecord(jwk)
					) {
						continue;
					}
					for (const member of PRIVATE_JWK_MEMBERS) {
						const value = jwk[member];
						if (typeof value === 'string') {
							leaves.push({
								target: { kind, keyId: key._id, bucketId, kid, member },
								value,
								revoked: state === 'revoked'
							});
						}
					}
				}
				return leaves;
			}
			case 'totpSecret':
				for (const bucketId of await this.bucketIds()) {
					// The enrolment test the user store's `totpEnrolled` filter uses: an enrolment is an object.
					const users = await this.collection(userAreaFor(bucketId))
						.find(
							{ totp: { $type: 'object' } },
							{ projection: { 'totp.secret': 1 } }
						)
						.toArray();
					for (const user of users) {
						const value = isRecord(user.totp) ? user.totp.secret : undefined;
						if (typeof value === 'string') {
							leaves.push({
								target: { kind, bucketId, userId: user._id },
								value
							});
						}
					}
				}
				return leaves;
			case 'connectedServiceSecret': {
				const buckets = await this.collection(STORE_AREAS.userBuckets)
					.find(
						{
							connectedServices: {
								$elemMatch: { clientSecret: { $type: 'string' } }
							}
						},
						{ projection: { connectedServices: 1 } }
					)
					.toArray();
				for (const bucket of buckets) {
					const services = Array.isArray(bucket.connectedServices)
						? (bucket.connectedServices as unknown[])
						: [];
					for (const service of services) {
						if (!isRecord(service) || typeof service.id !== 'string') continue;
						if (filled(service.clientSecret)) {
							leaves.push({
								target: { kind, bucketId: bucket._id, serviceId: service.id },
								value: service.clientSecret
							});
						}
					}
				}
				return leaves;
			}
			case 'connectedAccountToken': {
				const records = await this.collection(STORE_AREAS.connectedAccounts)
					.find(
						{},
						{
							projection: {
								refreshToken: 1,
								accessToken: 1,
								bucketId: 1,
								accountId: 1
							}
						}
					)
					.toArray();
				for (const record of records) {
					for (const field of CONNECTED_ACCOUNT_TOKEN_FIELDS) {
						const value = record[field];
						if (
							filled(value) &&
							typeof record.bucketId === 'string' &&
							typeof record.accountId === 'string'
						) {
							leaves.push({
								target: {
									kind,
									id: record._id,
									field,
									bucketId: record.bucketId,
									accountId: record.accountId
								},
								value
							});
						}
					}
				}
				return leaves;
			}
			case 'dpopNonceSecret':
			case 'errorOriginSalt': {
				// The singleton store is the undecorated one, and the one place a stored Binary is unwrapped.
				const value = await new SingletonSecretStore(kind).read();
				if (value instanceof Uint8Array)
					leaves.push({ target: { kind }, value });
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
				const was = text(observed);
				/*
				 * The array filter names the element by its id and its observed value, so the write lands on the
				 * provider that was read wherever it now sits in the array, and on nothing if it has changed.
				 */
				const result = await this.collection(STORE_AREAS.userBuckets).updateOne(
					{
						_id: target.bucketId,
						federation: {
							$elemMatch: { id: target.providerId, [field]: was }
						}
					},
					{ $set: { [`federation.$[p].${field}`]: text(next) } },
					{ arrayFilters: [{ 'p.id': target.providerId, [`p.${field}`]: was }] }
				);
				return result.matchedCount === 1;
			}
			case 'clientSecret': {
				const result = await this.collection('Client').updateOne(
					{ _id: target.clientId, 'payload.clientSecret': text(observed) },
					{ $set: { 'payload.clientSecret': text(next) } }
				);
				return result.matchedCount === 1;
			}
			case 'totpPending': {
				const result = await this.collection('TotpEnrollment').updateOne(
					{ _id: target.uid, 'payload.secret': text(observed) },
					{ $set: { 'payload.secret': text(next) } }
				);
				return result.matchedCount === 1;
			}
			case 'signInTokenInTransit': {
				const result = await this.collection('FederationState').updateOne(
					{ _id: target.id, 'payload.kept.tokens': text(observed) },
					{ $set: { 'payload.kept.tokens': text(next) } }
				);
				return result.matchedCount === 1;
			}
			case 'smtpPassword': {
				const result = await db
					.collection(STORE_AREAS.serviceConfig)
					.updateOne(
						{ _id: this.settingsId, 'settings.password': text(observed) },
						{ $set: { 'settings.password': text(next) } }
					);
				return result.matchedCount === 1;
			}
			case 'privateKey': {
				const path = jwkPath(target.member);
				const result = await this.collection(STORE_AREAS.bucketKeys).updateOne(
					{
						_id: target.keyId,
						bucketId: target.bucketId,
						kid: target.kid,
						[path]: text(observed)
					},
					{ $set: { [path]: text(next) } }
				);
				return result.matchedCount === 1;
			}
			case 'totpSecret': {
				const result = await this.collection(
					userAreaFor(target.bucketId)
				).updateOne(
					{ _id: target.userId, 'totp.secret': text(observed) },
					{ $set: { 'totp.secret': text(next) } }
				);
				return result.matchedCount === 1;
			}
			case 'connectedServiceSecret': {
				const was = text(observed);
				// As for a provider: the element is named by its id and its observed value.
				const result = await this.collection(STORE_AREAS.userBuckets).updateOne(
					{
						_id: target.bucketId,
						connectedServices: {
							$elemMatch: { id: target.serviceId, clientSecret: was }
						}
					},
					{ $set: { 'connectedServices.$[s].clientSecret': text(next) } },
					{
						arrayFilters: [{ 's.id': target.serviceId, 's.clientSecret': was }]
					}
				);
				return result.matchedCount === 1;
			}
			case 'connectedAccountToken': {
				const result = await this.collection(
					STORE_AREAS.connectedAccounts
				).updateOne(
					{ _id: target.id, [target.field]: text(observed) },
					{ $set: { [target.field]: text(next) } }
				);
				return result.matchedCount === 1;
			}
			case 'dpopNonceSecret':
			case 'errorOriginSalt': {
				const written = await new SingletonSecretStore(target.kind).replace(
					observed,
					Buffer.from(next)
				);
				return written instanceof Uint8Array && same(written, next);
			}
		}
	}
}
