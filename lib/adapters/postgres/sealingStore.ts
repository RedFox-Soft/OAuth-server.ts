import crypto from 'crypto';

import { sql } from './db.js';
import { SingletonSecretStore } from './singletonSecretStore.js';
import { sqlState } from './sqlState.js';
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
import { member as memberOf } from '../../helpers/_/object.js';
import type { SealedLeaf, SealingStoreInstance } from '../types.js';

function derivedId(name: string): string {
	return crypto
		.createHash('sha256')
		.update(name)
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

/* A column of a projection the query itself fixes, read as text or not at all. */
function column(row: unknown, name: string): string | undefined {
	const value = memberOf(row, name);
	return typeof value === 'string' ? value : undefined;
}

/* The member is bound as a parameter, and still checked against the list rather than trusted from the type. */
function checkedMember(member: PrivateJwkMember): PrivateJwkMember {
	if (!(PRIVATE_JWK_MEMBERS as readonly string[]).includes(member)) {
		throw new Error(`'${member}' is not a private JWK member`);
	}
	return member;
}

/* A bucket whose user table was never created holds no enrolment, which is not a fault of the pass. */
const UNDEFINED_TABLE = '42P01';

/*
 * The encryption pass's own view of the datastore (specs/116 R8): every leaf read as it is stored, and every
 * write a compare-and-set of that one leaf, so an edit made between the pass's read and its write is never
 * undone. Reads the tables directly, never through the stores the sealing decorators wrap.
 *
 * Every path is a literal or a bound parameter, as in the user store: nothing a record holds is spliced into
 * SQL text. Each write answers whether a row met its WHERE, which, with the observed value in it, is whether
 * it wrote.
 */
export class SealingStore implements SealingStoreInstance {
	private settingsId = derivedId('smtpSettings');

	async scan(kind: SealKind): Promise<SealedLeaf[]> {
		const handle = sql();
		const leaves: SealedLeaf[] = [];
		switch (kind) {
			case 'providerSecret':
			case 'providerSigningKey': {
				const field = kind === 'providerSecret' ? 'clientSecret' : 'signingKey';
				const rows = await handle`
					SELECT b.id AS bucket_id,
						p.provider->>'id' AS provider_id,
						p.provider->>${field}::text AS value
					FROM ${handle(STORE_AREAS.userBuckets)} AS b
					CROSS JOIN LATERAL jsonb_array_elements(
						CASE WHEN jsonb_typeof(b.doc->'federation') = 'array'
							THEN b.doc->'federation' ELSE '[]'::jsonb END
					) AS p(provider)
					WHERE jsonb_typeof(p.provider->${field}::text) = 'string'
						AND jsonb_typeof(p.provider->'id') = 'string'
				`;
				for (const row of rows) {
					const bucketId = column(row, 'bucket_id');
					const providerId = column(row, 'provider_id');
					const value = column(row, 'value');
					if (bucketId && providerId !== undefined && value) {
						leaves.push({ target: { kind, bucketId, providerId }, value });
					}
				}
				return leaves;
			}
			case 'clientSecret': {
				const rows = await handle`
					SELECT id, payload->>'clientSecret' AS value FROM ${handle('Client')}
					WHERE jsonb_typeof(payload->'clientSecret') = 'string'
				`;
				for (const row of rows) {
					const clientId = column(row, 'id');
					const value = column(row, 'value');
					if (clientId !== undefined && value) {
						leaves.push({ target: { kind, clientId }, value });
					}
				}
				return leaves;
			}
			case 'totpPending': {
				const rows = await handle`
					SELECT id,
						payload->>'secret' AS value,
						payload->>'bucketId' AS bucket_id,
						payload->>'accountId' AS account_id
					FROM ${handle('TotpEnrollment')}
					WHERE jsonb_typeof(payload->'secret') = 'string'
						AND jsonb_typeof(payload->'bucketId') = 'string'
						AND jsonb_typeof(payload->'accountId') = 'string'
				`;
				for (const row of rows) {
					const uid = column(row, 'id');
					const value = column(row, 'value');
					const bucketId = column(row, 'bucket_id');
					const accountId = column(row, 'account_id');
					if (
						uid !== undefined &&
						value !== undefined &&
						bucketId !== undefined &&
						accountId !== undefined
					) {
						leaves.push({
							target: { kind, uid, bucketId, accountId },
							value
						});
					}
				}
				return leaves;
			}
			case 'smtpPassword': {
				const rows = await handle`
					SELECT doc->>'password' AS value FROM ${handle(STORE_AREAS.serviceConfig)}
					WHERE id = ${this.settingsId} AND jsonb_typeof(doc->'password') = 'string'
				`;
				const value = column(rows[0], 'value');
				if (value) leaves.push({ target: { kind }, value });
				return leaves;
			}
			case 'privateKey': {
				const rows = await handle`
					SELECT id, doc->>'bucketId' AS bucket_id, doc->>'kid' AS kid,
						doc->>'state' AS state, doc->'jwk' AS jwk
					FROM ${handle(STORE_AREAS.bucketKeys)}
					WHERE jsonb_typeof(doc->'jwk') = 'object'
				`;
				for (const row of rows) {
					const keyId = column(row, 'id');
					const bucketId = column(row, 'bucket_id');
					const kid = column(row, 'kid');
					const jwk = memberOf(row, 'jwk');
					if (
						keyId === undefined ||
						bucketId === undefined ||
						kid === undefined
					) {
						continue;
					}
					for (const member of PRIVATE_JWK_MEMBERS) {
						const value = memberOf(jwk, member);
						if (typeof value === 'string') {
							leaves.push({
								target: { kind, keyId, bucketId, kid, member },
								value,
								revoked: column(row, 'state') === 'revoked'
							});
						}
					}
				}
				return leaves;
			}
			case 'totpSecret': {
				const buckets = await handle`
					SELECT id FROM ${handle(STORE_AREAS.userBuckets)}
				`;
				for (const bucket of buckets) {
					const bucketId = column(bucket, 'id');
					if (bucketId === undefined) continue;
					let rows: unknown[];
					try {
						// The enrolment test the user store's `totpEnrolled` filter uses: an enrolment is an object.
						rows = await handle`
							SELECT id, doc->'totp'->>'secret' AS value
							FROM ${handle(userAreaFor(bucketId))}
							WHERE jsonb_typeof(doc->'totp') = 'object'
								AND jsonb_typeof(doc->'totp'->'secret') = 'string'
						`;
					} catch (error) {
						if (sqlState(error) === UNDEFINED_TABLE) continue;
						throw error;
					}
					for (const row of rows) {
						const userId = column(row, 'id');
						const value = column(row, 'value');
						if (userId !== undefined && value !== undefined) {
							leaves.push({ target: { kind, bucketId, userId }, value });
						}
					}
				}
				return leaves;
			}
			case 'connectedServiceSecret': {
				const rows = await handle`
					SELECT b.id AS bucket_id,
						s.service->>'id' AS service_id,
						s.service->>'clientSecret' AS value
					FROM ${handle(STORE_AREAS.userBuckets)} AS b
					CROSS JOIN LATERAL jsonb_array_elements(
						CASE WHEN jsonb_typeof(b.doc->'connectedServices') = 'array'
							THEN b.doc->'connectedServices' ELSE '[]'::jsonb END
					) AS s(service)
					WHERE jsonb_typeof(s.service->'clientSecret') = 'string'
						AND jsonb_typeof(s.service->'id') = 'string'
				`;
				for (const row of rows) {
					const bucketId = column(row, 'bucket_id');
					const serviceId = column(row, 'service_id');
					const value = column(row, 'value');
					if (bucketId && serviceId !== undefined && value) {
						leaves.push({ target: { kind, bucketId, serviceId }, value });
					}
				}
				return leaves;
			}
			case 'connectedAccountToken': {
				for (const field of CONNECTED_ACCOUNT_TOKEN_FIELDS) {
					const rows = await handle`
						SELECT id, doc->>${field}::text AS value,
							doc->>'bucketId' AS bucket_id, doc->>'accountId' AS account_id
						FROM ${handle(STORE_AREAS.connectedAccounts)}
						WHERE jsonb_typeof(doc->${field}::text) = 'string'
					`;
					for (const row of rows) {
						const id = column(row, 'id');
						const value = column(row, 'value');
						const bucketId = column(row, 'bucket_id');
						const accountId = column(row, 'account_id');
						if (
							id !== undefined &&
							value &&
							bucketId !== undefined &&
							accountId !== undefined
						) {
							leaves.push({
								target: { kind, id, field, bucketId, accountId },
								value
							});
						}
					}
				}
				return leaves;
			}
			case 'dpopNonceSecret':
			case 'errorOriginSalt': {
				// The singleton store is the undecorated one, and the one place a bytea is normalised to bytes.
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
		const handle = sql();
		switch (target.kind) {
			case 'providerSecret':
			case 'providerSigningKey': {
				const field =
					target.kind === 'providerSecret' ? 'clientSecret' : 'signingKey';
				const was = text(observed);
				/*
				 * The provider's position is found in the statement, and the UPDATE's own WHERE checks that
				 * position again on the row it locks: a concurrent edit that reordered or changed the array
				 * between the two is re-read by PostgreSQL there, and the write then matches nothing.
				 */
				const rows = await handle`
					WITH found AS (
						SELECT (p.position - 1)::int AS idx
						FROM ${handle(STORE_AREAS.userBuckets)} AS b
						CROSS JOIN LATERAL jsonb_array_elements(
							CASE WHEN jsonb_typeof(b.doc->'federation') = 'array'
								THEN b.doc->'federation' ELSE '[]'::jsonb END
						) WITH ORDINALITY AS p(provider, position)
						WHERE b.id = ${target.bucketId}
							AND p.provider->>'id' = ${target.providerId}
							AND p.provider->>${field}::text = ${was}
						LIMIT 1
					)
					UPDATE ${handle(STORE_AREAS.userBuckets)} AS u
					SET doc = jsonb_set(
						u.doc,
						ARRAY['federation', found.idx::text, ${field}::text],
						to_jsonb(${text(next)}::text)
					)
					FROM found
					WHERE u.id = ${target.bucketId}
						AND u.doc->'federation'->found.idx->>'id' = ${target.providerId}
						AND u.doc->'federation'->found.idx->>${field}::text = ${was}
					RETURNING u.id
				`;
				return rows.length === 1;
			}
			case 'clientSecret': {
				const rows = await handle`
					UPDATE ${handle('Client')}
					SET payload = jsonb_set(payload, '{clientSecret}', to_jsonb(${text(next)}::text))
					WHERE id = ${target.clientId}
						AND payload->>'clientSecret' = ${text(observed)}
					RETURNING id
				`;
				return rows.length === 1;
			}
			case 'totpPending': {
				const rows = await handle`
					UPDATE ${handle('TotpEnrollment')}
					SET payload = jsonb_set(payload, '{secret}', to_jsonb(${text(next)}::text))
					WHERE id = ${target.uid} AND payload->>'secret' = ${text(observed)}
					RETURNING id
				`;
				return rows.length === 1;
			}
			case 'smtpPassword': {
				const rows = await handle`
					UPDATE ${handle(STORE_AREAS.serviceConfig)}
					SET doc = jsonb_set(doc, '{password}', to_jsonb(${text(next)}::text))
					WHERE id = ${this.settingsId} AND doc->>'password' = ${text(observed)}
					RETURNING id
				`;
				return rows.length === 1;
			}
			case 'privateKey': {
				const member = checkedMember(target.member);
				const rows = await handle`
					UPDATE ${handle(STORE_AREAS.bucketKeys)}
					SET doc = jsonb_set(
						doc,
						ARRAY['jwk', ${member}::text],
						to_jsonb(${text(next)}::text)
					)
					WHERE id = ${target.keyId}
						AND doc->>'bucketId' = ${target.bucketId}
						AND doc->>'kid' = ${target.kid}
						AND doc->'jwk'->>${member}::text = ${text(observed)}
					RETURNING id
				`;
				return rows.length === 1;
			}
			case 'totpSecret': {
				const rows = await handle`
					UPDATE ${handle(userAreaFor(target.bucketId))}
					SET doc = jsonb_set(doc, '{totp,secret}', to_jsonb(${text(next)}::text))
					WHERE id = ${target.userId}
						AND doc->'totp'->>'secret' = ${text(observed)}
					RETURNING id
				`;
				return rows.length === 1;
			}
			case 'connectedServiceSecret': {
				const was = text(observed);
				// As for a provider: the position is found, then checked again on the locked row.
				const rows = await handle`
					WITH found AS (
						SELECT (s.position - 1)::int AS idx
						FROM ${handle(STORE_AREAS.userBuckets)} AS b
						CROSS JOIN LATERAL jsonb_array_elements(
							CASE WHEN jsonb_typeof(b.doc->'connectedServices') = 'array'
								THEN b.doc->'connectedServices' ELSE '[]'::jsonb END
						) WITH ORDINALITY AS s(service, position)
						WHERE b.id = ${target.bucketId}
							AND s.service->>'id' = ${target.serviceId}
							AND s.service->>'clientSecret' = ${was}
						LIMIT 1
					)
					UPDATE ${handle(STORE_AREAS.userBuckets)} AS u
					SET doc = jsonb_set(
						u.doc,
						ARRAY['connectedServices', found.idx::text, 'clientSecret'],
						to_jsonb(${text(next)}::text)
					)
					FROM found
					WHERE u.id = ${target.bucketId}
						AND u.doc->'connectedServices'->found.idx->>'id' = ${target.serviceId}
						AND u.doc->'connectedServices'->found.idx->>'clientSecret' = ${was}
					RETURNING u.id
				`;
				return rows.length === 1;
			}
			case 'connectedAccountToken': {
				const rows = await handle`
					UPDATE ${handle(STORE_AREAS.connectedAccounts)}
					SET doc = jsonb_set(doc, ARRAY[${target.field}::text], to_jsonb(${text(next)}::text))
					WHERE id = ${target.id}
						AND doc->>${target.field}::text = ${text(observed)}
					RETURNING id
				`;
				return rows.length === 1;
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
