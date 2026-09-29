import { getBucketKeysStore, getProjectStore } from '../../adapters/index.js';
import type { BucketKey, UserBucket } from '../../adapters/types.js';
import { isAddressable } from '../auth/bucketAddress.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { recordAdminAudit } from '../audit/record.js';
import { loadBucketForEdit } from '../buckets/access.js';
import { generateJWKS } from '../../helpers/jwks.js';
import { SUPPORTED_ALGS, type SupportedAlg } from '../jwks/schema.js';
import {
	invalidateBucketKeys,
	KEY_PUBLICATION_SECONDS,
	retiredKeyRemovableAt
} from '../../keys/issuer_keys.js';
import { Client } from '../../models/client.js';

/*
 * Rotating an addressable bucket's own keys: generate, promote, retire.
 *
 * Held by the bucket's owning group as well as by super administrators, because the keys are the
 * tenant's issuer and a mistake here breaks that tenant alone. The instance key set, which every
 * root-served bucket signs with, stays a super administrator's under lib/admin/jwks/.
 *
 * The three steps exist because every instance caches a bucket's set for a short while. A key is
 * published before it may sign, for longer than that cache, so no instance signs with a key another
 * does not yet serve; the key it replaces keeps being published; and a retired key stays published
 * until every token it could have signed has expired. That is what keeps a rotation from invalidating
 * a token still in circulation (Constitution VI).
 */

/* A refusal carrying what the operator needs to act on it — when to try again, what is in the way. */
export class KeyActionRefused extends AdminError {
	constructor(
		status: number,
		message: string,
		readonly detail: Record<string, unknown>
	) {
		super(status, message);
	}
}

export interface KeyView {
	kid: string;
	alg: string;
	use: 'sig' | 'enc';
	state: BucketKey['state'];
	createdAt: Date;
	stateChangedAt: Date;
	promotableAt?: Date;
	removableAt?: Date;
}

/* Never the key material: the private members stay on the server, and the public ones are at /jwks. */
function viewOf(key: BucketKey): KeyView {
	return {
		kid: key.kid,
		alg: key.alg,
		use: key.use,
		state: key.state,
		createdAt: key.createdAt,
		stateChangedAt: key.stateChangedAt,
		...(key.state === 'published' ? { promotableAt: promotableAt(key) } : {}),
		...(key.state === 'retired'
			? { removableAt: retiredKeyRemovableAt(key) }
			: {})
	};
}

function promotableAt(key: BucketKey): Date {
	return new Date(
		key.stateChangedAt.getTime() + KEY_PUBLICATION_SECONDS * 1000
	);
}

/*
 * The bucket, if the caller may manage its keys and it has keys to manage. A bucket served at the root
 * signs with the instance keys, so its keys are not here — refused with a conflict that says where they
 * are rather than a not-found that would suggest they do not exist.
 */
export async function loadKeyedBucket(
	ctx: AdminContext,
	bucketId: string
): Promise<UserBucket> {
	const bucket = await loadBucketForEdit(ctx, bucketId);
	if (!isAddressable(bucket)) {
		throw new AdminError(
			409,
			'This bucket signs with the instance keys; manage them under Keys.'
		);
	}
	return bucket;
}

async function keyOf(bucketId: string, kid: string): Promise<BucketKey> {
	const key = await getBucketKeysStore().find(bucketId, kid);
	if (!key) throw new AdminError(404, 'no such key in this bucket');
	return key;
}

/* Visible keys: a retired key past its window is gone from /jwks and from here. */
export async function listKeys(ctx: AdminContext, bucketId: string) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	const now = Date.now();
	const keys = (await getBucketKeysStore().listByBucket(bucket._id))
		.filter(
			(key) =>
				key.state !== 'retired' || now < retiredKeyRemovableAt(key).getTime()
		)
		.map(viewOf);
	return {
		keys,
		supportedAlgorithms: SUPPORTED_ALGS,
		publicationSeconds: KEY_PUBLICATION_SECONDS
	};
}

export async function generateKey(
	ctx: AdminContext,
	bucketId: string,
	alg: SupportedAlg
) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	const {
		keys: [jwk]
	} = await generateJWKS(alg);

	await recordAdminAudit(ctx, 'bucket.key.generate', bucket._id, {
		ownerGroupId: bucket.ownerGroupId
	});
	const now = new Date(Date.now());
	const key: BucketKey = {
		_id: `${bucket._id} ${jwk.kid}`,
		bucketId: bucket._id,
		kid: jwk.kid,
		jwk,
		alg,
		use: 'sig',
		state: 'published',
		createdAt: now,
		stateChangedAt: now
	};
	await getBucketKeysStore().createIfAbsent(key);
	invalidateBucketKeys(bucket._id);
	return viewOf(key);
}

/*
 * The algorithms the bucket's clients ask to be signed for: every client of every project backed by
 * this bucket, read through the client model so an unset preference reads as the default it resolves
 * to.
 */
async function requiredAlgorithms(bucketId: string): Promise<Set<string>> {
	const required = new Set<string>();
	const projects = (await getProjectStore().list()).filter(
		(project) => project.bucketId === bucketId
	);
	for (const project of projects) {
		for (const clientId of project.clientIds ?? []) {
			const client = await Client.tryFind(clientId);
			if (!client) continue;
			for (const alg of [
				client.idTokenSignedResponseAlg,
				client.userinfoSignedResponseAlg,
				client.introspectionSignedResponseAlg,
				client.authorizationSignedResponseAlg
			]) {
				if (typeof alg === 'string' && !alg.startsWith('HS')) required.add(alg);
			}
		}
	}
	return required;
}

/*
 * One signing key per key type, so which key signs is always answerable: promoting a key returns the
 * one of its type that was signing to `published`, where it keeps verifying what it signed.
 */
export async function promoteKey(
	ctx: AdminContext,
	bucketId: string,
	kid: string
) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	const key = await keyOf(bucket._id, kid);
	if (key.state !== 'published' || key.use !== 'sig') {
		throw new AdminError(409, 'only a published signing key can be promoted');
	}
	if (Date.now() < promotableAt(key).getTime()) {
		throw new KeyActionRefused(
			409,
			'the key has not been published long enough for every instance to serve it',
			{ reason: 'too_soon', promotableAt: promotableAt(key) }
		);
	}

	const all = await getBucketKeysStore().listByBucket(bucket._id);
	const displaced = all.find(
		(other) =>
			other.state === 'signing' &&
			other.use === 'sig' &&
			other.jwk.kty === key.jwk.kty &&
			other.kid !== key.kid
	);
	if (displaced) {
		const after = new Set(
			all
				.filter(
					(other) => other.state === 'signing' && other.kid !== displaced.kid
				)
				.map((other) => other.alg)
		);
		after.add(key.alg);
		const lost = [...(await requiredAlgorithms(bucket._id))].filter(
			(alg) => !after.has(alg)
		);
		if (lost.length > 0) {
			throw new KeyActionRefused(
				409,
				'the bucket would have no key to sign with in an algorithm its clients require',
				{ reason: 'required_alg', algorithms: lost.sort() }
			);
		}
	}

	await recordAdminAudit(ctx, 'bucket.key.promote', bucket._id, {
		ownerGroupId: bucket.ownerGroupId
	});
	const now = new Date(Date.now());
	const store = getBucketKeysStore();
	if (displaced) {
		await store.setState(bucket._id, displaced.kid, 'published', now);
	}
	await store.setState(bucket._id, key.kid, 'signing', now);
	invalidateBucketKeys(bucket._id);
	return {
		kid: key.kid,
		state: 'signing' as const,
		...(displaced ? { demoted: displaced.kid } : {})
	};
}

export async function retireKey(
	ctx: AdminContext,
	bucketId: string,
	kid: string
) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	const key = await keyOf(bucket._id, kid);
	if (key.state === 'signing') {
		throw new KeyActionRefused(
			409,
			'the bucket signs with this key; promote another first',
			{ reason: 'signing' }
		);
	}
	if (key.state === 'retired') {
		throw new AdminError(409, 'the key is already retired');
	}

	await recordAdminAudit(ctx, 'bucket.key.retire', bucket._id, {
		ownerGroupId: bucket.ownerGroupId
	});
	const retired = await getBucketKeysStore().setState(
		bucket._id,
		key.kid,
		'retired',
		new Date(Date.now())
	);
	invalidateBucketKeys(bucket._id);
	if (!retired) throw new AdminError(404, 'no such key in this bucket');
	return {
		kid: key.kid,
		state: 'retired' as const,
		removableAt: retiredKeyRemovableAt(retired)
	};
}
