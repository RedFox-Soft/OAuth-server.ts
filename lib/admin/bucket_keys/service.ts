import type { UserBucket } from '../../adapters/types.js';
import { isAddressable } from '../auth/bucketAddress.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { recordAdminAudit } from '../audit/record.js';
import { loadBucketForEdit } from '../buckets/access.js';
import { SUPPORTED_ALGS, type SupportedAlg } from '../jwks/schema.js';
import { invalidateBucketKeys } from '../../keys/issuer_keys.js';
import * as lifecycle from '../key_lifecycle.js';

export { KeyActionRefused, type KeyView } from '../key_lifecycle.js';

/*
 * Rotating an addressable bucket's own keys: generate, promote, retire — the lifecycle in
 * `../key_lifecycle.ts`, which the instance keys follow too.
 *
 * Held by the bucket's owning group as well as by super administrators, because the keys are the
 * tenant's issuer and a mistake here breaks that tenant alone. The instance key set, which every
 * root-served bucket signs with, stays a super administrator's under lib/admin/jwks/.
 */

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

function ownerOf(ctx: AdminContext, bucket: UserBucket): lifecycle.KeyOwner {
	return {
		id: bucket._id,
		audit: async (verb) => {
			await recordAdminAudit(ctx, `bucket.key.${verb}`, bucket._id, {
				ownerGroupId: bucket.ownerGroupId
			});
		},
		invalidate: () => invalidateBucketKeys(bucket._id)
	};
}

export async function listKeys(ctx: AdminContext, bucketId: string) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	return {
		...(await lifecycle.listKeys(ownerOf(ctx, bucket))),
		supportedAlgorithms: SUPPORTED_ALGS
	};
}

export async function generateKey(
	ctx: AdminContext,
	bucketId: string,
	alg: SupportedAlg
) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	return lifecycle.generateKey(ownerOf(ctx, bucket), alg);
}

export async function promoteKey(
	ctx: AdminContext,
	bucketId: string,
	kid: string
) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	return lifecycle.promoteKey(ownerOf(ctx, bucket), kid);
}

export async function retireKey(
	ctx: AdminContext,
	bucketId: string,
	kid: string,
	confirm: unknown
) {
	const bucket = await loadKeyedBucket(ctx, bucketId);
	return lifecycle.retireKey(ownerOf(ctx, bucket), kid, confirm);
}
