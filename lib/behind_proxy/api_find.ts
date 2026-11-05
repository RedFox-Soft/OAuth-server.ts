import { getProtectedResourceStore } from '../adapters/index.js';
import type { ProtectedResource } from '../adapters/types.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import type { RequestBucket } from '../configs/issuer.js';
import { hostOfRequest } from '../consts/request_host.js';
import { UnknownBucket } from '../helpers/errors.js';
import { checkIdOf } from './check_id.js';

/*
 * The API a check or a metadata request names (specs/123 R1): the project from the request's own address, exactly
 * as every request to it is addressed, and then one of that project's APIs by the digest of its identifier — only
 * one the proxy checks. Nothing a caller forwards takes part, so no header can select another project's API.
 */

export interface AddressedApi {
	bucket: RequestBucket;
	api: ProtectedResource;
	checkId: string;
}

export function checkIdParam(params: unknown): string | undefined {
	const checkId = (params as { checkId?: unknown } | undefined)?.checkId;
	return typeof checkId === 'string' && checkId !== '' ? checkId : undefined;
}

async function addressedBucket(
	params: unknown,
	request: Request
): Promise<RequestBucket | null> {
	try {
		/* Without `includeScheduled`: a project scheduled for deletion is no project here. */
		return await requestBucketFor(
			(params as { bucket?: string } | undefined)?.bucket,
			hostOfRequest(request)
		);
	} catch (err) {
		if (err instanceof UnknownBucket) return null;
		throw err;
	}
}

export async function addressedApi(
	params: unknown,
	request: Request
): Promise<AddressedApi | null> {
	const checkId = checkIdParam(params);
	if (!checkId) return null;
	const bucket = await addressedBucket(params, request);
	/* The administrators' project issues no token for any API (wiki administrators-applications). */
	if (!bucket || bucket._id === ADMIN_BUCKET_ID) return null;
	const api = (await getProtectedResourceStore().listByBucket(bucket._id)).find(
		(candidate) =>
			candidate.checkedBy === 'proxy' &&
			checkIdOf(candidate.identifier) === checkId
	);
	return api ? { bucket, api, checkId } : null;
}
