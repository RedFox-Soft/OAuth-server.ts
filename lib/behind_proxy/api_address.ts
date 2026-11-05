import type { RequestBucket } from '../configs/issuer.js';
import { issuerFor } from '../configs/issuer.js';
import { checkIdOf } from './check_id.js';

/*
 * Where a proxy checks an API's tokens, and where the API's protected-resource metadata is, beneath the project's
 * own address (specs/123 R1, R5). One function for the check's challenge and the admin view's Connect, so the
 * address an administrator pastes is the one the check names in every `401`.
 */
export function apiCheckUrlOf(
	bucket: RequestBucket,
	identifier: string
): string {
	return `${issuerFor(bucket)}/verify/api/${checkIdOf(identifier)}`;
}

export function apiMetadataUrlOf(
	bucket: RequestBucket,
	identifier: string
): string {
	return `${apiCheckUrlOf(bucket, identifier)}/metadata`;
}
