import { getBucketStore } from '../adapters/index.js';
import { federationEnabled } from '../federation/providers.js';
import { resolveBucketForRequest } from '../admin/auth/resolveBucket.js';
import type { RequestBucket } from '../configs/issuer.js';
import { signInOptionsOf, type LoginOptions } from './signInOptions.js';
import { signUpsPaused } from '../plans/signups.js';

export type { LoginOptions } from './signInOptions.js';

/*
 * The login page's options for a stored bucket. The rule is `signInOptionsOf` (./signInOptions.ts), shared with
 * the console's preview of the page (specs/091); this side reads the bucket and supplies the live federation
 * switch.
 */
export async function loginOptionsForBucket(
	bucketId: string
): Promise<LoginOptions> {
	const bucket = await getBucketStore().find(bucketId);
	const options = signInOptionsOf(bucketId, bucket, federationEnabled());
	/* A project at its plan's active-user cap offers no sign-up (specs/102); the doors refuse it too. */
	return bucket && options.registrationOpen && (await signUpsPaused(bucket))
		? { ...options, registrationOpen: false }
		: options;
}

/* The same answer, reached from the client that started the interaction — which is the only trustworthy
 * route to a bucket: a bucket id taken from a request would let anyone aim the page at any tenant.
 *
 * `resource` is required, not optional, because leaving it out resolves a different bucket than the
 * sign-in does for a client that belongs to no bucket: the page then shows, and the enrolment step then enforces,
 * the default bucket's options instead of the bucket the request named. */
export async function loginOptionsForClient(
	clientId: string | undefined,
	resource: string | readonly string[] | undefined,
	addressed: RequestBucket
): Promise<LoginOptions> {
	return loginOptionsForBucket(
		await resolveBucketForRequest(clientId, resource, addressed)
	);
}
