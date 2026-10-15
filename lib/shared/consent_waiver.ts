import { getBucketStore } from '../adapters/index.js';
import { clientBelongsToBucket } from '../models/client/provenance.js';
import { resolveBucketForRequest } from '../admin/auth/resolveBucket.js';
import type { OIDCContext } from '../helpers/oidc_context.js';

/*
 * Whether this request's client may skip the consent screen for the user signing in.
 *
 * `consent.require: false` is a tenant's decision about its own users, so it is honoured only where they
 * are its own: in the bucket the client belongs to (specs/099). A client of one bucket can reach another's
 * sign-in through a declared resource, and honouring the flag there would hand its tenant the claims of
 * that bucket's users with a session, with `prompt=none` and no page shown.
 *
 * A client that belongs to no bucket keeps the flag as stored. Nothing a caller controls can set it on one:
 * dynamic registration and client documents cannot carry it (lib/models/client/wire.ts), so such a client
 * was provisioned by the operator.
 *
 * Decided per request rather than at write time, because the bucket signed into is the request's.
 * Memoised per context: the consent policy and the grant loader both ask.
 */
const decided = new WeakMap<object, Promise<boolean>>();

export function consentWaived(oidc: OIDCContext): Promise<boolean> {
	let answer = decided.get(oidc);
	if (!answer) {
		answer = decide(oidc);
		decided.set(oidc, answer);
	}
	return answer;
}

async function decide(oidc: OIDCContext): Promise<boolean> {
	const { client } = oidc;
	if (client['consent.require']) return false;

	const bucket = await getBucketStore().find(
		await resolveBucketForRequest(
			client.clientId,
			oidc.params.resource,
			oidc.bucket
		)
	);
	return (await clientBelongsToBucket(client.clientId, bucket)) ?? true;
}
