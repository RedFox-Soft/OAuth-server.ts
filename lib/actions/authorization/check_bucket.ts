import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import type { RequestBucket } from 'lib/configs/issuer.js';
import { getBucketStore } from '../../adapters/index.js';
import {
	pinnedBucketOf,
	resolveBucketForRequest,
	storedBucketOf
} from '../../admin/auth/resolveBucket.js';
import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	DEFAULT_BUCKET_ID
} from '../../admin/consts.js';
import { isAddressable } from '../../admin/auth/bucketAddress.js';
import { bucketIdOfAccountPageClient } from '../../account_page/client.js';
import { InvalidClientAuth, UnauthorizedClient } from '../../helpers/errors.js';

/*
 * A client of an addressable bucket may only be used at that bucket's address.
 *
 * This is a refusal, not a resolution, and the distinction is the whole point. The bucket-resolution
 * rules were written so that a request parameter can select among an operator's choices and never
 * create one — the reasoning is recorded against an earlier rejected design in `resolveBucket.ts`.
 * An address a client could be used at regardless would undo that from the other end: a client would
 * reach a population its operator never put it in, and the tokens it got would carry that
 * population's issuer.
 *
 * The same refusal covers a request naming a declared resource of another bucket, because
 * `resolveBucketForRequest` answers both questions with one rule — which is why this compares its
 * answer rather than re-deriving anything.
 *
 * **Addressable is the qualifier that makes this correct rather than merely strict.** A bucket with
 * no address has no endpoints of its own, no metadata and no issuer identifier, so its clients have
 * nowhere to go but the bare endpoints — refusing them there would strand every one of them, which is
 * what a first version of this check did to a hundred and seventy-seven existing flows. The two
 * reserved buckets are unaddressable for a different reason, given at `isAddressable`. Either way such
 * a bucket keeps exactly the behaviour it had before buckets became tenants, and the moment an
 * operator gives one an address its clients move there and this check begins to apply to them.
 *
 * Runs after the resource is final, because rule 3 derives a bucket from a declared resource and a
 * resource arriving inside a pushed request or a request object is not settled until then.
 *
 * The bucket it resolved is handed back rather than discarded, and that is not scope creep: the caller
 * needs the same answer to name the session cookie, and resolving it twice is two chances to disagree
 * about one population — the failure the login POST already records against itself one file over.
 * Returning it keeps this a refusal that happens to say what it compared against.
 */
export default async function checkBucket(
	oidc: OIDCContext<PipelineParams>
): Promise<string> {
	const belongsTo = await resolveBucketForRequest(
		oidc.client.clientId,
		oidc.params.resource,
		oidc.bucket
	);

	if (belongsTo === oidc.bucket._id) return belongsTo;

	/*
	 * The console's own clients, at the root only (specs/103). The administrators' bucket has no address, so the
	 * look below would let them through at every address — a tenant's path, subdomain or hostname included — and
	 * the console sign-in would then run on a tenant's origin.
	 */
	if (belongsTo === ADMIN_BUCKET_ID) {
		if (oidc.bucket._id === DEFAULT_BUCKET_ID) return belongsTo;
		throw notAuthorizedHere();
	}

	/*
	 * The default bucket is addressable by definition: its address is the root, which exists whether or
	 * not anybody has provisioned its record. A client of it at a named address is therefore always at
	 * the wrong one, and is refused without a lookup — the lookup below would otherwise let it through
	 * on an unprovisioned instance, which is exactly where a hole like this goes unnoticed.
	 */
	if (belongsTo !== DEFAULT_BUCKET_ID) {
		/*
		 * Any other bucket has to be looked at rather than assumed. A bucket with no record at all is the
		 * same case as one with no slug, and for the stronger reason: there is nothing to address.
		 * `resolveBucketForRequest` answers by rule — the reserved client maps to the reserved bucket
		 * whether or not that record has been provisioned — so an answer is not evidence of a record.
		 */
		const bucket = await getBucketStore().find(belongsTo);
		if (!bucket || !isAddressable(bucket)) return belongsTo;
	}

	/*
	 * `unauthorized_client` rather than a not-found: the address exists and the client exists, and what
	 * is wrong is that this client is not authorized at this address. Saying so discloses nothing a
	 * caller could not already determine — the client is theirs and the address is published.
	 */
	throw notAuthorizedHere();
}

/*
 * The same refusal for the endpoints that authenticate a client — token, introspection, revocation, PAR,
 * device authorization and backchannel authentication, all through `tokenAuth`. RFC 6749 §2.2 makes a client
 * identifier unique to the server that issued it, and every project with an address is its own server, so a
 * client of one is unknown to another; MCP's SEP-2352 tells clients the same from their side.
 *
 * Only the project a client is pinned to counts, never a requested resource. Rule 3 lets a client of no
 * project reach a project through a resource declared there, and that is safe at `/auth` because the code it
 * gets records the project and is redeemable nowhere else. Here a resource parameter would let such a client
 * choose a project for a grant with no earlier step at all; client credentials answer that one themselves.
 *
 * Answered as an unknown client, and before any credential is checked: a refusal that differed from one, or
 * that depended on the secret being right, would tell a caller the client exists at another issuer.
 */
export async function assertClientServedHere(
	clientId: string,
	addressed: RequestBucket
): Promise<void> {
	if (clientId === ADMIN_CLIENT_ID) {
		if (addressed._id === DEFAULT_BUCKET_ID) return;
		throw unknownHere();
	}

	const pinned =
		bucketIdOfAccountPageClient(clientId) ??
		pinnedBucketOf(await storedBucketOf(clientId));
	if (!pinned || pinned === addressed._id) return;

	const bucket = await getBucketStore().find(pinned);
	if (!bucket || !isAddressable(bucket)) return;

	throw unknownHere();
}

function unknownHere(): InstanceType<typeof InvalidClientAuth> {
	return new InvalidClientAuth('client not found');
}

function notAuthorizedHere(): InstanceType<typeof UnauthorizedClient> {
	return new UnauthorizedClient(
		'client is not authorized at this address',
		'the client belongs to a different user bucket than the one addressed'
	);
}
