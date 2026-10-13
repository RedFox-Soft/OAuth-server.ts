import { getBucketStore } from '../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import { ACCOUNT_PAGE_CLIENT_PREFIX } from '../consts/account_page.js';
import { routeNames } from '../consts/param_list.js';
import { ISSUER } from '../configs/env.js';
import { addressOf, issuerFor, type RequestBucket } from '../configs/issuer.js';
import { ACCOUNT_PAGE_TEXTS } from './texts.js';

/*
 * The client each end-user bucket's connected-applications page signs people in through (specs/095 R3).
 *
 * Synthesized from the bucket on every resolution and stored nowhere, as a provisioning connection's client
 * is: nobody can edit or delete it, it needs no seed that would drift as buckets come and go, and there is no
 * record to hide from the console's client lists.
 *
 * It can do one thing — bring the person back to the page signed in. `response_type=none` returns nothing to
 * redeem, and with no grant type the token endpoint has nothing to give it, so the page never holds a token:
 * it reads the bucket's own sign-in session, which is what an authorization server knows about a person
 * anyway. The administrators' bucket has none: its people are signed in by the console, and a second
 * consent-free client for administrator accounts is exactly what nobody should be able to point at.
 */

export function accountPageClientId(bucketId: string): string {
	return `${ACCOUNT_PAGE_CLIENT_PREFIX}${bucketId}`;
}

export function isAccountPageClient(clientId: string | undefined): boolean {
	return (
		typeof clientId === 'string' &&
		clientId.startsWith(ACCOUNT_PAGE_CLIENT_PREFIX)
	);
}

export function bucketIdOfAccountPageClient(
	clientId: string
): string | undefined {
	return isAccountPageClient(clientId)
		? clientId.slice(ACCOUNT_PAGE_CLIENT_PREFIX.length) || undefined
		: undefined;
}

/*
 * Where a bucket's page is served. Its issuer, except for a bucket with no address of its own: such a bucket
 * signs its people in at the bare endpoints and shares the default bucket's session cookie, so its page is
 * the bare one too — `issuerFor` names it by record id, an address nothing routes.
 */
export function accountPageBase(bucket: RequestBucket): string {
	return addressOf(bucket).kind === 'unaddressed' ? ISSUER : issuerFor(bucket);
}

export function accountPageUrl(bucket: RequestBucket): string {
	return `${accountPageBase(bucket)}${routeNames.account_apps}`;
}

/* The metadata for a client id naming a bucket's page, or undefined when it names no bucket that may have one. */
export async function accountPageClientRecord(
	clientId: string
): Promise<Record<string, unknown> | undefined> {
	const bucketId = bucketIdOfAccountPageClient(clientId);
	if (!bucketId || bucketId === ADMIN_BUCKET_ID) return undefined;
	const bucket = await getBucketStore().find(bucketId);
	if (!bucket || isScheduledForDeletion(bucket)) return undefined;
	return {
		clientId,
		applicationType: 'web',
		responseTypes: ['none'],
		grantTypes: [],
		redirectUris: [
			`${accountPageBase(bucket)}${routeNames.account_apps_callback}`
		],
		token_endpoint_auth_method: 'none',
		client_name: ACCOUNT_PAGE_TEXTS.clientName,
		'consent.require': false,
		accountPageBucketId: bucket._id
	};
}
