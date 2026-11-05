import { getBehindProxyAppStore, getBucketStore } from '../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import {
	BEHIND_PROXY_CALLBACK_PATH,
	BEHIND_PROXY_CLIENT_PREFIX
} from '../consts/behind_proxy.js';

/*
 * The client each end-user bucket signs people in to its apps behind a proxy through (specs/122 R5).
 *
 * Synthesized from the bucket and its apps on every resolution and stored nowhere, as the account page's client
 * is (lib/account_page/client.ts): nobody can edit or delete it, and its redirect URIs follow the apps as they are
 * added, moved and removed without a second record to keep in step.
 *
 * It asks for a code, and only the check endpoint redeems it, in-process; the public token endpoint refuses a code
 * issued to it. The administrators' bucket has none: its people are signed in by the console, and a consent-free
 * client for administrator accounts is exactly what nobody should be able to point at.
 */

export function behindProxyClientId(bucketId: string): string {
	return `${BEHIND_PROXY_CLIENT_PREFIX}${bucketId}`;
}

export function isBehindProxyClient(clientId: string | undefined): boolean {
	return (
		typeof clientId === 'string' &&
		clientId.startsWith(BEHIND_PROXY_CLIENT_PREFIX)
	);
}

export function bucketIdOfBehindProxyClient(
	clientId: string
): string | undefined {
	return isBehindProxyClient(clientId)
		? clientId.slice(BEHIND_PROXY_CLIENT_PREFIX.length) || undefined
		: undefined;
}

/* Where the sign-in for an app at this address returns: a path on the app's own host, relayed to the check. */
export function behindProxyCallbackUri(address: string): string {
	return `${address}${BEHIND_PROXY_CALLBACK_PATH}`;
}

/* The metadata for a client id naming a bucket's proxy client, or undefined when it names no bucket that may have one. */
export async function behindProxyClientRecord(
	clientId: string
): Promise<Record<string, unknown> | undefined> {
	const bucketId = bucketIdOfBehindProxyClient(clientId);
	if (!bucketId || bucketId === ADMIN_BUCKET_ID) return undefined;
	const bucket = await getBucketStore().find(bucketId);
	if (!bucket || isScheduledForDeletion(bucket)) return undefined;
	const apps = await getBehindProxyAppStore().listByBucket(bucket._id);
	/* A code client with nowhere to return to is not a client; one app declared is what brings it into being. */
	if (apps.length === 0) return undefined;
	return {
		clientId,
		applicationType: 'web',
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: apps.map((app) => behindProxyCallbackUri(app.address)),
		token_endpoint_auth_method: 'none',
		/* `name` is the operator's label and never shown to end users; without a display name the page names none. */
		...(bucket.displayName ? { client_name: bucket.displayName } : {}),
		'consent.require': false,
		behindProxyBucketId: bucket._id
	};
}
