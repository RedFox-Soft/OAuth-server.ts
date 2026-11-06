import { expect } from 'bun:test';

import { whenUsageRecorded } from 'lib/behind_proxy/usage.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	behindProxyPath,
	checkApp,
	expectStatus,
	type AppView,
	type Check
} from './helpers.ts';

/*
 * Conditions at the proxy (specs/124) as the people around them reach them: an administrator issuing the project's
 * proxy key and setting conditions through the real admin routes, and a proxy running the new recipe — which
 * overwrites `X-Forwarded-For` with the connection's address and sends the key — reaching the check.
 */

export const KEY_HEADER = 'X-FoxAuth-Proxy-Key';
export const PROBE_ADDRESS = '192.0.2.66';

export function proxyKeysPath(bucketId: string, keyId?: string): string {
	const base = `/admin/api/projects/${bucketId}/proxy-keys`;
	return keyId === undefined ? base : `${base}/${keyId}`;
}

export interface IssuedKey {
	id: string;
	key: string;
}

export async function issueProxyKey(
	cookie: string,
	bucketId: string
): Promise<IssuedKey> {
	const reply = await admin('POST', proxyKeysPath(bucketId), cookie, {});
	expectStatus(reply, 201, 'issuing a proxy key');
	const body = reply.body as { id: string; key: string };
	return { id: body.id, key: body.key };
}

/* The headers the new recipe adds to the check: the key, and the connection's address. */
export function fromProxy(
	key: string | null,
	address: string | null
): Record<string, string> {
	return {
		...(key === null ? {} : { [KEY_HEADER]: key }),
		...(address === null ? {} : { 'X-Forwarded-For': address })
	};
}

type Target = { slug: string; app: Pick<AppView, 'id' | 'address'> };

/* The check for an app, sent through a proxy running the new recipe. */
export function keyedCheck(
	target: Target,
	key: string | null,
	address: string | null,
	input: Omit<Check, 'slug' | 'appId' | 'host'> = {}
): Promise<Response> {
	return checkApp(target, {
		...input,
		headers: { ...input.headers, ...fromProxy(key, address) }
	});
}

export interface AddressFlags {
	keyPresent: boolean;
	keyValid: boolean;
	addressPresent: boolean;
	single: boolean;
	isPublic: boolean;
	cloudflare: boolean;
	probe: boolean;
}

/* What the app's Connect page shows about the addresses its proxy passes. */
export async function addressesOf(
	cookie: string,
	bucketId: string,
	appId: string
): Promise<{
	provenAt: string | null;
	forgedAt: string | null;
	last: AddressFlags | null;
}> {
	const reply = await admin('GET', behindProxyPath(bucketId, appId), cookie);
	expectStatus(reply, 200, 'reading an app behind the proxy');
	const addresses = (reply.body as { addresses?: unknown }).addresses;
	expect(addresses).toBeDefined();
	return addresses as {
		provenAt: string | null;
		forgedAt: string | null;
		last: AddressFlags | null;
	};
}

/* One keyed check from a public address, so the app counts as proven and network conditions may be saved. */
export async function proveAddresses(
	target: Target,
	key: string
): Promise<void> {
	const response = await keyedCheck(target, key, '203.0.113.200', {
		accept: 'application/json'
	});
	await response.arrayBuffer();
	await whenUsageRecorded();
}
