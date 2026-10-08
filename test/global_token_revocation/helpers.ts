import { getBucketStore, getUserStore } from 'lib/adapters/index.js';
import type { UserBucket } from 'lib/adapters/types.js';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { issuerFor } from 'lib/configs/issuer.js';
import type { FederationProvider } from 'lib/federation/types.js';
import { elysia } from 'lib/index.js';
import { idpStub, type IdpStub } from '../federation/idp_stub.js';

/*
 * Shared scaffolding for the global token revocation suites: a bucket whose upstream provider is a stub
 * IdP with keys of its own, and a caller that speaks to the real server over HTTP the way Okta does.
 */

/* Our client identifier at the upstream provider — what Okta puts in the assertion's `sub`. */
export const CLIENT_AT_IDP = 'our-client-at-idp';

let seq = 0;

/* A fresh origin per case: the discovery and key caches are module-level and keyed by URL. */
export function uniqueOrigin(label: string): string {
	seq += 1;
	return `https://${label}-${seq}-${Math.random().toString(36).slice(2, 8)}.idp.test`;
}

export function upstreamProvider(
	id: string,
	issuer: string,
	overrides: Partial<FederationProvider> = {}
): FederationProvider {
	return {
		id,
		displayName: id,
		enabled: true,
		issuer,
		clientId: CLIENT_AT_IDP,
		clientSecret: 'stub-secret',
		scopes: ['openid', 'email'],
		emailTrusted: false,
		provisioning: 'jit',
		allowedEmailDomains: [],
		emailClaim: 'email',
		acceptsGlobalTokenRevocation: true,
		...overrides
	};
}

/* The default bucket, served at the root, holding exactly these providers. */
export async function defaultBucketWith(
	providers: FederationProvider[]
): Promise<UserBucket> {
	const store = getBucketStore();
	const existing = await store.find(DEFAULT_BUCKET_ID);
	if (!existing) {
		return store.create({
			_id: DEFAULT_BUCKET_ID,
			name: 'default',
			ownerGroupId: UNASSIGNED_GROUP_ID,
			federation: providers
		});
	}
	const updated = await store.update(DEFAULT_BUCKET_ID, {
		federation: providers
	});
	if (!updated) throw new Error('the default bucket vanished');
	return updated;
}

/* A path-addressed bucket holding these providers. */
export async function pathBucketWith(
	providers: FederationProvider[]
): Promise<UserBucket & { slug: string }> {
	seq += 1;
	const slug = `gtr${seq}-${Math.random().toString(36).slice(2, 8)}`;
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `gtr-${seq}`,
		slug,
		federation: providers
	});
	return { ...bucket, slug };
}

export interface Upstream {
	stub: IdpStub;
	provider: FederationProvider;
	bucket: UserBucket;
}

/* A stub IdP configured as an opted-in provider of the default bucket. */
export async function upstreamOfDefaultBucket(
	label: string,
	overrides: Partial<FederationProvider> = {}
): Promise<Upstream> {
	const origin = uniqueOrigin(label);
	const stub = await idpStub(origin);
	const provider = upstreamProvider(label, origin, overrides);
	const bucket = await defaultBucketWith([provider]);
	return { stub, provider, bucket };
}

/* The provider's discovery document and keys, as the endpoint will fetch them once per case. */
export async function servesKeys(stub: IdpStub): Promise<void> {
	stub.expectDiscovery();
	await stub.expectJwks();
}

export function endpointOf(bucket: UserBucket): string {
	return `${issuerFor(bucket)}/global-token-revocation`;
}

/* Links an account of `bucketId` to the provider's subject, as a federated sign-in would have. */
export async function linkTo(
	bucketId: string,
	accountId: string,
	providerId: string,
	sub: string
): Promise<void> {
	await getUserStore(bucketId).update(accountId, {
		federated: [{ providerId, sub, linkedAt: new Date() }]
	});
}

export interface RevocationResponse {
	status: number;
	json: Record<string, unknown>;
	headers: Headers;
}

/* POST the request to `url`, as Okta sends it: a bearer assertion and a JSON body. */
export async function revoke(
	url: string,
	options: {
		assertion?: string;
		authorization?: string;
		body?: unknown;
		rawBody?: string;
		contentType?: string;
	}
): Promise<RevocationResponse> {
	const headers: Record<string, string> = {
		'content-type': options.contentType ?? 'application/json'
	};
	if (options.authorization !== undefined) {
		headers.authorization = options.authorization;
	} else if (options.assertion !== undefined) {
		headers.authorization = `Bearer ${options.assertion}`;
	}
	const response = await elysia.handle(
		new Request(url, {
			method: 'POST',
			headers,
			body: options.rawBody ?? JSON.stringify(options.body ?? {})
		})
	);
	const text = await response.text();
	let json: Record<string, unknown>;
	try {
		json = text ? JSON.parse(text) : {};
	} catch {
		json = { raw: text };
	}
	return { status: response.status, json, headers: response.headers };
}

/* The body naming a user by the provider's subject for them. */
export function issSub(iss: string, sub: string) {
	return { sub_id: { format: 'iss_sub', iss, sub } };
}

export function email(address: string) {
	return { sub_id: { format: 'email', email: address } };
}
