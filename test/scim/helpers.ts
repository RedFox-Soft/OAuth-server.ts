import { getBucketStore } from 'lib/adapters/index.js';
import type { ProvisioningConnection, UserBucket } from 'lib/adapters/types.js';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import type { FederationProvider } from 'lib/federation/types.js';
import { elysia } from 'lib/index.js';
import {
	createConnection,
	issueCredential,
	type CreateConnectionInput
} from 'lib/provisioning/service.js';
import { SCIM_PATCH_OP, SCIM_USER_SCHEMA } from 'lib/consts/scim.js';

/*
 * Shared scaffolding for the SCIM suites: a bucket with a federation provider, a connection bound to it
 * holding a static token, and a caller that speaks to the real server over HTTP the way a directory does.
 */

export function provider(
	id: string,
	overrides: Partial<FederationProvider> = {}
): FederationProvider {
	return {
		id,
		displayName: id,
		enabled: true,
		issuer: `https://${id}.idp.test`,
		clientId: 'stub-client',
		clientSecret: 'stub-secret',
		scopes: ['openid', 'email', 'profile'],
		emailTrusted: false,
		provisioning: 'jit',
		allowedEmailDomains: [],
		emailClaim: 'email',
		...overrides
	};
}

let seq = 0;

/* A path-addressed bucket with the given providers. */
export async function scimBucket(
	providers: FederationProvider[] = [provider('corp')],
	fields: Partial<UserBucket> = {}
): Promise<UserBucket> {
	seq += 1;
	return getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `scim-${seq}`,
		slug: `acme${seq}-${Math.random().toString(36).slice(2, 8)}`,
		federation: providers,
		...fields
	});
}

/* The default bucket, served at the root, with the given providers. */
export async function defaultScimBucket(
	providers: FederationProvider[] = [provider('corp')]
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
	return (await store.update(DEFAULT_BUCKET_ID, {
		federation: providers
	})) as UserBucket;
}

export async function reload(bucket: UserBucket): Promise<UserBucket> {
	return (await getBucketStore().find(bucket._id)) as UserBucket;
}

const noAudit = async () => undefined;

export interface Connected {
	bucket: UserBucket;
	connection: ProvisioningConnection;
	token: string;
	/* `/<slug>/scim/v2`, or `/scim/v2` at the root. */
	base: string;
}

/* A connection on `bucket` bound to its first provider (or `providerId`), holding a static token. */
export async function connect(
	bucket: UserBucket,
	input: Partial<CreateConnectionInput> = {}
): Promise<Connected> {
	const fresh = await reload(bucket);
	const connection = await createConnection(
		fresh,
		{
			displayName: 'Directory',
			providerId: input.providerId ?? fresh.federation?.[0]?.id ?? 'corp',
			...input
		},
		noAudit
	);
	const issued = await issueCredential(
		await reload(fresh),
		connection._id,
		{ kind: 'static_token' },
		noAudit
	);
	return {
		bucket: await reload(fresh),
		connection: issued.connection,
		token: issued.token as string,
		base:
			fresh.slug && fresh._id !== DEFAULT_BUCKET_ID
				? `/${fresh.slug}/scim/v2`
				: '/scim/v2'
	};
}

export interface ScimResponse {
	status: number;
	json: Record<string, unknown>;
	headers: Headers;
}

export async function scim(
	method: string,
	path: string,
	options: {
		token?: string;
		authorization?: string;
		body?: unknown;
		contentType?: string;
		rawBody?: string;
	} = {}
): Promise<ScimResponse> {
	const headers: Record<string, string> = {};
	if (options.authorization !== undefined) {
		headers.authorization = options.authorization;
	} else if (options.token) {
		headers.authorization = `Bearer ${options.token}`;
	}
	let body: string | undefined;
	if (options.rawBody !== undefined || options.body !== undefined) {
		headers['content-type'] = options.contentType ?? 'application/scim+json';
		body = options.rawBody ?? JSON.stringify(options.body);
	}
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, { method, headers, body })
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

/* A SCIM User a directory would send. */
export function scimUser(
	userName: string,
	extra: Record<string, unknown> = {}
): Record<string, unknown> {
	return {
		schemas: [SCIM_USER_SCHEMA],
		userName,
		emails: [{ value: userName, type: 'work', primary: true }],
		active: true,
		...extra
	};
}

export function patchOf(operations: unknown[]): Record<string, unknown> {
	return { schemas: [SCIM_PATCH_OP], Operations: operations };
}
