import { Type, type Static } from '@sinclair/typebox';
import { generateKeyPair } from 'jose';

import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { issuingBucket } from 'lib/admin/auth/bucketAddress.ts';
import { keysFor } from 'lib/keys/issuer_keys.ts';
import * as JWT from 'lib/helpers/jwt.ts';
import { checkIdOf } from 'lib/behind_proxy/check_id.ts';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import nanoid from 'lib/helpers/nanoid.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import { expectStatus } from './helpers.ts';

/*
 * APIs whose tokens the operator's proxy checks (specs/123), as the people around them reach them: an administrator
 * through the real admin routes, an MCP client through the proxy, and the proxy through the API check, sent exactly
 * as Caddy sends it — the original host and method in `X-Forwarded-*`, every other header of the client's request
 * copied as it came.
 */

export interface ToolsBody {
	rows: { name: string; scopes: string[] }[];
	otherTools: 'refuse' | 'token';
	withoutMethod: 'refuse' | 'token';
}

export const ApiView = Type.Object({
	identifier: Type.String(),
	namespace: Type.String(),
	checkedBy: Type.String(),
	scopes: Type.Array(Type.String()),
	tokenFormat: Type.String(),
	connection: Type.Object({
		issuer: Type.String(),
		metadataUrl: Type.Union([Type.String(), Type.Null()]),
		challenge: Type.Union([Type.String(), Type.Null()]),
		check: Type.Optional(
			Type.Union([
				Type.Null(),
				Type.Object({ verifyUrl: Type.String(), metadataUrl: Type.String() })
			])
		)
	})
});
export type ApiView = Static<typeof ApiView>;

export function resourcesPath(bucketId: string, identifier?: string): string {
	const base = `/admin/api/projects/${bucketId}/resources`;
	return identifier === undefined
		? base
		: `${base}/${encodeURIComponent(identifier)}`;
}

let apis = 0;

/* An identifier no other API of the file uses, so cases never meet each other's APIs. */
export function freshIdentifier(): string {
	apis += 1;
	return `https://mcp${String(apis)}.example.com/mcp`;
}

export const FILE_SCOPES = ['files:read', 'files:write', 'files:delete'];

export async function declareApi(
	cookie: string,
	bucketId: string,
	fields: {
		identifier?: string;
		scopes?: string[];
		tokenFormat?: 'jwt' | 'opaque';
		checkedBy?: 'server' | 'proxy';
		tools?: ToolsBody;
	} = {}
): Promise<ApiView> {
	const reply = await admin('POST', resourcesPath(bucketId), cookie, {
		identifier: fields.identifier ?? freshIdentifier(),
		name: 'Files MCP',
		scopes: fields.scopes ?? FILE_SCOPES,
		...(fields.tokenFormat ? { tokenFormat: fields.tokenFormat } : {}),
		...(fields.checkedBy ? { checkedBy: fields.checkedBy } : {})
	});
	expectStatus(reply, 201, 'declaring an API');
	const declared = shaped(ApiView, reply.body);
	if (!fields.tools) return declared;
	return changeApi(cookie, bucketId, declared.identifier, {
		tools: fields.tools
	});
}

export async function changeApi(
	cookie: string,
	bucketId: string,
	identifier: string,
	body: Record<string, unknown>
): Promise<ApiView> {
	const reply = await admin(
		'PATCH',
		resourcesPath(bucketId, identifier),
		cookie,
		body
	);
	expectStatus(reply, 200, 'changing an API');
	return shaped(ApiView, reply.body);
}

/* --- tokens -------------------------------------------------------------------------------------------------- */

/* The bucket whose keys sign the API's tokens: its project when that has an address, the root's otherwise. */
function signerOf(api: Pick<ApiView, 'namespace'>) {
	return issuingBucket(api.namespace === '@root' ? undefined : api.namespace);
}

export interface Minted {
	claims?: Record<string, unknown>;
	header?: Record<string, unknown>;
	/* A key the project does not hold. */
	foreignKey?: boolean;
}

/*
 * A self-contained access token for the API, signed the way the project signs one: by the project's key, `typ`
 * `at+jwt`. Every claim can be overridden, so a case states the one defect it is about.
 */
export async function jwtFor(
	api: Pick<ApiView, 'identifier' | 'namespace' | 'connection'>,
	minted: Minted = {}
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const payload: Record<string, unknown> = {
		iss: api.connection.issuer,
		aud: api.identifier,
		sub: 'account-1',
		client_id: 'agent-1',
		scope: 'files:read',
		jti: nanoid(),
		iat: now,
		exp: now + 300,
		...minted.claims
	};
	for (const [name, value] of Object.entries(payload)) {
		if (value === undefined) delete payload[name];
	}
	if (minted.foreignKey) {
		const { privateKey } = await generateKeyPair('ES256');
		return JWT.sign(payload, privateKey, 'ES256', {
			typ: 'at+jwt',
			noIat: true,
			fields: { kid: 'not-the-project-key', ...minted.header }
		});
	}
	const { signing } = await keysFor(await signerOf(api));
	const jwk = [...signing].at(0);
	if (!jwk || typeof jwk.alg !== 'string') {
		throw new Error('the project holds no signing key');
	}
	return JWT.sign(payload, signing.getKeyObject(jwk), jwk.alg, {
		typ: 'at+jwt',
		noIat: true,
		fields: { kid: jwk.kid, ...minted.header }
	});
}

/* An opaque machine token for the API, stored as the token endpoint stores one. */
export async function opaqueFor(
	api: Pick<ApiView, 'identifier'>,
	bucketId: string,
	fields: { scope?: string; jkt?: string } = {}
): Promise<{ value: string; revoke: () => Promise<void> }> {
	const token = new ClientCredentials({
		clientId: 'agent-1',
		bucketId,
		aud: api.identifier,
		scope: fields.scope ?? 'files:read',
		...(fields.jkt ? { jkt: fields.jkt } : {})
	});
	token.expiresIn = 300;
	const value = await token.save();
	return {
		value,
		revoke: async () => {
			const found = await ClientCredentials.tryFind(value);
			await found?.destroy();
		}
	};
}

/* --- the check, as a proxy sends it ------------------------------------------------------------------------- */

export function apiCheckUrl(slug: string | null, identifier: string): string {
	return `${ISSUER}${slug ? `/${slug}` : ''}/verify/api/${checkIdOf(identifier)}`;
}

export interface ApiCheck {
	slug: string | null;
	identifier: string;
	/* The host the client asked for, as the proxy reports it; the identifier's own by default. */
	host?: string;
	method?: string;
	/* One `Authorization` value, or several to send the header more than once. */
	authorization?: string | string[];
	mcpMethod?: string;
	mcpName?: string;
	protocolVersion?: string | null;
	omit?: readonly ('X-Forwarded-Host' | 'X-Forwarded-Method')[];
	headers?: Record<string, string>;
	query?: string;
}

export function apiCheck(input: ApiCheck): Promise<Response> {
	const headers = new Headers(input.headers);
	const forwarded = {
		'X-Forwarded-Host': input.host ?? new URL(input.identifier).host,
		'X-Forwarded-Method': input.method ?? 'POST'
	};
	for (const [name, value] of Object.entries(forwarded)) {
		if (!input.omit?.includes(name as keyof typeof forwarded)) {
			headers.set(name, value);
		}
	}
	headers.set('X-Forwarded-Uri', new URL(input.identifier).pathname);
	headers.set('X-Forwarded-Proto', 'https');
	for (const value of [input.authorization ?? []].flat()) {
		headers.append('Authorization', value);
	}
	if (input.mcpMethod !== undefined) headers.set('Mcp-Method', input.mcpMethod);
	if (input.mcpName !== undefined) headers.set('Mcp-Name', input.mcpName);
	const version =
		input.protocolVersion === undefined ? '2026-07-28' : input.protocolVersion;
	if (version !== null) headers.set('MCP-Protocol-Version', version);
	return elysia.handle(
		new Request(
			`${apiCheckUrl(input.slug, input.identifier)}${input.query ?? ''}`,
			{ method: 'GET', headers }
		)
	);
}

export function bearer(token: string): string {
	return `Bearer ${token}`;
}
