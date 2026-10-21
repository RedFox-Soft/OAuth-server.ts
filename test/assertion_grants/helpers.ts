import {
	SignJWT,
	calculateJwkThumbprint,
	exportJWK,
	generateKeyPair,
	type GenerateKeyPairResult
} from 'jose';
import { Type } from '@sinclair/typebox';

import { agent } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { getProtectedResourceStore } from 'lib/adapters/index.js';
import type { UserBucket } from 'lib/adapters/types.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.js';
import type { FederationProvider } from 'lib/federation/types.js';
import nanoid from 'lib/helpers/nanoid.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import {
	idpStub,
	type AssertionOptions,
	type IdpStub
} from '../federation/idp_stub.js';
import {
	defaultBucketWith,
	servesKeys,
	uniqueOrigin,
	upstreamProvider
} from '../global_token_revocation/helpers.js';

/*
 * Shared scaffolding for the assertion grant suites (specs/108): an enterprise identity provider with keys of
 * its own, trusted by the default project for assertions, and an agent that presents what it signs at the
 * project's token endpoint the way an MCP client does.
 */

export const ID_JAG_TYP = 'oauth-id-jag+jwt';
export const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
export const JWT_DPOP = 'urn:ietf:params:oauth:grant-type:jwt-dpop';

/* The OAuth error body every refusal here is read through. */
export const OAuthError = Type.Object({
	error: Type.String(),
	error_description: Type.Optional(Type.String())
});
export const TokenBody = Type.Object({
	access_token: Type.String(),
	token_type: Type.String(),
	expires_in: Type.Number(),
	scope: Type.Optional(Type.String()),
	resource: Type.Optional(Type.String()),
	refresh_token: Type.Optional(Type.String())
});

export interface Enterprise {
	stub: IdpStub;
	provider: FederationProvider;
	bucket: UserBucket;
}

/*
 * A stub IdP configured as a provider of the default project, trusted for identity assertions unless the
 * overrides say otherwise. Its discovery document and keys are registered once: the key cache outlives a
 * request, so a case presenting twice consumes them once.
 */
export async function enterprise(
	label: string,
	overrides: Partial<FederationProvider> = {}
): Promise<Enterprise> {
	const origin = uniqueOrigin(label);
	const stub = await idpStub(origin);
	const provider = upstreamProvider(label, origin, {
		acceptsGlobalTokenRevocation: undefined,
		acceptsIdentityAssertions: true,
		...overrides
	});
	const bucket = await defaultBucketWith([provider]);
	await servesKeys(stub);
	return { stub, provider, bucket };
}

/* An API declared by the default project, served at the root issuer. */
export async function declareApi(
	identifier: string,
	scopes: string[],
	tokenFormat: 'jwt' | 'opaque' = 'opaque'
): Promise<void> {
	await getProtectedResourceStore().create({
		namespace: ROOT_NAMESPACE,
		identifier,
		bucketId: DEFAULT_BUCKET_ID,
		name: identifier,
		scopes,
		tokenFormat
	});
}

/* An ID-JAG this provider issues for the agent, addressed to the root issuer; `claims` override any member. */
export function idJag(
	stub: IdpStub,
	claims: Record<string, unknown>,
	opts?: AssertionOptions
): Promise<string> {
	return stub.assertion(
		{ aud: ISSUER, client_id: 'agent', sub: 'enterprise-subject', ...claims },
		ID_JAG_TYP,
		opts
	);
}

export interface Presentation {
	assertion: string;
	grantType?: string;
	clientId?: string;
	/* `null` presents the client id alone, as a client that does not authenticate does. */
	secret?: string | null;
	resource?: string | string[];
	scope?: string;
	dpop?: string;
}

/* The agent presenting an assertion at the root token endpoint, authenticated with its secret. */
export function present(presentation: Presentation) {
	const {
		assertion,
		grantType = JWT_BEARER,
		clientId = 'agent',
		secret = 'agent-secret',
		resource,
		scope,
		dpop
	} = presentation;
	return agent.token.post(
		{
			grant_type: grantType,
			assertion,
			...(secret === null ? { client_id: clientId } : {}),
			...(resource === undefined ? {} : { resource }),
			...(scope === undefined ? {} : { scope })
		},
		{
			headers: {
				...(secret === null
					? {}
					: AuthorizationRequest.basicAuthHeader(clientId, secret)),
				...(dpop ? { dpop } : {})
			}
		}
	);
}

export async function dpopKey(): Promise<{
	keypair: GenerateKeyPairResult;
	thumbprint: string;
}> {
	const keypair = await generateKeyPair('ES256', { extractable: true });
	const thumbprint = await calculateJwkThumbprint(
		await exportJWK(keypair.publicKey)
	);
	return { keypair, thumbprint };
}

/* A DPoP proof for a token request to the root issuer (RFC 9449 §4.2). */
export async function dpopProof(
	keypair: GenerateKeyPairResult,
	htu = `${ISSUER}/token`
): Promise<string> {
	return new SignJWT({ htu, htm: 'POST' })
		.setProtectedHeader({
			alg: 'ES256',
			typ: 'dpop+jwt',
			jwk: await exportJWK(keypair.publicKey)
		})
		.setJti(nanoid())
		.setIssuedAt()
		.sign(keypair.privateKey);
}
