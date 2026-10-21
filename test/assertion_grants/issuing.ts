import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { Type } from '@sinclair/typebox';

import { agent, redirectParameter, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { getOutsideAuthorizationServerStore } from 'lib/adapters/index.js';
import type {
	OutsideAuthorizationServer,
	OutsideServerRule
} from 'lib/adapters/types.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { outsideServerId } from 'lib/assertions/outside_server_id.ts';
import { ISSUER } from 'lib/configs/env.js';
import { present, shaped } from 'test/shape.js';
import { ID_JAG_TYP } from './helpers.js';

/*
 * Shared scaffolding for the issuing side (specs/108 story 2): a person signed in to the project through an
 * application, the tokens that sign-in produced, and the token exchange that application then makes.
 */

export const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
export const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
export const REFRESH_TOKEN_TYPE =
	'urn:ietf:params:oauth:token-type:refresh_token';

export const ExchangeBody = Type.Object({
	issued_token_type: Type.String(),
	access_token: Type.String(),
	token_type: Type.String(),
	expires_in: Type.Number(),
	scope: Type.Optional(Type.String()),
	refresh_token: Type.Optional(Type.String())
});

const Tokens = Type.Object({
	id_token: Type.String(),
	refresh_token: Type.Optional(Type.String())
});

const SECRETS: Partial<Record<string, string>> = {
	'globex-agent': 'globex-agent-secret',
	'other-agent': 'other-agent-secret',
	'https://agent.globex.example/client.json': 'url-agent-secret',
	'tickets-sso': 'tickets-sso-secret'
};

/* The person signs in through `clientId` with the code flow; answers the ID token and refresh token it got. */
export async function signIn(
	setup: Setup,
	clientId: string,
	accountId: string,
	scope = 'openid offline_access'
): Promise<{ id_token: string; refresh_token?: string }> {
	const cookie = await setup.login({ scope, accountId });
	const request = new AuthorizationRequest({
		client_id: clientId,
		scope,
		prompt: 'consent'
	});
	const auth = await agent.auth.get({
		query: request.params,
		headers: { cookie }
	});
	const { data } = await request.getToken(
		redirectParameter(auth.response, 'code')
	);
	return shaped(Tokens, data);
}

export interface Exchange {
	subjectToken: string;
	subjectTokenType?: string;
	audience?: string | string[];
	resource?: string | string[];
	scope?: string;
	requestedTokenType?: string | null;
	clientId?: string;
	/* `null` presents the client id alone, as a client that does not authenticate does. */
	secret?: string | null;
	actorToken?: string;
	dpop?: string;
}

/* A token exchange at the root token endpoint, for an ID-JAG unless the case says otherwise. */
export function exchange(request: Exchange) {
	const {
		subjectToken,
		subjectTokenType = ID_TOKEN_TYPE,
		audience,
		resource,
		scope,
		requestedTokenType = ID_JAG_TOKEN_TYPE,
		clientId = 'globex-agent',
		secret = SECRETS[clientId],
		actorToken,
		dpop
	} = request;
	return agent.token.post(
		{
			grant_type: EXCHANGE,
			subject_token: subjectToken,
			subject_token_type: subjectTokenType,
			...(requestedTokenType === null
				? {}
				: { requested_token_type: requestedTokenType }),
			...(audience === undefined ? {} : { audience }),
			...(resource === undefined ? {} : { resource }),
			...(scope === undefined ? {} : { scope }),
			...(actorToken === undefined
				? {}
				: {
						actor_token: actorToken,
						actor_token_type: ID_TOKEN_TYPE
					}),
			...(secret === null ? { client_id: clientId } : {})
		},
		{
			headers: {
				...(secret === null || secret === undefined
					? {}
					: AuthorizationRequest.basicAuthHeader(clientId, secret)),
				...(dpop ? { dpop } : {})
			}
		}
	);
}

/* An outside authorization server connected to the default project, as the console would store it. */
export async function connect(fields: {
	issuer: string;
	clients?: OutsideAuthorizationServer['clients'];
	rules?: OutsideServerRule[];
	signInClientId?: string;
	includeEmail?: boolean;
}): Promise<OutsideAuthorizationServer> {
	const now = new Date();
	return getOutsideAuthorizationServerStore().create({
		_id: outsideServerId(DEFAULT_BUCKET_ID, fields.issuer),
		bucketId: DEFAULT_BUCKET_ID,
		issuer: fields.issuer,
		displayName: 'Outside',
		clients: fields.clients ?? [
			{ clientId: 'globex-agent', externalClientId: 'f53f191f' }
		],
		rules: fields.rules ?? [],
		...(fields.signInClientId === undefined
			? {}
			: { signInClientId: fields.signInClientId }),
		includeEmail: fields.includeEmail ?? true,
		createdAt: now,
		updatedAt: now
	});
}

/* The ID-JAG checked as the outside server checks it: against the keys this project publishes, typed. */
export async function verifiedIdJag(
	idJag: string,
	audience: string
): Promise<{ header: Record<string, unknown>; claims: JWTPayload }> {
	const { data } = await agent.jwks.get();
	// The published set's shape is RFC 7517's, which jose validates itself as it builds the key set.
	const keys = createLocalJWKSet(present(data, 'the key set'));
	const { payload, protectedHeader } = await jwtVerify(idJag, keys, {
		issuer: ISSUER,
		audience,
		typ: ID_JAG_TYP
	});
	return { header: protectedHeader, claims: payload };
}
