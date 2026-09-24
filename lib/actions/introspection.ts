import { InvalidRequest } from '../helpers/errors.ts';
import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Elysia, t, type Static } from 'elysia';
import { routeNames } from 'lib/consts/param_list.js';
import {
	introspectionAllowedPolicy,
	pairwiseIdentifier,
	rarForIntrospectionResponse
} from '../addon/index.js';
import { issuingBucket } from 'lib/admin/auth/bucketAddress.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { IdToken } from 'lib/models/id_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { Client } from 'lib/models/client.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';
import { storeToken } from '../shared/findToken.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import { hasGrant } from './grants/index.js';
import {
	AuthPlugin,
	authHeaders,
	authParams,
	withBody,
	type authParamsType
} from 'lib/plugins/auth.js';
import {
	IntrospectionResponse,
	OAuthError
} from 'lib/shared/response_schemas.js';

const introspectable = new Set([
	'AccessToken',
	'ClientCredentials',
	'RefreshToken'
]);
const JWT = 'application/token-introspection+jwt';

const tokenTypes = {
	access_token(token: string) {
		return AccessToken.tryFind(token);
	},
	async client_credentials(token: string) {
		if (!hasGrant('client_credentials')) {
			return;
		}
		return ClientCredentials.tryFind(token);
	},
	refresh_token(token: string) {
		return RefreshToken.tryFind(token);
	}
};

// What the introspection endpoint reads off its request, once its body schema has been applied.
type IntrospectionParams = authParamsType & {
	token: string;
	token_type_hint?: string;
};

function isTokenTypeHint(value: unknown): value is keyof typeof tokenTypes {
	return typeof value === 'string' && Object.hasOwn(tokenTypes, value);
}

// The members an introspection answer reads off a token; a client-credentials token carries fewer.
type IntrospectedPayload = {
	clientId: string;
	kind: string;
	bucketId?: string;
	grantId?: string;
	accountId?: string;
	exp?: number;
	iat?: number;
	sid?: string;
	jti?: string;
	aud?: string;
	rar?: unknown[];
	scope?: string;
	jkt?: string;
	'x5t#S256'?: string;
};

// The JSON answer (the JWT form is built from it by the handler).
type IntrospectionAnswer = Exclude<
	Static<typeof IntrospectionResponse>,
	string
>;

async function renderTokenResponse(
	oidc: OIDCContext<IntrospectionParams>
): Promise<IntrospectionAnswer> {
	const { params } = oidc;
	let token;

	const hint = params.token_type_hint;
	if (isTokenTypeHint(hint)) {
		token = await tokenTypes[hint](params.token);
		if (!token) {
			const otherMethods = Object.entries(tokenTypes)
				.filter(([type]) => type !== hint)
				.map(([, find]) => find(params.token));
			token = (await Promise.all(otherMethods)).find((found) => found);
		}
	} else {
		token = (
			await Promise.all(Object.values(tokenTypes).map((fn) => fn(params.token)))
		).find((t) => t);
	}

	if (!token?.isValid) {
		return { active: false };
	}

	const payload: IntrospectedPayload = token.payload;

	/*
	 * A token this address did not issue is not active here.
	 *
	 * RFC 7662 §2.2 makes `active: true` an assertion that *this* authorization server issued the token,
	 * and every bucket is its own authorization server. Answering `true` for a token minted by another
	 * bucket would tell a resource server that a token from a different population is good — the same
	 * defect a realm-confusion advisory reported against a Keycloak integration, where a token of one
	 * realm was silently accepted by a policy configured for another.
	 *
	 * Compared against the recorded issuing bucket rather than anything derived from the client, which
	 * is the whole reason that field is stored. A token minted before buckets became tenants records
	 * nothing and belongs to the default bucket, which is what `issuingBucket` resolves an absence to.
	 */
	const issuedBy = await issuingBucket(payload.bucketId);
	if (issuedBy._id !== oidc.bucket._id) {
		return { active: false };
	}

	if (payload.grantId) {
		const grant = await Grant.tryFind(payload.grantId, {
			ignoreExpiration: true
		});

		if (
			!grant ||
			grant.isExpired ||
			grant.payload.clientId !== payload.clientId ||
			grant.payload.accountId !== payload.accountId
		) {
			return { active: false };
		}

		oidc.entity('Grant', grant);
	}

	if (introspectable.has(payload.kind)) {
		storeToken(oidc, token);
	} else {
		return { active: false };
	}

	if (!(await introspectionAllowedPolicy(oidc, oidc.client, token))) {
		return { active: false };
	}

	const body: IntrospectionAnswer = {
		active: true,
		client_id: payload.clientId,
		exp: payload.exp,
		iat: payload.iat,
		sid: payload.sid,
		iss: oidc.issuer,
		jti: payload.jti !== params.token ? payload.jti : undefined,
		aud: payload.aud,
		scope: payload.scope || undefined,
		token_type: payload.kind !== 'RefreshToken' ? token.tokenType : undefined
	};

	if (payload.accountId) {
		let sub = payload.accountId;
		if (payload.clientId !== oidc.client.clientId) {
			const client = await Client.find(payload.clientId);
			if (client.subjectType === 'pairwise') {
				sub = await pairwiseIdentifier(sub, client);
			}
		} else if (oidc.client.subjectType === 'pairwise') {
			sub = await pairwiseIdentifier(sub, oidc.client);
		}
		body.sub = sub;
	}

	if (payload.rar) {
		const details = await rarForIntrospectionResponse(oidc, token);
		// A deployment shapes these; anything but a list is not an authorization_details value.
		body.authorization_details = Array.isArray(details) ? details : undefined;
	}

	if (token.isSenderConstrained()) {
		const cnf: Record<string, string> = {};
		if (payload['x5t#S256']) {
			cnf['x5t#S256'] = payload['x5t#S256'];
		}
		if (payload.jkt) {
			cnf.jkt = payload.jkt;
		}
		body.cnf = cnf;
	}
	return body;
}

export const introspect = new Elysia().use(AuthPlugin).post(
	routeNames.introspect,
	async function ({ oidc: context, body: requestBody, request, set }) {
		const oidc = withBody(context, requestBody);
		if (ApplicationConfig['jwtIntrospection.enabled']) {
			const client = oidc.client;

			const {
				introspectionEncryptedResponseAlg: encrypt,
				introspectionSignedResponseAlg: sign
			} = client;

			const accept = request.headers.get('accept') || '';
			const accepts = accept.includes(JWT) ? JWT : 'json';
			if (encrypt && accepts !== JWT) {
				throw new InvalidRequest(
					`introspection must be requested with Accept: ${JWT} for this client`
				);
			}

			const body = await renderTokenResponse(oidc);

			if ((encrypt || sign) && accepts === JWT) {
				const token = new IdToken(client);
				token.extra = {
					token_introspection: body,
					aud: body.active ? body.aud : undefined
				};

				// Set once issuing has succeeded: a refusal from issue() is answered through `set` too.
				const jwt = await token.issue('introspection');
				set.headers['content-type'] =
					'application/token-introspection+jwt; charset=utf-8';
				return jwt;
			}
			return body;
		}

		return await renderTokenResponse(oidc);
	},
	{
		body: t.Object({
			token: t.String(),
			token_type_hint: t.Optional(t.String()),
			...authParams.properties
		}),
		headers: authHeaders,
		response: {
			200: IntrospectionResponse,
			400: OAuthError,
			401: OAuthError,
			500: OAuthError
		}
	}
);
