import instance from '../helpers/weak_cache.ts';
import { InvalidRequest } from '../helpers/errors.ts';
import { Elysia, t } from 'elysia';
import { routeNames } from 'lib/consts/param_list.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { IdToken } from 'lib/models/id_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { Client } from 'lib/models/client.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import { hasGrant } from './grants/index.js';
import { AuthPlugin, authHeaders, authParams } from 'lib/plugins/auth.js';
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
		return AccessToken.find(token);
	},
	async client_credentials(token: string) {
		if (!hasGrant('client_credentials')) {
			return;
		}
		return ClientCredentials.find(token);
	},
	refresh_token(token: string) {
		return RefreshToken.find(token);
	}
};

async function renderTokenResponse(oidc) {
	const { params } = oidc;
	const { configuration } = instance(provider);
	const {
		pairwiseIdentifier,
		features: {
			introspection: { allowedPolicy },
			richAuthorizationRequests
		}
	} = configuration;

	let token;

	const methodToken = tokenTypes[params.token_type_hint];
	if (methodToken) {
		token = await methodToken(params.token);
		if (!token) {
			const otherMethods = Object.keys(tokenTypes)
				.filter((type) => type !== params.token_type_hint)
				.map((type) => tokenTypes[type](params.token));
			token = (await Promise.all(otherMethods)).find((t) => t);
		}
	} else {
		token = (
			await Promise.all(Object.values(tokenTypes).map((fn) => fn(params.token)))
		).find((t) => t);
	}

	if (!token?.isValid) {
		return { active: false };
	}

	if (token.payload.grantId) {
		const grant = await Grant.find(token.payload.grantId, {
			ignoreExpiration: true
		});

		if (
			!grant ||
			grant.isExpired ||
			grant.payload.clientId !== token.payload.clientId ||
			grant.payload.accountId !== token.payload.accountId
		) {
			return { active: false };
		}

		oidc.entity('Grant', grant);
	}

	if (introspectable.has(token.payload.kind)) {
		oidc.entity(token.payload.kind, token);
	} else {
		return { active: false };
	}

	if (!(await allowedPolicy({ oidc }, oidc.client, token))) {
		return { active: false };
	}

	const body: any = { active: false };
	if (token.payload.accountId) {
		body.sub = token.payload.accountId;
		if (token.payload.clientId !== oidc.client.clientId) {
			const client = await Client.find(token.payload.clientId);
			if (client.subjectType === 'pairwise') {
				body.sub = await pairwiseIdentifier(body.sub, client);
			}
		} else if (oidc.client.subjectType === 'pairwise') {
			body.sub = await pairwiseIdentifier(body.sub, oidc.client);
		}
	}

	Object.assign(body, {
		...token.extra,
		active: true,
		client_id: token.payload.clientId,
		exp: token.payload.exp,
		iat: token.payload.iat,
		sid: token.payload.sid,
		iss: ISSUER,
		jti: token.payload.jti !== params.token ? token.payload.jti : undefined,
		aud: token.payload.aud,
		authorization_details: token.payload.rar
			? await richAuthorizationRequests.rarForIntrospectionResponse(
					{ oidc },
					token
				)
			: undefined,
		scope: token.payload.scope || undefined,
		cnf: token.isSenderConstrained() ? {} : undefined,
		token_type:
			token.payload.kind !== 'RefreshToken' ? token.tokenType : undefined
	});

	if (token.payload['x5t#S256']) {
		body.cnf['x5t#S256'] = token.payload['x5t#S256'];
	}

	if (token.payload.jkt) {
		body.cnf.jkt = token.payload.jkt;
	}
	return body;
}

export const introspect = new Elysia().use(AuthPlugin).post(
	routeNames.introspect,
	async function ({ oidc, request }) {
		if (ApplicationConfig['jwtIntrospection.enabled']) {
			const { client } = oidc;

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
					aud: body.aud
				};

				const jwt = await token.issue('introspection');
				return new Response(jwt, {
					headers: {
						'Content-Type': 'application/token-introspection+jwt; charset=utf-8'
					}
				});
			}
			return body;
		}

		return await renderTokenResponse(oidc);
	},
	{
		body: t.Composite([
			t.Object({
				token: t.String(),
				token_type_hint: t.Optional(t.String())
			}),
			authParams
		]),
		headers: authHeaders,
		response: {
			200: IntrospectionResponse,
			400: OAuthError,
			401: OAuthError
		}
	}
);
