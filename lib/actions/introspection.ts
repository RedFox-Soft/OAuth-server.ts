import { tokenAuth } from '../shared/token_auth.js';
import instance from '../helpers/weak_cache.ts';
import { InvalidRequest } from '../helpers/errors.ts';
import { Elysia, t } from 'elysia';
import { routeNames } from 'lib/consts/param_list.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { IdToken } from 'lib/models/id_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { Client } from 'lib/models/client.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';

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
	client_credentials(token: string) {
		const { grantTypeHandlers } = instance(provider);
		const { ClientCredentials } = provider;
		if (!grantTypeHandlers.has('client_credentials')) {
			return;
		}
		return ClientCredentials.find(token);
	},
	refresh_token(token: string) {
		const { grantTypeHandlers } = instance(provider);
		if (!grantTypeHandlers.has('refresh_token')) {
			return;
		}
		return RefreshToken.find(token);
	}
};

async function renderTokenResponse(ctx) {
	const { params } = ctx.oidc;
	const { configuration } = instance(provider);
	const {
		pairwiseIdentifier,
		features: {
			introspection: { allowedPolicy },
			richAuthorizationRequests
		}
	} = configuration;

	ctx.body = { active: false };

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
		return ctx.body;
	}

	if (token.grantId) {
		const grant = await Grant.find(token.grantId, {
			ignoreExpiration: true
		});

		if (!grant) return ctx.body;
		if (grant.isExpired) return ctx.body;
		if (grant.clientId !== token.clientId) return ctx.body;
		if (grant.accountId !== token.accountId) return ctx.body;

		ctx.oidc.entity('Grant', grant);
	}

	if (introspectable.has(token.kind)) {
		ctx.oidc.entity(token.kind, token);
	} else {
		return ctx.body;
	}

	if (!(await allowedPolicy(ctx, ctx.oidc.client, token))) {
		return ctx.body;
	}

	if (token.accountId) {
		ctx.body.sub = token.accountId;
		if (token.clientId !== ctx.oidc.client.clientId) {
			const client = await Client.find(token.clientId);
			if (client.subjectType === 'pairwise') {
				ctx.body.sub = await pairwiseIdentifier(ctx.body.sub, client);
			}
		} else if (ctx.oidc.client.subjectType === 'pairwise') {
			ctx.body.sub = await pairwiseIdentifier(ctx.body.sub, ctx.oidc.client);
		}
	}

	Object.assign(ctx.body, {
		...token.extra,
		active: true,
		client_id: token.clientId,
		exp: token.exp,
		iat: token.iat,
		sid: token.sid,
		iss: ISSUER,
		jti: token.jti !== params.token ? token.jti : undefined,
		aud: token.aud,
		authorization_details: token.rar
			? await richAuthorizationRequests.rarForIntrospectionResponse(ctx, token)
			: undefined,
		scope: token.scope || undefined,
		cnf: token.isSenderConstrained() ? {} : undefined,
		token_type: token.kind !== 'RefreshToken' ? token.tokenType : undefined
	});

	if (token['x5t#S256']) {
		ctx.body.cnf['x5t#S256'] = token['x5t#S256'];
	}

	if (token.jkt) {
		ctx.body.cnf.jkt = token.jkt;
	}
	return ctx.body;
}

export const introspect = new Elysia().post(
	routeNames.introspect,
	async function ({ headers, body, route }) {
		const ctx = {
			headers,
			_matchedRouteName: route
		};
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = body;
		ctx.oidc.body = body;

		await tokenAuth(body, headers, ctx);

		const { configuration } = instance(provider);
		const {
			features: { jwtIntrospection }
		} = configuration;
		if (jwtIntrospection.enabled) {
			const { client } = ctx.oidc;

			const {
				introspectionEncryptedResponseAlg: encrypt,
				introspectionSignedResponseAlg: sign
			} = client;

			const accepts = ctx.accepts('json', JWT);
			if (encrypt && accepts !== JWT) {
				throw new InvalidRequest(
					`introspection must be requested with Accept: ${JWT} for this client`
				);
			}

			const body = await renderTokenResponse(ctx);

			if ((encrypt || sign) && accepts === JWT) {
				const token = new IdToken(client);
				token.extra = {
					token_introspection: body,
					aud: body.aud
				};

				ctx.body = await token.issue({ use: 'introspection' });
				return new Response(ctx.body, {
					headers: {
						'Content-Type': 'application/token-introspection+jwt; charset=utf-8'
					}
				});
			}
			return body;
		}

		return await renderTokenResponse(ctx);
	},
	{
		body: t.Object({
			token: t.String(),
			token_type_hint: t.Optional(t.String()),
			client_id: t.Optional(t.String()),
			client_assertion: t.Optional(t.String()),
			client_assertion_type: t.Optional(t.String()),
			client_secret: t.Optional(t.String())
		}),
		headers: t.Object({
			authorization: t.Optional(t.String())
		})
	}
);
