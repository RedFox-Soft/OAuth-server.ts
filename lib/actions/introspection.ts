import getTokenAuth from '../shared/token_auth.ts';
import instance from '../helpers/weak_cache.ts';
import { InvalidRequest } from '../helpers/errors.ts';
import { Elysia, t } from 'elysia';
import { routeNames } from 'lib/consts/param_list.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';

const introspectable = new Set([
	'AccessToken',
	'ClientCredentials',
	'RefreshToken'
]);
const JWT = 'application/token-introspection+jwt';

function getAccessToken(token) {
	const { AccessToken } = provider;
	return AccessToken.find(token);
}

function getClientCredentials(token) {
	const { grantTypeHandlers } = instance(provider);
	const { ClientCredentials } = provider;
	if (!grantTypeHandlers.has('client_credentials')) {
		return undefined;
	}
	return ClientCredentials.find(token);
}

function getRefreshToken(token) {
	const { grantTypeHandlers } = instance(provider);
	const { RefreshToken } = provider;
	if (!grantTypeHandlers.has('refresh_token')) {
		return undefined;
	}
	return RefreshToken.find(token);
}

function findResult(results) {
	return results.find((found) => !!found);
}

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

	switch (params.token_type_hint) {
		case 'access_token':
			token = await getAccessToken(params.token).then((result) => {
				if (result) return result;
				return Promise.all([
					getClientCredentials(params.token),
					getRefreshToken(params.token)
				]).then(findResult);
			});
			break;
		case 'client_credentials':
			token = await getClientCredentials(params.token).then((result) => {
				if (result) return result;
				return Promise.all([
					getAccessToken(params.token),
					getRefreshToken(params.token)
				]).then(findResult);
			});
			break;
		case 'refresh_token':
			token = await getRefreshToken(params.token).then((result) => {
				if (result) return result;
				return Promise.all([
					getAccessToken(params.token),
					getClientCredentials(params.token)
				]).then(findResult);
			});
			break;
		default:
			token = await Promise.all([
				getAccessToken(params.token),
				getClientCredentials(params.token),
				getRefreshToken(params.token)
			]).then(findResult);
	}

	if (!token?.isValid) {
		return ctx.body;
	}

	if (token.grantId) {
		const grant = await ctx.oidc.provider.Grant.find(token.grantId, {
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
			const client = await provider.Client.find(token.clientId);
			if (client.subjectType === 'pairwise') {
				ctx.body.sub = await pairwiseIdentifier(ctx, ctx.body.sub, client);
			}
		} else if (ctx.oidc.client.subjectType === 'pairwise') {
			ctx.body.sub = await pairwiseIdentifier(
				ctx,
				ctx.body.sub,
				ctx.oidc.client
			);
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
	async function ({ headers, body }) {
		const ctx = {
			headers
		};
		const OIDCContext = provider.OIDCContext;
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = body;
		ctx.oidc.body = body;

		const { middleware: tokenAuth } = getTokenAuth(provider);

		for (const middleware of tokenAuth) {
			await middleware(ctx, () => {});
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

export default function introspectionAction(provider) {
	const { configuration } = instance(provider);
	const {
		features: { jwtIntrospection }
	} = configuration;
	const { IdToken } = provider;

	return [
		async function jwtIntrospectionResponse(ctx, next) {
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

				await next();

				if ((encrypt || sign) && accepts === JWT) {
					const token = new IdToken({}, { ctx });
					token.extra = {
						token_introspection: ctx.body,
						aud: ctx.body.aud
					};

					ctx.body = await token.issue({ use: 'introspection' });
					ctx.type = 'application/token-introspection+jwt; charset=utf-8';
				}
			} else {
				await next();
			}
		}
	];
}
