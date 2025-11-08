import { InvalidRequest } from '../helpers/errors.ts';
import presence from '../helpers/validate_presence.ts';
import instance from '../helpers/weak_cache.ts';
import { tokenAuth } from '../shared/token_auth.ts';
import { urlencoded as parseBody } from '../shared/selective_body.ts';
import paramsMiddleware from '../shared/assemble_params.ts';
import revoke from '../helpers/revoke.ts';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AccessToken } from 'lib/models/access_token.js';

const revokeable = new Set([
	'AccessToken',
	'ClientCredentials',
	'RefreshToken'
]);

export default async function revocationAction(provider) {
	await tokenAuth(params, headers, ctx);
	const PARAM_LIST = new Set(['token', 'token_type_hint']);
	const { grantTypeHandlers } = instance(provider);

	function getAccessToken(token) {
		return AccessToken.find(token);
	}

	function getClientCredentials(token) {
		if (!grantTypeHandlers.has('client_credentials')) {
			return undefined;
		}
		return provider.ClientCredentials.find(token);
	}

	function getRefreshToken(token) {
		if (!grantTypeHandlers.has('refresh_token')) {
			return undefined;
		}
		return RefreshToken.find(token);
	}

	function findResult(results) {
		return results.find((found) => !!found);
	}

	return [
		parseBody,
		paramsMiddleware.bind(undefined, PARAM_LIST),

		async function validateTokenPresence(ctx, next) {
			presence(ctx, 'token');
			await next();
		},

		async function renderTokenResponse(ctx, next) {
			ctx.status = 200;
			ctx.body = '';
			await next();
		},

		async function revokeToken(ctx) {
			let token;
			const { params } = ctx.oidc;

			switch (params.token_type_hint) {
				case 'access_token':
				case 'urn:ietf:params:oauth:token-type:access_token':
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
				case 'urn:ietf:params:oauth:token-type:refresh_token':
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

			if (!token) return;

			if (revokeable.has(token.kind)) {
				ctx.oidc.entity(token.kind, token);
			} else {
				return;
			}

			if (token.clientId !== ctx.oidc.client.clientId) {
				throw new InvalidRequest('this token does not belong to you');
			}

			await token.destroy();

			if (token.kind === 'RefreshToken' || token.kind === 'AccessToken') {
				await revoke(ctx, token.grantId);
			}
		}
	];
}
