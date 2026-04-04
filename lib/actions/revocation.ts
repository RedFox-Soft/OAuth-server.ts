import { Elysia, t } from 'elysia';
import { InvalidRequest } from '../helpers/errors.js';
import revoke from '../helpers/revoke.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AccessToken } from 'lib/models/access_token.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import { hasGrant } from './grants/index.js';
import { routeNames } from 'lib/consts/param_list.js';
import { authHeaders, AuthPlugin } from 'lib/plugins/auth.js';

const revokeable = new Set([
	'AccessToken',
	'ClientCredentials',
	'RefreshToken'
]);

const uriMapTypes: Record<string, string> = {
	'urn:ietf:params:oauth:token-type:access_token': 'access_token',
	'urn:ietf:params:oauth:token-type:refresh_token': 'refresh_token'
};

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
type TokenType = keyof typeof tokenTypes;

function isTokenType(type?: string): type is TokenType {
	if (type === undefined) {
		return false;
	}
	const tType = type in uriMapTypes ? uriMapTypes[type] : type;
	return tType in tokenTypes;
}

export const revocation = new Elysia().use(AuthPlugin).post(
	routeNames.revocation,
	async function ({ body: params, oidc }) {
		const ctx = { oidc };

		let token: AccessToken | RefreshToken | ClientCredentials | undefined;

		if (isTokenType(params.token_type_hint)) {
			const methodToken = tokenTypes[params.token_type_hint];
			token = await methodToken(params.token);
			if (!token) {
				const otherMethods = (Object.keys(tokenTypes) as TokenType[])
					.filter((type) => type !== params.token_type_hint)
					.map((type) => tokenTypes[type](params.token));
				token = (await Promise.all(otherMethods)).find((t) => t);
			}
		} else {
			token = (
				await Promise.all(
					Object.values(tokenTypes).map((fn) => fn(params.token))
				)
			).find((t) => t);
		}

		if (!token) {
			return;
		}

		if (!revokeable.has(token.payload.kind)) {
			return;
		}
		ctx.oidc.entity(token.payload.kind, token);

		if (token.payload.clientId !== ctx.oidc.client.clientId) {
			throw new InvalidRequest('this token does not belong to you');
		}

		await token.destroy();

		if (
			token.payload.kind === 'RefreshToken' ||
			token.payload.kind === 'AccessToken'
		) {
			await revoke(ctx, token.payload.grantId);
		}
	},
	{
		body: t.Object({
			token: t.String(),
			token_type_hint: t.Optional(t.String())
		}),
		headers: authHeaders
	}
);
