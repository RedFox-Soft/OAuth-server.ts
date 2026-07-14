import { Elysia, t } from 'elysia';
import { InvalidRequest } from '../helpers/errors.js';
import revoke from '../helpers/revoke.js';
import { routeNames } from 'lib/consts/param_list.js';
import { authHeaders, AuthPlugin, authParams } from 'lib/plugins/auth.js';
import { findToken } from '../shared/findToken.js';
import { OAuthError } from 'lib/shared/response_schemas.js';

const revokeable = new Set([
	'AccessToken',
	'ClientCredentials',
	'RefreshToken'
]);

export const revocation = new Elysia().use(AuthPlugin).post(
	routeNames.revocation,
	async function ({ body: params, oidc }) {
		const token = await findToken(params.token, params.token_type_hint);
		if (!token) {
			return;
		}

		if (!revokeable.has(token.payload.kind)) {
			return;
		}
		oidc.entity(token.payload.kind, token);

		if (token.payload.clientId !== oidc.client.clientId) {
			throw new InvalidRequest('this token does not belong to you');
		}

		await token.destroy();

		if (
			token.payload.kind === 'RefreshToken' ||
			token.payload.kind === 'AccessToken'
		) {
			await revoke(oidc, token.payload.grantId);
		}
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
			200: t.Void(),
			400: OAuthError,
			401: OAuthError
		}
	}
);
