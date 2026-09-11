import { Elysia, t } from 'elysia';
import { InvalidRequest } from '../helpers/errors.js';
import {
	cibaGrantParameters,
	codeGrantParameters,
	deviceCodeGrantParameters,
	executeGrant,
	grantTypeSchema,
	refreshTokenGrantParameters
} from './grants/index.js';
import { refusedParam, routeNames } from 'lib/consts/param_list.js';
import {
	dpopValidate,
	setNonceHeader,
	validateReplay
} from 'lib/helpers/validate_dpop.js';
import { AuthPlugin, authHeaders, authParams } from 'lib/plugins/auth.js';
import { corsClientBased, formClientId } from 'lib/plugins/cors.js';
import { ignoreUnknownParams } from 'lib/plugins/ignore_unknown_params.js';
import { TokenResponse } from 'lib/shared/response_schemas.js';

const TokenRequestBody = t.Object({
	...authParams.properties,
	scope: t.Optional(t.String()),
	resource: t.Optional(t.String({ format: 'uri' })),
	// Literal union of the grant types the project supports (single source of truth in
	// grants/index.ts). A proper literal union — not a `keys().map(t.Literal)` array,
	// whose TypeBox static type collapses to `never` and makes the handler fail Elysia's
	// InlineHandlerNonMacro check (which is what previously blocked the `response` map).
	grant_type: grantTypeSchema,
	...t.Partial(codeGrantParameters).properties,
	...t.Partial(refreshTokenGrantParameters).properties,
	...t.Partial(deviceCodeGrantParameters).properties,
	...t.Partial(cibaGrantParameters).properties,
	/*
	 * RFC 9396 §7 defines authorization_details here as a way for a client to *narrow* the grant it
	 * is exchanging. This server does not implement that, and ignoring it would hand back a token
	 * broader than the one the client asked for, without saying so. Declared absent so it is refused.
	 */
	authorization_details: refusedParam('authorization_details')
});

// The CORS hook must precede AuthPlugin: AuthPlugin authenticates the client in a `derive`, which runs
// in the same transform queue and throws `invalid_client` from there. Registered after it, this hook
// would never run for a wrong-secret 401 — the response a misconfigured browser app sees most often.
export const tokenAction = new Elysia()
	.use(corsClientBased(formClientId))
	.use(ignoreUnknownParams(TokenRequestBody))
	.use(AuthPlugin)
	.post(
		routeNames.token,
		async ({ body, headers, route, set, oidc }) => {
			const client = oidc.client;
			const dPoP = await dpopValidate(headers.dpop, { route });
			setNonceHeader(set.headers, dPoP);
			await validateReplay(client.clientId, dPoP);

			const grantType = body.grant_type;
			if (!client.grantTypeAllowed(grantType)) {
				throw new InvalidRequest(
					'requested grant type is not allowed for this client'
				);
			}

			return executeGrant(grantType, oidc, dPoP);
		},
		{
			body: TokenRequestBody,
			headers: authHeaders,
			// Success body varies by grant_type (access-token-only for client_credentials, +id_token/
			// refresh_token for the code/device/ciba flows). Modelled as a grant-dependent union in
			// TokenResponse. See contracts/endpoint-responses.md.
			response: TokenResponse
		}
	);
