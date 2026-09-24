import { Elysia, t, type Static } from 'elysia';
import { UnauthorizedClient, UnsupportedGrantType } from '../helpers/errors.js';
import {
	cibaGrantParameters,
	codeGrantParameters,
	deviceCodeGrantParameters,
	executeGrant,
	hasGrant,
	refreshTokenGrantParameters
} from './grants/index.js';
import { refusedParam, routeNames } from 'lib/consts/param_list.js';
import {
	dpopValidate,
	setNonceHeader,
	validateReplay
} from 'lib/helpers/validate_dpop.js';
import {
	AuthPlugin,
	authHeaders,
	authParams,
	withBody
} from 'lib/plugins/auth.js';
import { corsClientBased, formClientId } from 'lib/plugins/cors.js';
import { ignoreUnknownParams } from 'lib/plugins/ignore_unknown_params.js';
import { OAuthError, TokenResponse } from 'lib/shared/response_schemas.js';
import { grantTypeAllowed } from 'lib/models/client.js';

const TokenRequestBody = t.Object({
	...authParams.properties,
	scope: t.Optional(t.String()),
	resource: t.Optional(t.String({ format: 'uri' })),
	/*
	 * Any string, not the set this server implements: RFC 6749 §5.2 answers a grant type the server
	 * does not support with `unsupported_grant_type`, and a closed schema turned it into
	 * `invalid_request` before the handler could say so. Only its absence is invalid_request.
	 */
	grant_type: t.String({ error: 'invalid grant_type' }),
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

/* What a grant handler may read off `oidc.params`, derived from the body the token endpoint validates. */
export type TokenParams = Static<typeof TokenRequestBody>;

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
			if (!hasGrant(grantType)) {
				throw new UnsupportedGrantType();
			}
			// RFC 6749 §5.2: a grant type the client is not registered for is unauthorized_client.
			if (!grantTypeAllowed(client, grantType)) {
				throw new UnauthorizedClient(
					'requested grant type is not allowed for this client'
				);
			}

			return executeGrant(grantType, withBody(oidc, body), dPoP);
		},
		{
			body: TokenRequestBody,
			headers: authHeaders,
			// Which members a success body carries depends on grant_type; see TokenResponse.
			response: {
				200: TokenResponse,
				400: OAuthError,
				401: OAuthError
			}
		}
	);
