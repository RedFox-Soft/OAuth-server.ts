import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { TokenParams } from 'lib/actions/token.js';
import { t } from 'elysia';
import { UnsupportedGrantType } from 'lib/helpers/errors.js';
import { eventBus } from 'lib/event_bus.js';
import { noteActivity } from 'lib/activity/note.js';
import { noteClientUse } from 'lib/models/client/usage.js';
import { TokenResponse } from 'lib/shared/response_schemas.js';

// Body every grant handler resolves to (RFC 6749 §5.1), varying by grant_type — see TokenResponse.
type TokenResponseBody = (typeof TokenResponse)['static'];

export const codeGrantParameters = t.Object({
	code: t.String(),
	redirect_uri: t.Optional(t.String()),
	/*
	 * `43*128unreserved`, the whole of what RFC 7636 §4.1 defines — both halves of it, which this
	 * pattern has now had to learn twice.
	 *
	 * The length came first: the challenge is 43 characters because it is a SHA-256 digest, while the
	 * verifier is whatever length in 43..128 the client chose, and a client picking 64 or 86 is
	 * conformant. The alphabet is the same mistake one level down. `[A-Za-z0-9_-]` is base64url, which
	 * is how the *challenge* is encoded and how this project happens to generate verifiers; §4.1 says
	 * `unreserved` from RFC 3986 §2.3, which also admits `.` and `~`. A verifier is an opaque string
	 * the client chose, so its alphabet is the RFC's to fix and not ours.
	 *
	 * Both survived for one reason, and it is worth stating because it will recur: this server cannot
	 * trip over itself here. Every verifier the project produces is 43 base64url characters —
	 * lib/admin/auth/login.ts derives one from 32 random bytes, test/AuthorizationRequest.ts does the
	 * same — so nothing in the suite ever presented a conformant verifier this pattern refused.
	 *
	 * A refusal here lands before the grant runs, so a mathematically correct verifier could not
	 * redeem its code, and PKCE is mandatory: such a client cannot use the authorization code grant
	 * at all.
	 */
	code_verifier: t.String({ pattern: '^[A-Za-z0-9\\-._~]{43,128}$' })
});

export const refreshTokenGrantParameters = t.Object({
	refresh_token: t.String()
});

export const deviceCodeGrantParameters = t.Object({
	device_code: t.String()
});

export const cibaGrantParameters = t.Object({
	auth_req_id: t.String()
});

/* RFC 7523 §2.1: a single JWT. Whether it is one is the grant's to answer, as invalid_grant. */
export const jwtBearerGrantParameters = t.Object({
	assertion: t.String()
});

/*
 * RFC 8693 §2.1. `actor_token` is declared, not refused with `refusedParam`: refusing it here would refuse it
 * on every grant, while RFC 6749 §3.2 has the others ignore it, and the exchange must be able to see it was
 * sent to refuse it (ID-JAG §4.3 defines no processing for it). `audience` may repeat, as `resource` does,
 * so the exchange can refuse more than one rather than read the first.
 */
export const tokenExchangeGrantParameters = t.Object({
	subject_token: t.String(),
	subject_token_type: t.String(),
	requested_token_type: t.String(),
	audience: t.Union([t.String(), t.Array(t.String())]),
	actor_token: t.String(),
	actor_token_type: t.String()
});

export * as authorization_code from './authorization_code.ts';
export * as refresh_token from './refresh_token.ts';
export * as 'urn:ietf:params:oauth:grant-type:device_code' from './device_code.ts';
export * as 'urn:openid:params:grant-type:ciba' from './ciba.ts';

import * as authorization_code from './authorization_code.ts';
import { clientCredentials } from './client_credentials.ts';
import { jwtBearer } from './jwt_bearer.ts';
import { tokenExchange } from './token_exchange.ts';
import {
	JWT_BEARER_GRANT,
	JWT_DPOP_GRANT,
	TOKEN_EXCHANGE_GRANT
} from 'lib/consts/assertion_grants.js';
import * as refresh_token from './refresh_token.ts';
import * as device_code from './device_code.ts';
import * as ciba from './ciba.ts';
import { ApplicationConfig as config } from 'lib/configs/application.js';
import { supportedGrantTypes } from 'lib/configs/discoverySupport.js';
import type { DPoPProof } from 'lib/helpers/validate_dpop.js';

// Grant handlers always resolve to the grant-dependent token response body. No handler returns a
// raw `Response`; the /token route relies on this so its `response` schema is TokenResponse.
type GrantHandler = (
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
) => Promise<TokenResponseBody>;

export const grantStore: Map<string, GrantHandler> = new Map([
	['authorization_code', authorization_code.handler],
	['client_credentials', clientCredentials],
	['refresh_token', refresh_token.handler],
	['urn:ietf:params:oauth:grant-type:device_code', device_code.handler],
	['urn:openid:params:grant-type:ciba', ciba.handler],
	[JWT_BEARER_GRANT, jwtBearer],
	[JWT_DPOP_GRANT, jwtBearer],
	[TOKEN_EXCHANGE_GRANT, tokenExchange]
]);

// Read from the same derivation discovery advertises, never a second table of flags: two lists
// agreed on the optional grants and disagreed on refresh_token, which was processed while unadvertised.
export function hasGrant(grantType: string): boolean {
	return (
		grantStore.has(grantType) && supportedGrantTypes(config).includes(grantType)
	);
}

export async function executeGrant(
	grantType: string,
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
): Promise<TokenResponseBody> {
	const grant = grantStore.get(grantType);
	if (!grant || !hasGrant(grantType)) {
		throw new UnsupportedGrantType();
	}
	const res: TokenResponseBody = await grant(oidc, dPoP);
	/*
	 * The one place activity is recorded: every token issued on a person's behalf is minted by a grant that
	 * resolves here. Synchronous and never failing — see lib/activity/note.ts for why it is a call, not a
	 * listener on the event below.
	 */
	noteActivity(oidc);
	// Beside it, for the same reasons: the application's own "last used" (spec 107), never awaited.
	noteClientUse(oidc.entities.Client?.clientId);
	eventBus.emit('grant.success', oidc);
	return res;
}
