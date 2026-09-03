import { eventBus } from './event_bus.ts';
import * as errors from './helpers/errors.ts';
import * as interactionPolicy from './helpers/interaction_policy/index.ts';
// The CIBA counterpart to the triggerAuthenticationDevice addon: exported here because completing a
// backchannel request is something the deployment does, not the server.
import { backchannelResult } from './actions/authorization/backchannel_result.ts';

export default eventBus;
export { backchannelResult, errors, eventBus, interactionPolicy };

import { Elysia } from 'elysia';
import { staticPlugin } from '@elysiajs/static';

import { errorHandler } from './shared/authorization_error_handler.js';
import { nocache } from './plugins/noCache.js';
import { securityHeaders } from './plugins/securityHeaders.js';
import {
	authGet,
	authPost,
	par
} from './actions/authorization/authorization.js';
import { tokenAction } from './actions/token.js';
import { ui } from './interactions/index.js';
import { discovery } from './actions/discovery.js';
import { userinfo } from './actions/userinfo.js';
import { backchannelAuth, deviceAuth } from './actions/authorization/device.js';
import { codeVerification } from './actions/code_verification.js';
import { introspect } from './actions/introspection.js';
import { logoutAction, logoutConfirmAction } from './actions/end_session.js';
import { revocation } from './actions/revocation.js';
import { jwks } from './actions/jwks.js';
import { registration } from './actions/registration.js';
import { healthCheck } from './actions/health.js';
import { securityTxt } from './actions/security_txt.js';
import { featureGate } from './plugins/featureGate.js';
import { rateLimit } from './plugins/rateLimit.js';
import { corsPreflight } from './plugins/cors.js';
import { InvalidDpopProof, UseDpopNonce } from './helpers/validate_dpop.js';
import { adminApp } from './admin/index.js';
import { mcpApp } from './mcp/index.js';
import { verificationRoutes } from './routes/verification.js';
import { passwordResetRoutes } from './routes/password_reset.js';
/* Its own top-level instance because it cannot satisfy the `ui` guard: see lib/federation/routes.ts. */
import { federationRoutes } from './federation/routes.js';
import { initSentry } from './sentry/client.js';
import { reportStartupFailure } from './sentry/startup.js';

/*
 * Armed before the app is built, and deliberately not as a plugin.
 *
 * Nothing about the integration is mounted into Elysia: it registers no lifecycle hook, adds no
 * header, and sees no request. Faults reach it after the fact, from the one place the error store
 * records them. That is what keeps responses byte-identical and adds no latency — there is no code
 * on the request path to do either.
 *
 * It is armed here rather than lazily so that a fault raised while the routes below are being
 * constructed still has somewhere to go.
 */
initSentry();

export const elysia = new Elysia({ strictPath: true, normalize: false })
	.error({
		invalid_request: errors.InvalidRequest,
		invalid_client: errors.InvalidClient,
		invalid_client_auth: errors.InvalidClientAuth,
		invalid_client_metadata: errors.InvalidClientMetadata,
		invalid_token: errors.InvalidToken,
		invalid_scope: errors.InvalidScope,
		insufficient_scope: errors.InsufficientScope,
		invalid_grant: errors.InvalidGrant,
		invalid_redirect_uri: errors.InvalidRedirectUri,
		invalid_header_authorization: errors.InvalidHeaderAuthorization,
		invalid_request_object: errors.InvalidRequestObject,
		invalid_request_uri: errors.InvalidRequestUri,
		invalid_target: errors.InvalidTarget,
		invalid_authorization_details: errors.InvalidAuthorizationDetails,
		invalid_binding_message: errors.InvalidBindingMessage,
		invalid_user_code: errors.InvalidUserCode,
		invalid_software_statement: errors.InvalidSoftwareStatement,
		unapproved_software_statement: errors.UnapprovedSoftwareStatement,
		not_supported: errors.NotSupportedError,
		session_not_found: errors.SessionNotFound,
		access_denied: errors.AccessDenied,
		authorization_pending: errors.AuthorizationPending,
		consent_required: errors.ConsentRequired,
		expired_login_hint_token: errors.ExpiredLoginHintToken,
		expired_token: errors.ExpiredToken,
		interaction_required: errors.InteractionRequired,
		login_required: errors.LoginRequired,
		missing_user_code: errors.MissingUserCode,
		request_uri_not_supported: errors.RequestUriNotSupported,
		slow_down: errors.SlowDown,
		temporarily_unavailable: errors.TemporarilyUnavailable,
		transaction_failed: errors.TransactionFailed,
		unauthorized_client: errors.UnauthorizedClient,
		unknown_user_id: errors.UnknownUserId,
		unmet_authentication_requirements: errors.UnmetAuthenticationRequirements,
		unsupported_grant_type: errors.UnsupportedGrantType,
		unsupported_response_mode: errors.UnsupportedResponseMode,
		use_dpop_nonce: UseDpopNonce,
		invalid_dpop_proof: InvalidDpopProof,
		rate_limited: errors.RateLimited
	})
	.onError(errorHandler)
	.use(healthCheck)
	.use(securityTxt)
	.use(staticPlugin({ assets: 'public' }))
	.use(nocache)
	.use(securityHeaders)
	// Must follow nocache and securityHeaders for the same reason featureGate does, and must PRECEDE
	// featureGate — which is the ordering that looks like a performance detail and is actually a
	// correctness one. Were the gate to run first, a capability-disabled endpoint would answer 404
	// without ever being counted, while an unserved path would be counted and answer 429 under load:
	// the two become distinguishable, which is precisely the fingerprint featureGate exists to
	// eliminate. Counted first, both answer identically in both states.
	.use(rateLimit)
	// Must follow nocache and securityHeaders: onRequest hooks run in registration order and a gate
	// refusal throws, so gating first would skip the no-store and hardening headers every other
	// response carries.
	.use(featureGate)
	// Must follow both: it answers preflights by short-circuiting, which ends the onRequest chain, so
	// mounting it before nocache would omit no-store from the 204 and before featureGate would confirm
	// an endpoint whose capability is switched off.
	.use(corsPreflight)
	.use(discovery)
	.use(jwks)
	.use(authGet)
	.use(authPost)
	.use(deviceAuth)
	.use(codeVerification)
	.use(backchannelAuth)
	.use(par)
	.use(introspect)
	.use(revocation)
	.use(tokenAction)
	.use(registration)
	.use(logoutAction)
	.use(logoutConfirmAction)
	.use(userinfo)
	.use(ui)
	.use(verificationRoutes)
	.use(passwordResetRoutes)
	.use(federationRoutes)
	.use(adminApp)
	.use(mcpApp);

/*
 * Binding the port, and the one startup failure this module can report.
 *
 * The error is re-thrown, so what an operator sees on a failed boot is exactly what they saw before
 * this feature existed — the report is an addition to that, never a replacement for it, and nothing
 * here swallows or delays the failure beyond the reporter's own bounded flush.
 *
 * Deliberately not a process-level `uncaughtException` handler, which would have caught more. Adding
 * one stops the runtime terminating on an uncaught error, so the server would survive a boot failure
 * it used to die on — a change to startup behaviour the requirement forbids, traded for a wider net.
 *
 * The limit is worth stating: a failure raised while this module's *imports* evaluate — an
 * unusable configuration, an unreachable datastore — happens before this line and cannot be reported
 * from here. Those still surface only in the process output, as they always have.
 */
try {
	elysia.listen(3000);
} catch (error) {
	await reportStartupFailure(
		error instanceof Error ? error.name : 'unknown',
		'listen'
	);
	throw error;
}
