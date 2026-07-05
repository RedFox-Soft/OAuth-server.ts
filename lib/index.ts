import { provider } from './provider.ts';
import * as errors from './helpers/errors.ts';
import * as interactionPolicy from './helpers/interaction_policy/index.ts';

export default provider;
export { errors, interactionPolicy, provider };

import { Elysia } from 'elysia';
import { staticPlugin } from '@elysiajs/static';

import { errorHandler } from './shared/authorization_error_handler.js';
import { nocache } from './plugins/noCache.js';
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
import { introspect } from './actions/introspection.js';
import { logoutAction, logoutConfirmAction } from './actions/end_session.js';
import { revocation } from './actions/revocation.js';
import { jwks } from './actions/jwks.js';
import { healthCheck } from './actions/health.js';
import { InvalidDpopProof, UseDpopNonce } from './helpers/validate_dpop.js';

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
		invalid_dpop_proof: InvalidDpopProof
	})
	.onError(errorHandler)
	.use(healthCheck)
	.use(staticPlugin({ assets: 'public' }))
	.use(nocache)
	.use(discovery)
	.use(jwks)
	.use(authGet)
	.use(authPost)
	.use(deviceAuth)
	.use(backchannelAuth)
	.use(par)
	.use(introspect)
	.use(revocation)
	.use(tokenAction)
	.use(logoutAction)
	.use(logoutConfirmAction)
	.use(userinfo)
	.use(ui)
	.listen(3000);
