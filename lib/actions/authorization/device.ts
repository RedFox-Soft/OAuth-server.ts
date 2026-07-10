import checkResource from '../../shared/check_resource.ts';
import { tokenAuth } from '../../shared/token_auth.ts';

import processRequestObject, {
	isEncryptedJWT
} from './process_request_object.ts';
import cibaRequired from './ciba_required.ts';
import checkMaxAge from './check_max_age.ts';
import checkIdTokenHint from './check_id_token_hint.ts';
import checkScope from './check_scope.ts';
import assignDefaults from './assign_defaults.ts';
import checkClaims from './check_claims.ts';
import assignClaims from './assign_claims.ts';
import checkOpenidScope from './check_openid_scope.ts';
import deviceAuthorizationResponse from './device_authorization_response.ts';
import stripOutsideJarParams from './strip_outside_jar_params.ts';
import cibaLoadAccount from './ciba_load_account.ts';
import backchannelRequestResponse from './backchannel_request_response.ts';
import checkCibaContext from './check_ciba_context.ts';
import unsupportedRar from './unsupported_rar.ts';
import {
	DeviceAuthorizationParameters,
	JWTparameters,
	routeNames,
	BackchannelAuthParameters
} from 'lib/consts/param_list.js';
import { Elysia, t } from 'elysia';
import {
	InvalidRequest,
	InvalidRequestObject,
	RegistrationNotSupported,
	RequestNotSupported,
	RequestUriNotSupported
} from 'lib/helpers/errors.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { featureVerification } from './featureVerification.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { authHeaders, authParams } from 'lib/plugins/auth.js';
import { coerceArrayParams } from 'lib/plugins/coerce_array_params.js';
import {
	BackchannelAuthenticationResponse,
	DeviceAuthorizationResponse,
	OAuthError
} from 'lib/shared/response_schemas.js';

const deviceAuthGrantType = 'urn:ietf:params:oauth:grant-type:device_code';
const backchannelAuthGrantType = 'urn:openid:params:grant-type:ciba';

const DeviceRequest = t.Composite([
	t.Omit(DeviceAuthorizationParameters, ['request']),
	JWTparameters
]);

// The request-object required-claim checks for CIBA (exp/iat/nbf/jti) are enforced by
// features.requestObjects.assertJwtClaimsAndHeader with precise error messages; the JWT param
// schema here is therefore relaxed to optional so a missing claim surfaces as invalid_request
// (400) rather than a generic schema validation error (422).
const BacckchannelRequest = t.Composite([
	t.Omit(BackchannelAuthParameters, ['request']),
	t.Partial(JWTparameters)
]);

async function authentication(params, headers, oidc) {
	await tokenAuth(params, headers, oidc);

	// params is the request body object here; setting client_id on it preserves prior behaviour
	if (!params.client_id) {
		params.client_id = oidc.client.clientId;
		oidc.params.client_id = oidc.client.clientId;
	}
}

export const deviceAuth = new Elysia()
	.use(coerceArrayParams('ui_locales', 'resource'))
	.guard({
		body: t.Composite([authParams, DeviceAuthorizationParameters]),
		headers: authHeaders
	})
	.resolve(({ body }) => {
		featureVerification(body);
	})
	.post(
		routeNames.device_authorization,
		async ({ body, headers, server, request }) => {
			const oidc = new OIDCContext(body, headers);

			await authentication(body, headers, oidc);
			const client = oidc.client;
			if (!client.grantTypeAllowed(deviceAuthGrantType)) {
				throw new InvalidRequest(
					`${deviceAuthGrantType} is not allowed for this client`
				);
			}
			await processRequestObject(DeviceRequest, oidc);
			assignDefaults(oidc);
			checkScope(oidc);
			checkOpenidScope(oidc);
			await checkClaims(oidc);
			unsupportedRar(oidc);
			await checkResource(oidc);
			checkMaxAge(oidc);
			await checkIdTokenHint(oidc);
			const deviceInfo = {
				ip: server?.requestIP(request),
				ua: request.headers.get('user-agent')
			};
			return deviceAuthorizationResponse(oidc, deviceInfo);
		},
		{
			response: {
				200: DeviceAuthorizationResponse,
				400: OAuthError,
				401: OAuthError
			}
		}
	);

export const backchannelAuth = new Elysia()
	.use(coerceArrayParams('ui_locales', 'resource'))
	.guard({
		// request_uri and registration are accepted by the schema so the handler can reject them
		// with the OIDC-specified `<param>_not_supported` errors rather than a generic 422.
		// registration is otherwise typed as `t.Undefined` upstream, so it is omitted first.
		body: t.Composite([
			authParams,
			t.Omit(BackchannelAuthParameters, ['registration']),
			t.Object({
				request_uri: t.Optional(t.String()),
				registration: t.Optional(t.String())
			})
		]),
		headers: authHeaders
	})
	.post(
		routeNames.backchannel_authentication,
		async ({ body, headers, request }) => {
			const contentType = request.headers.get('content-type') || '';
			if (!contentType.includes('application/x-www-form-urlencoded')) {
				throw new InvalidRequest(
					'only application/x-www-form-urlencoded content-type bodies are supported on POST /backchannel'
				);
			}

			const oidc = new OIDCContext(body, headers, 'backchannel_authentication');

			await authentication(body, headers, oidc);
			const client = oidc.client;

			// CIBA does not accept request_uri or registration; request (JAR) is only
			// accepted when Request Objects are enabled. These carry endpoint-specific
			// error codes rather than the generic feature-verification message.
			if (oidc.params.request_uri !== undefined) {
				throw new RequestUriNotSupported();
			}
			if (oidc.params.registration !== undefined) {
				throw new RegistrationNotSupported();
			}
			if (
				oidc.params.request !== undefined &&
				!ApplicationConfig['requestObjects.enabled']
			) {
				throw new RequestNotSupported();
			}

			featureVerification(oidc.params);

			stripOutsideJarParams(oidc);

			if (!client.grantTypeAllowed(backchannelAuthGrantType)) {
				throw new InvalidRequest(
					`${backchannelAuthGrantType} is not allowed for this client`
				);
			}

			try {
				if (
					oidc.params.request !== undefined &&
					isEncryptedJWT(oidc.params.request)
				) {
					throw new InvalidRequest(
						'Encrypted Request Objects are not supported by CIBA'
					);
				}

				await processRequestObject(BacckchannelRequest, oidc, {
					clientAlg: client['requestObject.backChannelSigningAlg']
				});
				cibaRequired(oidc);
				assignDefaults(oidc);
				checkScope(oidc);
				checkOpenidScope(oidc);
				await checkClaims(oidc);
				unsupportedRar(oidc);
				await checkResource(oidc);
				checkMaxAge(oidc);
				await checkCibaContext(oidc);
				assignClaims(oidc);
				await cibaLoadAccount(oidc);

				return backchannelRequestResponse(oidc);
			} catch (err) {
				// Remaps request-object errors thrown by downstream steps to invalid_request,
				// preserving the description (former backchannel_request_remap_errors).
				if (err instanceof InvalidRequestObject) {
					Object.assign(err, {
						message: 'invalid_request',
						error: 'invalid_request'
					});
				}
				throw err;
			}
		},
		{
			response: {
				200: BackchannelAuthenticationResponse,
				400: OAuthError,
				401: OAuthError
			}
		}
	);
