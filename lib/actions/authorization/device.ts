import checkResource from '../../shared/check_resource.ts';
import { tokenAuth } from '../../shared/token_auth.ts';
import { hostOfRequest } from 'lib/consts/request_host.js';
import { requestBucketFor } from 'lib/admin/auth/bucketAddress.js';
import checkBucket from './check_bucket.ts';
import { deviceInfo } from '../../addon/index.js';

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
	refusedParam,
	routeNames,
	BackchannelAuthParameters
} from 'lib/consts/param_list.js';
import { Elysia, t } from 'elysia';
import {
	InvalidRequest,
	InvalidRequestObject,
	RegistrationNotSupported,
	RequestNotSupported,
	RequestUriNotSupported,
	UnauthorizedClient
} from 'lib/helpers/errors.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { featureVerification } from './featureVerification.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import {
	authHeaders,
	authParams,
	type authParamsType
} from 'lib/plugins/auth.js';
import {
	coerceArrayParams,
	parseJsonParams
} from 'lib/plugins/coerce_array_params.js';
import { ignoreUnknownParams } from 'lib/plugins/ignore_unknown_params.js';
import { corsClientBased, formClientId } from 'lib/plugins/cors.js';
import {
	BackchannelAuthenticationResponse,
	DeviceAuthorizationResponse,
	OAuthError
} from 'lib/shared/response_schemas.js';
import { grantTypeAllowed } from 'lib/models/client.js';

const deviceAuthGrantType = 'urn:ietf:params:oauth:grant-type:device_code';
const backchannelAuthGrantType = 'urn:openid:params:grant-type:ciba';

// `request`/`request_uri` inside a Request Object is inception, refused rather than ignored — see
// the same declaration on the authorization endpoint.
const DeviceRequest = t.Object({
	...t.Omit(DeviceAuthorizationParameters, ['request']).properties,
	request: refusedParam('request'),
	request_uri: refusedParam('request_uri'),
	...JWTparameters.properties
});

// The request-object required-claim checks for CIBA (exp/iat/nbf/jti) are enforced by
// features.requestObjects.assertJwtClaimsAndHeader with precise error messages; the JWT param
// schema here is therefore relaxed to optional so a missing claim surfaces as invalid_request
// (400) rather than a generic schema validation error (422).
const BacckchannelRequest = t.Object({
	...t.Omit(BackchannelAuthParameters, ['request']).properties,
	request: refusedParam('request'),
	request_uri: refusedParam('request_uri'),
	...t.Partial(JWTparameters).properties
});

const DeviceAuthorizationBody = t.Object({
	...authParams.properties,
	...DeviceAuthorizationParameters.properties
});

const BackchannelAuthenticationBody = t.Object({
	...authParams.properties,
	...t.Omit(BackchannelAuthParameters, ['registration']).properties,
	request_uri: t.Optional(t.String()),
	registration: t.Optional(t.String())
});

/*
 * Both endpoints are mounted beneath every bucket's address, and what they store records the bucket
 * the flow was started at — the token issued from it later carries that bucket's issuer. So the
 * address is resolved here, as every other prefixed endpoint does, rather than left to the default.
 */
function bucketOf(params: unknown, request: Request) {
	return requestBucketFor(
		(params as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

async function authentication(
	params: authParamsType,
	headers: Record<string, string | undefined>,
	oidc: OIDCContext<PipelineParams>
) {
	await tokenAuth(params, headers, oidc);

	// params is the request body object here; setting client_id on it preserves prior behaviour
	if (!params.client_id) {
		params.client_id = oidc.client.clientId;
		oidc.params.client_id = oidc.client.clientId;
	}
}

/*
 * `deviceAuth` is the browser-facing half of this module; `backchannelAuth` below is not, and gets no
 * CORS — CIBA is initiated by the client's own backend by construction. The hook precedes the guard so
 * the header is written before body-schema validation can reject the request.
 */
export const deviceAuth = new Elysia()
	.use(corsClientBased(formClientId))
	.use(ignoreUnknownParams(DeviceAuthorizationBody))
	.use(coerceArrayParams('resource'))
	.use(parseJsonParams('authorization_details'))
	.guard({
		body: DeviceAuthorizationBody,
		headers: authHeaders
	})
	.resolve(({ body }) => {
		featureVerification(body);
	})
	.post(
		routeNames.device_authorization,
		async ({ body, headers, params, server, request }) => {
			const oidc = new OIDCContext({
				params: body,
				headers,
				bucket: await bucketOf(params, request),
				ip: server?.requestIP(request)?.address
			});

			await authentication(body, headers, oidc);
			const client = oidc.client;
			// RFC 8628 §3.2 answers with the token endpoint's errors (RFC 6749 §5.2): unauthorized_client.
			if (!grantTypeAllowed(client, deviceAuthGrantType)) {
				throw new UnauthorizedClient(
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
			/* Once the address is honoured the refusal has to come with it — see `checkBucket`. */
			await checkBucket(oidc);
			checkMaxAge(oidc);
			await checkIdTokenHint(oidc);
			return deviceAuthorizationResponse(oidc, deviceInfo(oidc));
		},
		{
			response: {
				200: DeviceAuthorizationResponse,
				400: OAuthError,
				401: OAuthError,
				500: OAuthError
			}
		}
	);

export const backchannelAuth = new Elysia()
	.use(ignoreUnknownParams(BackchannelAuthenticationBody))
	.use(coerceArrayParams('resource'))
	.use(parseJsonParams('authorization_details'))
	.guard({
		// request_uri and registration are accepted by the schema so the handler can reject them
		// with the OIDC-specified `<param>_not_supported` errors rather than a generic 422.
		// registration is otherwise typed as `t.Undefined` upstream, so it is omitted first.
		body: BackchannelAuthenticationBody,
		headers: authHeaders
	})
	.post(
		routeNames.backchannel_authentication,
		async ({ body, headers, params, request }) => {
			const contentType = request.headers.get('content-type') || '';
			if (!contentType.includes('application/x-www-form-urlencoded')) {
				throw new InvalidRequest(
					'only application/x-www-form-urlencoded content-type bodies are supported on POST /backchannel'
				);
			}

			const oidc = new OIDCContext({
				params: body,
				headers,
				route: 'backchannel_authentication',
				bucket: await bucketOf(params, request)
			});

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

			// CIBA Core §13: unauthorized_client for a client not allowed this authentication flow.
			if (!grantTypeAllowed(client, backchannelAuthGrantType)) {
				throw new UnauthorizedClient(
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
				await checkBucket(oidc);
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
				401: OAuthError,
				500: OAuthError
			}
		}
	);
