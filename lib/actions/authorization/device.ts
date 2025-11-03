import checkResource from '../../shared/check_resource.ts';
import getTokenAuth from '../../shared/token_auth.ts';

import checkClient from './check_client.ts';
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
import backchannelRequestRemapErrors from './backchannel_request_remap_errors.ts';
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
import { InvalidRequest } from 'lib/helpers/errors.js';
import { featureVerification } from './featureVerification.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

const deviceAuthGrantType = 'urn:ietf:params:oauth:grant-type:device_code';
const backchannelAuthGrantType = 'urn:openid:params:grant-type:ciba';

const DeviceRequest = t.Composite([
	t.Omit(DeviceAuthorizationParameters, ['request']),
	JWTparameters
]);

const BacckchannelRequest = t.Composite([
	t.Omit(BackchannelAuthParameters, ['request']),
	JWTparameters
]);

async function authentication(ctx) {
	const tokenAuth = getTokenAuth();
	tokenAuth.forEach((tokenAuthMiddleware) => {
		tokenAuthMiddleware;
	});

	if (!ctx.body.client_id) {
		ctx.body.client_id = ctx.oidc.client.clientId;
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

export const deviceAuth = new Elysia()
	.guard({
		body: DeviceAuthorizationParameters
	})
	.derive(({ body }) => {
		if (
			isRecord(body) &&
			'ui_locales' in body &&
			typeof body.ui_locales === 'string'
		) {
			body.ui_locales = [body.ui_locales];
		}
	})
	.resolve(({ body }) => {
		featureVerification(body);
	})
	.post(routeNames.device_authorization, async ({ body, server, request }) => {
		const ctx = { body };
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = { ...body };

		await authentication(ctx);
		await checkClient(ctx);
		const client = ctx.oidc.client;
		if (!client.grantTypeAllowed(deviceAuthGrantType)) {
			throw new InvalidRequest(
				`${deviceAuthGrantType} is not allowed for this client`
			);
		}
		await processRequestObject(DeviceRequest, ctx, {
			clientAlg: client.requestObjectSigningAlg
		});
		assignDefaults(ctx);
		checkScope(new Set(), ctx);
		checkOpenidScope(ctx);
		await checkClaims(ctx);
		unsupportedRar(ctx);
		await checkResource(ctx);
		checkMaxAge(ctx);
		await checkIdTokenHint(ctx);
		const deviceInfo = {
			ip: server?.requestIP(request),
			ua: request.headers.get('user-agent')
		};
		return deviceAuthorizationResponse(ctx, deviceInfo);
	});

export const backchannelAuth = new Elysia()
	.guard({
		body: BackchannelAuthParameters
	})
	.resolve(({ body }) => {
		featureVerification(body);
	})
	.post(routeNames.backchannel_authentication, async ({ body }) => {
		const ctx = { body };
		ctx.oidc = new OIDCContext(ctx);

		authentication;
		stripOutsideJarParams;
		const client = ctx.oidc.client;
		if (!client.grantTypeAllowed(backchannelAuthGrantType)) {
			throw new InvalidRequest(
				`${backchannelAuthGrantType} is not allowed for this client`
			);
		}
		backchannelRequestRemapErrors;

		if (body.request !== undefined && isEncryptedJWT(body.request)) {
			throw new InvalidRequest(
				'Encrypted Request Objects are not supported by CIBA'
			);
		}

		processRequestObject(BacckchannelRequest, ctx, {
			clientAlg: client.backchannelAuthenticationRequestSigningAlg
		});
		cibaRequired;
		assignDefaults;
		checkScope.bind(undefined, allowList);
		checkOpenidScope;
		checkClaims;
		unsupportedRar;
		checkResource;
		checkMaxAge;
		checkCibaContext;
		assignClaims;
		cibaLoadAccount;
		backchannelRequestResponse;
	});
