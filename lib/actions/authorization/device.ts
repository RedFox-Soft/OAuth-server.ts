import paramsMiddleware from '../../shared/assemble_params.ts';
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
import { routeNames } from 'lib/consts/param_list.js';
import { Elysia } from 'elysia';
import { provider } from 'lib/provider.js';
import { InvalidRequest } from 'lib/helpers/errors.js';

const deviceAuthGrantType = 'urn:ietf:params:oauth:grant-type:device_code';
const backchannelAuthGrantType = 'urn:openid:params:grant-type:ciba';

async function authentication(ctx) {
	const { params: authParams, middleware: tokenAuth } = getTokenAuth(provider);
	paramsMiddleware.bind(undefined, authParams);
	tokenAuth.forEach((tokenAuthMiddleware) => {
		tokenAuthMiddleware;
	});

	if (!ctx.oidc.body.client_id) {
		ctx.oidc.body.client_id = ctx.oidc.client.clientId;
	}
}

export const deviceAuth = new Elysia().post(
	routeNames.device_authorization,
	async ({ body }) => {
		const ctx = { body };
		const OIDCContext = provider.OIDCContext;
		ctx.oidc = new OIDCContext(ctx);

		authentication;
		checkClient;
		const client = ctx.oidc.client;
		if (!client.grantTypeAllowed(deviceAuthGrantType)) {
			throw new InvalidRequest(
				`${deviceAuthGrantType} is not allowed for this client`
			);
		}
		processRequestObject.bind(undefined, allowList);
		assignDefaults;
		checkScope.bind(undefined, allowList);
		checkOpenidScope;
		checkClaims;
		unsupportedRar;
		checkResource;
		checkMaxAge;
		checkIdTokenHint;
		deviceAuthorizationResponse;
	}
);

export const backchannelAuth = new Elysia().post(
	routeNames.backchannel_authentication,
	async ({ body }) => {
		const ctx = { body };
		const OIDCContext = provider.OIDCContext;
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

		if (
			body.request === undefined &&
			client.backchannelAuthenticationRequestSigningAlg
		) {
			throw new InvalidRequest('Request Object must be used by this client');
		} else if (body.request !== undefined && isEncryptedJWT(body.request)) {
			throw new InvalidRequest(
				'Encrypted Request Objects are not supported by CIBA'
			);
		}

		processRequestObject.bind(undefined, allowList);
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
	}
);
