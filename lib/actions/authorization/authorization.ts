import { Elysia, t, ValidationError } from 'elysia';

import checkRar from '../../shared/check_rar.ts';
import checkResource from '../../shared/check_resource.ts';

import checkClient from './check_client.ts';
import checkResponseMode from './check_response_mode.ts';
import oneRedirectUriClients from './one_redirect_uri_clients.ts';
import loadPushedAuthorizationRequest from './load_pushed_authorization_request.ts';
import processRequestObject from './process_request_object.ts';
import checkPrompt from './check_prompt.ts';
import checkMaxAge from './check_max_age.ts';
import checkIdTokenHint from './check_id_token_hint.ts';
import checkScope from './check_scope.ts';
import checkResponseType from './check_response_type.ts';
import checkRedirectUri from './check_redirect_uri.ts';
import assignDefaults from './assign_defaults.ts';
import checkClaims from './check_claims.ts';
import assignClaims from './assign_claims.ts';
import loadAccount from './load_account.ts';
import loadGrant from './load_grant.ts';
import interactions from './interactions.ts';
import respond from './respond.ts';
import checkOpenidScope from './check_openid_scope.ts';
import stripOutsideJarParams from './strip_outside_jar_params.ts';
import pushedAuthorizationRequestResponse from './pushed_authorization_request_response.ts';
import presence from '../../helpers/validate_presence.ts';

import {
	AuthorizationCookies,
	AuthorizationParameters,
	JWTparameters,
	routeNames
} from '../../consts/param_list.ts';
import sessionHandler from '../../shared/session.ts';
import { noQueryDup } from 'lib/plugins/noQueryDup.js';
import { coerceArrayParams } from 'lib/plugins/coerce_array_params.js';
import { featureVerification } from './featureVerification.js';
import { authorizationPKCE } from 'lib/helpers/pkce.js';
import {
	InvalidClient,
	InvalidRedirectUri,
	InvalidRequest,
	OIDCProviderError
} from 'lib/helpers/errors.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Client } from 'lib/models/client.js';
import {
	dpopValidate,
	setNonceHeader,
	validateReplay
} from 'lib/helpers/validate_dpop.js';
import {
	authHeaders,
	authParams,
	AuthPlugin,
	withBody
} from 'lib/plugins/auth.js';
import {
	OAuthError,
	ParResponse,
	RedirectOrHtmlResponse
} from 'lib/shared/response_schemas.js';

const authorizationRequest = t.Composite([
	t.Omit(AuthorizationParameters, ['request_uri', 'request', 'client_id']),
	t.Object({
		client_id: t.Optional(t.String())
	}),
	JWTparameters
]);

export async function isAllowRedirectUri(params) {
	const oidc = new OIDCContext(params);

	const client = await Client.find(params.client_id, {
		error: new InvalidClient('client is invalid', 'client not found')
	});
	oidc.entity('Client', client);
	try {
		await processRequestObject(authorizationRequest, oidc);
	} catch (e) {
		if (!(e instanceof OIDCProviderError) && !(e instanceof ValidationError)) {
			throw e;
		}
	}

	let redirect_uri = params.redirect_uri;
	if (redirect_uri === undefined) {
		oneRedirectUriClients(oidc);
		redirect_uri = params.redirect_uri;
	}
	if (typeof redirect_uri !== 'string') {
		throw new InvalidRedirectUri();
	}
	if (!client.redirectUriAllowed(redirect_uri)) {
		throw new InvalidRedirectUri();
	}

	const state = typeof params.state !== 'string' ? undefined : params.state;

	return { redirect_uri, state, oidc };
}

async function authorizationActionHandler(oidc) {
	const setCookies = await sessionHandler(oidc);
	await checkClient(oidc);

	const pushedAuthorizationRequest = await loadPushedAuthorizationRequest(oidc);
	const requestOptions = {
		trusted: false,
		isPar: false
	};
	if (pushedAuthorizationRequest) {
		requestOptions.isPar = true;
		requestOptions.trusted = pushedAuthorizationRequest.trusted;
	}
	await processRequestObject(authorizationRequest, oidc, requestOptions);
	checkResponseMode(oidc);
	oneRedirectUriClients(oidc);
	presence(oidc, 'response_type', 'redirect_uri');
	checkResponseType(oidc);
	assignDefaults(oidc);
	checkPrompt(oidc);
	checkScope(oidc, true);
	checkOpenidScope(oidc);
	checkRedirectUri(oidc);
	authorizationPKCE(oidc.params);
	await checkClaims(oidc);
	await checkRar(oidc);
	await checkResource(oidc);
	checkMaxAge(oidc);
	await checkIdTokenHint(oidc);
	assignClaims(oidc);
	await loadAccount(oidc);
	await loadGrant(oidc);
	const redirectUri = await interactions('resume', oidc);
	if (redirectUri) {
		await setCookies();
		return Response.redirect(redirectUri, 303);
	}
	const response = await respond(oidc);
	await setCookies();

	return response;
}

export const authGet = new Elysia()
	.derive(noQueryDup(['resource', 'ui_locales', 'authorization_details']))
	.guard({
		query: AuthorizationParameters,
		cookie: AuthorizationCookies
	})
	.resolve(({ query }) => {
		featureVerification(query);
	})
	.get(
		routeNames.authorization,
		async ({ query, cookie, route, request }) => {
			const url = new URL(request.url);
			url.search = url.pathname = '';

			const oidc = new OIDCContext(query, {}, route);
			oidc.cookie = cookie;
			oidc.baseUrl = url.toString();

			return await authorizationActionHandler(oidc);
		},
		{
			response: { 200: RedirectOrHtmlResponse, 400: OAuthError }
		}
	);

export const authPost = new Elysia()
	.use(coerceArrayParams('ui_locales', 'resource'))
	.guard({
		body: AuthorizationParameters,
		cookie: AuthorizationCookies
	})
	.resolve(({ body }) => {
		featureVerification(body);
	})
	.post(
		routeNames.authorization,
		async ({ body, cookie, route, request }) => {
			const url = new URL(request.url);
			url.search = '';
			url.pathname = url.pathname.replace(route, '');

			const oidc = new OIDCContext(body, {}, route);
			oidc.cookie = cookie;
			oidc.baseUrl = url.toString();

			return await authorizationActionHandler(oidc);
		},
		{
			response: { 200: RedirectOrHtmlResponse, 400: OAuthError }
		}
	);

export const par = new Elysia()
	.use(AuthPlugin)
	.guard({
		body: t.Composite([
			t.Omit(AuthorizationParameters, ['request_uri', 'client_id']),
			authParams
		]),
		headers: authHeaders
	})
	.resolve(({ body }) => {
		featureVerification(body);
	})
	.post(
		routeNames.pushed_authorization_request,
		async ({ body, headers, set, oidc: oidcInc }) => {
			const oidc = withBody(oidcInc, body);

			stripOutsideJarParams(oidc);
			const client = oidc.client;

			const request = await processRequestObject(authorizationRequest, oidc);
			checkResponseMode(oidc);
			oneRedirectUriClients(oidc);
			presence(oidc, 'response_type', 'redirect_uri');
			checkResponseType(oidc);
			checkPrompt(oidc);
			checkScope(oidc, true);
			checkOpenidScope(oidc);
			checkRedirectUri(oidc);
			authorizationPKCE(oidc.params);
			await checkClaims(oidc);
			await checkRar(oidc);
			await checkResource(oidc);
			await checkIdTokenHint(oidc);

			// DPOP Verification
			const dPoP = await dpopValidate(headers.dpop, {
				route: routeNames.pushed_authorization_request
			});
			setNonceHeader(set.headers, dPoP);
			await validateReplay(client.clientId, dPoP);
			if (dPoP) {
				if (oidc.params.dpop_jkt && oidc.params.dpop_jkt !== dPoP.thumbprint) {
					throw new InvalidRequest(
						'DPoP proof key thumbprint does not match dpop_jkt'
					);
				} else if (!oidc.params.dpop_jkt) {
					oidc.params.dpop_jkt = dPoP.thumbprint;
				}
			}

			return pushedAuthorizationRequestResponse(oidc, request);
		},
		{
			response: {
				201: ParResponse,
				400: OAuthError,
				401: OAuthError
			},
			status: 201
		}
	);
