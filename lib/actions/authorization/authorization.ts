import { Elysia } from 'elysia';

import { PARAM_LIST } from '../../consts/index.ts';
import checkRar from '../../shared/check_rar.ts';
import checkResource from '../../shared/check_resource.ts';

import { provider } from 'lib/provider.js';
import checkClient from './check_client.ts';
import checkResponseMode from './check_response_mode.ts';
import rejectUnsupported from './reject_unsupported.ts';
import rejectRegistration from './reject_registration.ts';
import oneRedirectUriClients from './one_redirect_uri_clients.ts';
import loadPushedAuthorizationRequest from './load_pushed_authorization_request.ts';
import processRequestObject from './process_request_object.ts';
import oidcRequired from './oidc_required.ts';
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
import interactionEmit from './interaction_emit.ts';
import checkOpenidScope from './check_openid_scope.ts';

import { globalConfiguration } from '../../globalConfiguration.ts';

import { authorizationPKCE } from '../../helpers/pkce.ts';
import {
	AuthorizationCookies,
	AuthorizationParameters,
	routeNames
} from '../../consts/param_list.ts';
import sessionHandler from '../../shared/session.ts';
import { noQueryDup } from 'lib/plugins/noQueryDup.js';
import { contentType } from 'lib/plugins/contentType.js';

function validdateGlobalParameters(params, error) {
	const {
		features: {
			claimsParameter,
			dPoP,
			resourceIndicators,
			richAuthorizationRequests,
			webMessageResponseMode
		}
	} = globalConfiguration;

	if (!Object.keys(params.claims ?? {}).length) {
		params.claims = undefined;
	}

	if (params.web_message_uri && !webMessageResponseMode.enabled) {
		return error(400, 'Web Message Response Mode is not supported');
	} else if (params.claims && !claimsParameter.enabled) {
		return error(400, 'Claims Parameter is not supported');
	} else if (params.resource && !resourceIndicators.enabled) {
		return error(400, 'Resource Indicators is not supported');
	} else if (
		params.authorization_details &&
		!richAuthorizationRequests.enabled
	) {
		return error(400, 'Rich Authorization Requests is not supported');
	} else if (params.dpop_jkt && !dPoP.enabled) {
		return error(400, 'DPoP JWK Thumbprint is not supported');
	}
}

async function authorizationActionHandler(ctx) {
	const params = ctx.oidc.params;

	const allowList = new Set(PARAM_LIST);
	const setCookies = await sessionHandler(ctx);
	rejectUnsupported(params, 'authorization');
	await checkClient(ctx);
	await loadPushedAuthorizationRequest(ctx);
	processRequestObject.bind(undefined, allowList);
	checkResponseMode(ctx);
	oneRedirectUriClients(ctx);
	rejectRegistration(ctx);
	checkResponseType(ctx);
	oidcRequired;
	assignDefaults(ctx);
	checkPrompt(ctx);
	checkScope(allowList, ctx);
	checkOpenidScope(ctx);
	checkRedirectUri(ctx);
	authorizationPKCE(params);
	checkClaims;
	checkRar;
	checkResource;
	checkMaxAge(ctx);
	await checkIdTokenHint(ctx);
	interactionEmit;
	assignClaims(ctx);
	await loadAccount(ctx);
	await loadGrant(ctx);
	let redirectUri = await interactions('resume', ctx);
	if (redirectUri) {
		await setCookies();
		return Response.redirect(redirectUri, 303);
	}
	const response = await respond(ctx);
	await setCookies();

	return response;
}

export const authGet = new Elysia()
	.derive(noQueryDup(['resource', 'ui_locales', 'authorization_details']))
	.get(
		routeNames.authorization,
		async ({ query, error, cookie, route, request }) => {
			const errorOut = validdateGlobalParameters(query, error);
			if (errorOut) {
				return errorOut;
			}
			const url = new URL(request.url);
			url.search = url.pathname = '';

			const ctx = {
				baseUrl: url.toString(),
				cookie,
				_matchedRouteName: route
			};
			const OIDCContext = provider.OIDCContext;
			ctx.oidc = new OIDCContext(ctx);
			ctx.oidc.params = query;

			return await authorizationActionHandler(ctx);
		},
		{
			query: AuthorizationParameters,
			cookie: AuthorizationCookies
		}
	);

export const authPost = new Elysia()
	.derive(contentType('application/x-www-form-urlencoded'))
	.post(
		routeNames.authorization,
		async ({ body, error, cookie, route, request }) => {
			const errorOut = validdateGlobalParameters(body, error);
			if (errorOut) {
				return errorOut;
			}
			const url = new URL(request.url);
			url.search = '';
			url.pathname = url.pathname.replace(route, '');

			const ctx = {
				baseUrl: url.toString(),
				cookie,
				_matchedRouteName: route
			};
			const OIDCContext = provider.OIDCContext;
			ctx.oidc = new OIDCContext(ctx);
			ctx.oidc.body = body;
			ctx.oidc.params = body;

			return await authorizationActionHandler(ctx);
		},
		{
			body: AuthorizationParameters,
			cookie: AuthorizationCookies
		}
	);
