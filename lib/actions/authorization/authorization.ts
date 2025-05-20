import { Elysia, t } from 'elysia';

import { PARAM_LIST } from '../../consts/index.ts';
import checkRar from '../../shared/check_rar.ts';
import checkResource from '../../shared/check_resource.ts';

import { provider } from 'lib/provider.js';
import checkClient from './check_client.ts';
import checkResponseMode from './check_response_mode.ts';
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
import getTokenAuth from '../../shared/token_auth.ts';
import stripOutsideJarParams from './strip_outside_jar_params.ts';
import pushedAuthorizationRequestRemapErrors from './pushed_authorization_request_remap_errors.ts';
import checkDpopJkt from './check_dpop_jkt.ts';
import pushedAuthorizationRequestResponse from './pushed_authorization_request_response.ts';

import {
	AuthorizationCookies,
	AuthorizationParameters,
	routeNames
} from '../../consts/param_list.ts';
import sessionHandler from '../../shared/session.ts';
import { noQueryDup } from 'lib/plugins/noQueryDup.js';
import { contentType } from 'lib/plugins/contentType.js';
import { authVerification } from './authVerification.js';

const authorizationRequest = t.Composite(
	[
		t.Omit(
			AuthorizationParameters,
			['request_uri', 'request', 'client_id'],
			t.Object({ client_id: t.Optional(t.String()) })
		)
	],
	{ additionalProperties: false }
);

async function authorizationActionHandler(ctx) {
	const allowList = new Set(PARAM_LIST);
	const setCookies = await sessionHandler(ctx);
	await checkClient(ctx);
	await loadPushedAuthorizationRequest(ctx);
	await processRequestObject(authorizationRequest, ctx);
	checkResponseMode(ctx);
	oneRedirectUriClients(ctx);
	checkResponseType(ctx);
	oidcRequired;
	assignDefaults(ctx);
	checkPrompt(ctx);
	checkScope(allowList, ctx);
	checkOpenidScope(ctx);
	checkRedirectUri(ctx);
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
	.guard({
		query: AuthorizationParameters,
		cookie: AuthorizationCookies
	})
	.resolve(({ query }) => {
		authVerification(query);
	})
	.get(routeNames.authorization, async ({ query, cookie, route, request }) => {
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
	});

export const authPost = new Elysia()
	.derive(contentType('application/x-www-form-urlencoded'))
	.guard({
		body: AuthorizationParameters,
		cookie: AuthorizationCookies
	})
	.resolve(({ body }) => {
		authVerification(body);
	})
	.post(routeNames.authorization, async ({ body, cookie, route, request }) => {
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
	});

export const par = new Elysia()
	.derive(contentType('application/x-www-form-urlencoded'))
	.guard({
		body: t.Composite(
			[
				t.Omit(AuthorizationParameters, ['request_uri', 'client_id']),
				t.Object({
					client_id: t.Optional(t.String()),
					client_secret: t.Optional(t.String())
				})
			],
			{ additionalProperties: false }
		),
		headers: t.Object({
			authorization: t.Optional(t.String())
		})
	})
	.resolve(({ body }) => {
		authVerification(body);
	})
	.post(
		routeNames.pushed_authorization_request,
		async ({ body, route, request, headers }) => {
			const url = new URL(request.url);
			url.search = '';
			url.pathname = url.pathname.replace(route, '');

			const ctx = {
				baseUrl: url.toString(),
				_matchedRouteName: route,
				headers
			};
			const OIDCContext = provider.OIDCContext;
			ctx.oidc = new OIDCContext(ctx);
			ctx.oidc.body = body;
			ctx.oidc.params = body;

			const { params: authParams, middleware: tokenAuth } =
				getTokenAuth(provider);
			for (const middleware of tokenAuth) {
				await middleware(ctx, () => {});
			}

			stripOutsideJarParams;

			const allowList = new Set(PARAM_LIST);
			pushedAuthorizationRequestRemapErrors;
			processRequestObject.bind(undefined, allowList);
			checkResponseMode;
			oneRedirectUriClients;
			checkResponseType(ctx);
			oidcRequired(ctx);
			checkPrompt(ctx);
			checkScope(allowList, ctx);
			checkOpenidScope(ctx);
			checkRedirectUri(ctx);
			await checkClaims(ctx);
			await checkRar(ctx);
			await checkResource(ctx);
			await checkIdTokenHint(ctx);
			await checkDpopJkt(ctx);
			return pushedAuthorizationRequestResponse(ctx);
		}
	);
