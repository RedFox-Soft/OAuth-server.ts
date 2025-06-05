import { Elysia, t, ValidationError } from 'elysia';

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
import presence from '../../helpers/validate_presence.ts';

import {
	AuthorizationCookies,
	AuthorizationParameters,
	JWTparameters,
	routeNames
} from '../../consts/param_list.ts';
import sessionHandler from '../../shared/session.ts';
import { noQueryDup } from 'lib/plugins/noQueryDup.js';
import { contentType } from 'lib/plugins/contentType.js';
import { featureVerification } from './featureVerification.js';
import { authorizationPKCE } from 'lib/helpers/pkce.js';
import {
	InvalidClient,
	InvalidRedirectUri,
	OIDCProviderError
} from 'lib/helpers/errors.js';

const authorizationRequest = t.Composite([
	t.Omit(AuthorizationParameters, ['request_uri', 'request', 'client_id']),
	t.Object({
		client_id: t.Optional(t.String())
	}),
	JWTparameters
]);

export async function isAllowRedirectUri(params) {
	const ctx = {};
	const OIDCContext = provider.OIDCContext;
	ctx.oidc = new OIDCContext(ctx);
	ctx.oidc.params = params;

	if (!params.client_id) {
		throw new InvalidClient('client_id is required', 'client not found');
	}
	if (typeof params.client_id !== 'string') {
		throw new InvalidClient('client is invalid', 'client not found');
	}
	const client = await provider.Client.find(params.client_id);
	if (!client) {
		throw new InvalidClient('client is invalid', 'client not found');
	}
	ctx.oidc.entity('Client', client);
	try {
		await processRequestObject(authorizationRequest, ctx);
	} catch (e) {
		if (!(e instanceof OIDCProviderError) && !(e instanceof ValidationError)) {
			throw e;
		}
	}

	let redirect_uri = params.redirect_uri;
	if (redirect_uri === undefined) {
		oneRedirectUriClients(ctx);
		redirect_uri = params.redirect_uri;
	}
	if (typeof redirect_uri !== 'string') {
		throw new InvalidRedirectUri();
	}
	if (!client.redirectUriAllowed(redirect_uri)) {
		throw new InvalidRedirectUri();
	}

	const state = typeof params.state !== 'string' ? undefined : params.state;

	return { redirect_uri, state };
}

async function authorizationActionHandler(ctx) {
	const allowList = new Set(PARAM_LIST);
	const setCookies = await sessionHandler(ctx);
	await checkClient(ctx);

	const cient = ctx.oidc.client;
	const pushedAuthorizationRequest = await loadPushedAuthorizationRequest(ctx);
	const requestOptions = {
		clientAlg: cient.requestObjectSigningAlg,
		trusted: false,
		isPar: false
	};
	if (pushedAuthorizationRequest) {
		requestOptions.isPar = true;
		requestOptions.clientAlg = undefined;
		requestOptions.trusted = pushedAuthorizationRequest.trusted;
	}
	await processRequestObject(authorizationRequest, ctx, requestOptions);
	checkResponseMode(ctx);
	oneRedirectUriClients(ctx);
	presence(ctx, 'response_type');
	checkResponseType(ctx);
	oidcRequired;
	assignDefaults(ctx);
	checkPrompt(ctx);
	checkScope(allowList, ctx);
	checkOpenidScope(ctx);
	checkRedirectUri(ctx);
	authorizationPKCE(ctx.oidc.params);
	await checkClaims(ctx);
	await checkRar(ctx);
	await checkResource(ctx);
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
		featureVerification(query);
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

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

export const authPost = new Elysia()
	.derive(contentType('application/x-www-form-urlencoded'))
	.derive(({ body }) => {
		if (
			isRecord(body) &&
			'ui_locales' in body &&
			typeof body.ui_locales === 'string'
		) {
			body.ui_locales = [body.ui_locales];
		}
	})
	.guard({
		body: AuthorizationParameters,
		cookie: AuthorizationCookies
	})
	.resolve(({ body }) => {
		featureVerification(body);
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
		query: t.Object({}),
		body: t.Composite([
			t.Omit(AuthorizationParameters, ['request_uri', 'client_id']),
			t.Object({
				client_id: t.Optional(t.String()),
				client_secret: t.Optional(t.String())
			})
		]),
		headers: t.Object({
			authorization: t.Optional(t.String())
		})
	})
	.resolve(({ body }) => {
		featureVerification(body);
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
			ctx.oidc.body = { ...body };
			ctx.oidc.params = body;

			const { params: authParams, middleware: tokenAuth } =
				getTokenAuth(provider);
			for (const middleware of tokenAuth) {
				await middleware(ctx, () => {});
			}

			stripOutsideJarParams;

			const allowList = new Set(PARAM_LIST);
			pushedAuthorizationRequestRemapErrors;
			const client = ctx.oidc.client;
			await processRequestObject(authorizationRequest, ctx, {
				clientAlg: client.requestObjectSigningAlg
			});
			checkResponseMode(ctx);
			oneRedirectUriClients(ctx);
			presence(ctx, 'response_type');
			checkResponseType(ctx);
			oidcRequired(ctx);
			checkPrompt(ctx);
			checkScope(allowList, ctx);
			checkOpenidScope(ctx);
			checkRedirectUri(ctx);
			authorizationPKCE(ctx.oidc.params);
			await checkClaims(ctx);
			await checkRar(ctx);
			await checkResource(ctx);
			await checkIdTokenHint(ctx);
			await checkDpopJkt(ctx);
			return pushedAuthorizationRequestResponse(ctx);
		}
	);
