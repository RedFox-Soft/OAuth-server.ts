import Elysia, { t } from 'elysia';

import { PARAM_LIST } from '../../consts/index.ts';
import checkRar from '../../shared/check_rar.ts';
import checkResource from '../../shared/check_resource.ts';

import checkClient from './check_client.ts';
import checkResponseMode from './check_response_mode.ts';
import rejectUnsupported from './reject_unsupported.ts';
import rejectRegistration from './reject_registration.ts';
import oauthRequired from './oauth_required.ts';
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
import checkExtraParams from './check_extra_params.ts';

import { globalConfiguration } from '../../globalConfiguration.ts';

import { authorizationPKCE } from '../../helpers/pkce.ts';
import { AuthorizationParameters } from '../../consts/param_list.ts';
import { OIDCProviderError } from '../../helpers/errors.ts';
import sessionHandler from '../../shared/session.ts';

const cookieName = globalConfiguration.cookies.names.session;

export const authorizationAction = new Elysia().get(
	globalConfiguration.routes.authorization,
	async ({ query, error, cookie, redirect }) => {
		const {
			features: {
				claimsParameter,
				dPoP,
				resourceIndicators,
				richAuthorizationRequests,
				webMessageResponseMode
			}
		} = globalConfiguration;

		const allowList = new Set(PARAM_LIST);

		if (!Object.keys(query.claims ?? {}).length) {
			query.claims = undefined;
		}

		if (query.web_message_uri && !webMessageResponseMode.enabled) {
			return error(400, 'Web Message Response Mode is not supported');
		} else if (query.claims && !claimsParameter.enabled) {
			return error(400, 'Claims Parameter is not supported');
		} else if (query.resource && !resourceIndicators.enabled) {
			return error(400, 'Resource Indicators is not supported');
		} else if (
			query.authorization_details &&
			!richAuthorizationRequests.enabled
		) {
			return error(400, 'Rich Authorization Requests is not supported');
		} else if (query.dpop_jkt && !dPoP.enabled) {
			return error(400, 'DPoP JWK Thumbprint is not supported');
		}

		const ctx = {
			cookie
		};
		const provider = globalThis.provider;
		const OIDCContext = provider.OIDCContext;
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = query;

		const setCookies = await sessionHandler(ctx);
		rejectUnsupported(query, 'authorization');
		await checkClient(ctx);
		loadPushedAuthorizationRequest;
		processRequestObject.bind(undefined, allowList);
		checkResponseMode;
		oneRedirectUriClients(ctx);
		oauthRequired;
		rejectRegistration;
		checkResponseType;
		oidcRequired;
		assignDefaults(ctx);
		checkPrompt;
		checkScope.bind(undefined, allowList);
		checkOpenidScope(ctx);
		checkRedirectUri;
		authorizationPKCE(query);
		checkClaims;
		checkRar;
		checkResource;
		checkMaxAge(ctx);
		checkIdTokenHint(ctx);
		checkExtraParams;
		interactionEmit;
		assignClaims(ctx);
		await loadAccount(ctx);
		await loadGrant(ctx);
		interactions.bind(undefined, 'resume');
		await respond(ctx);
		await setCookies();

		if (ctx.status === 303 && ctx.redirect) {
			return redirect(ctx.redirect, 303);
		}
	},
	{
		query: AuthorizationParameters,
		cookie: t.Cookie(
			{
				[cookieName]: t.Optional(t.String())
			},
			{ httpOnly: true, sameSite: 'lax', secure: true }
		)
	}
);
