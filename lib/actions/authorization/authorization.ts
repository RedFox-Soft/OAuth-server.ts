import { hostOfRequest } from 'lib/consts/request_host.js';
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
	refusedParam,
	routeNames
} from '../../consts/param_list.ts';
import sessionHandler from '../../shared/session.ts';
import { noQueryDup } from 'lib/plugins/noQueryDup.js';
import {
	coerceArrayParams,
	parseJsonParams
} from 'lib/plugins/coerce_array_params.js';
import { ignoreUnknownParams } from 'lib/plugins/ignore_unknown_params.js';
import { featureVerification } from './featureVerification.js';
import { authorizationPKCE } from 'lib/helpers/pkce.js';
import {
	InvalidClient,
	InvalidRedirectUri,
	InvalidRequest,
	OIDCProviderError
} from 'lib/helpers/errors.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { RequestBucket } from 'lib/configs/issuer.js';
import {
	issuingBucket,
	requestBucketFor
} from 'lib/admin/auth/bucketAddress.js';
import checkBucket from './check_bucket.js';
import { Client, redirectUriAllowed } from 'lib/models/client.js';
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
import { corsClientBased, formClientId } from 'lib/plugins/cors.js';
import {
	OAuthError,
	ParResponse,
	RedirectOrHtmlResponse
} from 'lib/shared/response_schemas.js';

/*
 * `request` and `request_uri` are declared absent rather than omitted: OIDC Core §6.1 forbids them
 * *inside* a Request Object, and a forbidden member has to be refused where an unrecognized one is
 * ignored. Omitting them would make inception indistinguishable from an extension parameter.
 */
const authorizationRequest = t.Object({
	...t.Omit(AuthorizationParameters, ['request_uri', 'request', 'client_id'])
		.properties,
	client_id: t.Optional(t.String()),
	request: refusedParam('request'),
	request_uri: refusedParam('request_uri'),
	...JWTparameters.properties
});

// RFC 9126 §2.1 step 2: a pushed request carrying `request_uri` is rejected, not ignored.
const pushedAuthorizationParameters = t.Object({
	...t.Omit(AuthorizationParameters, ['request_uri', 'client_id']).properties,
	...authParams.properties,
	request_uri: refusedParam('request_uri')
});

export async function isAllowRedirectUri(params, bucket?: RequestBucket) {
	/*
	 * The bucket is passed in because this runs from the error handler, which holds a route *pattern*
	 * rather than a resolved request. Everything the delivered error carries hangs off it — most visibly
	 * the `iss` RFC 9207 puts in the response, which a client compares against the metadata it
	 * discovered for the bucket it is talking to.
	 */
	const oidc = new OIDCContext({ params, bucket });

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
	if (!redirectUriAllowed(client, redirect_uri)) {
		throw new InvalidRedirectUri();
	}

	const state = typeof params.state !== 'string' ? undefined : params.state;

	return { redirect_uri, state, oidc };
}

async function authorizationActionHandler(oidc: OIDCContext) {
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
	authorizationPKCE(oidc);
	await checkClaims(oidc);
	await checkRar(oidc);
	await checkResource(oidc);
	/*
	 * After the resource, because a bucket can derive from a declared resource and a resource arriving
	 * inside a pushed request or a request object is not settled until here. Before anything that
	 * resolves an account or mints a grant, because everything downstream is scoped to a population and
	 * a client at the wrong address has no business reaching any of it.
	 */
	const signsInto = await checkBucket(oidc);
	/*
	 * The session is read only now, and this is the first step that could have read one.
	 *
	 * A session belongs to a population, and which population is not answerable from the address alone:
	 * the default bucket and the administrators' bucket are both served at the root, so the two share an
	 * address and only the client tells them apart. Read from the address, `/auth` took the default
	 * bucket's cookie into a console sign-in whose resumption then read the administrators' — the
	 * interaction recorded one session and the resumption found another, which is the
	 * `interaction session and authentication session mismatch` an operator saw whenever their browser
	 * already held an end-user sign-in at the same origin. It also meant a console session was never
	 * recognised at `/auth`, so the password was asked for on every authorization request.
	 *
	 * Deliberately after `checkBucket` rather than before it. That check is a refusal, comparing the
	 * client's bucket against the address, and a session loaded ahead of it would be the *client's*
	 * before anything had established the client may be used here at all.
	 */
	oidc.signInBucket = await issuingBucket(signsInto);
	const setCookies = await sessionHandler(oidc);
	checkMaxAge(oidc);
	await checkIdTokenHint(oidc);
	assignClaims(oidc);
	await loadAccount(oidc);
	await loadGrant(oidc);
	const redirectUri = await interactions(oidc);
	if (redirectUri) {
		await setCookies();
		return Response.redirect(redirectUri, 303);
	}
	const response = await respond(oidc);
	await setCookies();

	return response;
}

export const authGet = new Elysia()
	.use(ignoreUnknownParams(AuthorizationParameters))
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
		async ({ query, cookie, route, request, params }) => {
			/*
			 * The address decides the population, before anything else about the request is looked at.
			 * `params.bucket` is present only on the prefixed mount; its absence is the bare address,
			 * which is the default bucket's.
			 */
			const bucket = await requestBucketFor(
				(params as { bucket?: string } | undefined)?.bucket,
				hostOfRequest(request)
			);

			const oidc = new OIDCContext({
				params: query,
				route,
				bucket,
				cookie
			});

			return await authorizationActionHandler(oidc);
		},
		{
			response: { 200: RedirectOrHtmlResponse, 400: OAuthError }
		}
	);

export const authPost = new Elysia()
	.use(ignoreUnknownParams(AuthorizationParameters))
	.use(coerceArrayParams('ui_locales', 'resource'))
	.use(parseJsonParams('authorization_details'))
	.guard({
		body: AuthorizationParameters,
		cookie: AuthorizationCookies
	})
	.resolve(({ body }) => {
		featureVerification(body);
	})
	.post(
		routeNames.authorization,
		async ({ body, cookie, route, request, params }) => {
			/* The address decides the population, exactly as on the GET above. */
			const bucket = await requestBucketFor(
				(params as { bucket?: string } | undefined)?.bucket,
				hostOfRequest(request)
			);

			const oidc = new OIDCContext({
				params: body,
				route,
				bucket,
				cookie
			});

			return await authorizationActionHandler(oidc);
		},
		{
			response: { 200: RedirectOrHtmlResponse, 400: OAuthError }
		}
	);

/*
 * Only `par` carries CORS in this module: a browser reaches /auth by navigation, and the
 * browser-based-apps BCP forbids CORS there outright. The hook precedes AuthPlugin, which throws
 * invalid_client from a `derive` in the transform queue.
 */
export const par = new Elysia()
	.use(corsClientBased(formClientId))
	.use(ignoreUnknownParams(pushedAuthorizationParameters))
	.use(parseJsonParams('authorization_details'))
	.use(AuthPlugin)
	.guard({
		body: pushedAuthorizationParameters,
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
			authorizationPKCE(oidc);
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

			// RFC 9126 §2.2: 201 with an application/json body. The status belongs here rather
			// than in the hook options below — `status` is not a local hook Elysia reads, so the
			// declaration there was inert and the endpoint answered 200.
			set.status = 201;
			return pushedAuthorizationRequestResponse(oidc, request);
		},
		{
			response: {
				201: ParResponse,
				400: OAuthError,
				401: OAuthError
			}
		}
	);
