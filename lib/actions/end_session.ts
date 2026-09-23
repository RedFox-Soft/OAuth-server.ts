import { hostOfRequest } from 'lib/consts/request_host.js';
import { Elysia, t } from 'elysia';
import * as crypto from 'node:crypto';

import {
	InvalidClient,
	InvalidRequest,
	OIDCProviderError
} from '../helpers/errors.ts';
import * as JWT from '../helpers/jwt.ts';
import redirectUri from '../helpers/redirect_uri.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import revoke from '../helpers/revoke.ts';
import { IdToken } from 'lib/models/id_token.js';
import { Client, postLogoutRedirectUriAllowed } from 'lib/models/client.js';
import {
	AuthorizationCookies,
	routeNames,
	sessionCookieName
} from 'lib/consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import {
	issuingBucket,
	requestBucketFor
} from 'lib/admin/auth/bucketAddress.js';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.js';
import sessionHandler, { expiredSessionCookie } from '../shared/session.ts';
import {
	backchannelLogoutFor,
	destroyProviderSession
} from '../shared/destroy_session.ts';
import { logoutSuccess } from '../html/logoutSuccess.tsx';
import { logout } from '../html/logout.tsx';
import { eventBus } from '../event_bus.js';
import {
	OAuthError,
	RedirectOrHtmlResponse
} from 'lib/shared/response_schemas.js';

const logoutParameters = t.Object({
	id_token_hint: t.Optional(t.String()),
	post_logout_redirect_uri: t.Optional(t.String()),
	state: t.Optional(t.String()),
	ui_locales: t.Optional(t.String()),
	client_id: t.Optional(t.String()),
	logout_hint: t.Optional(t.String())
});

export const logoutAction = new Elysia()
	.guard({
		query: logoutParameters,
		cookie: AuthorizationCookies
	})
	.get(
		routeNames.end_session,
		async ({ query, cookie, route, params: routeParams }) => {
			/*
			 * The address names the population being signed out of. This is what removed the compromise an
			 * address-less design had to make: a sign-out carrying no client identifier could not name a
			 * bucket, so it had to end every sign-in the browser held or refuse outright. Addressed, it
			 * ends exactly one.
			 */
			const bucket = await requestBucketFor(
				(routeParams as { bucket?: string } | undefined)?.bucket
			);
			const oidc = new OIDCContext({
				params: query,
				route,
				bucket,
				cookie
			});
			const setCookies = await sessionHandler(oidc);
			const params = query;
			let client;
			if (params.id_token_hint) {
				try {
					const idTokenHint = JWT.decode(params.id_token_hint);
					oidc.entity('IdTokenHint', idTokenHint);
				} catch (err) {
					throw new InvalidRequest(
						'could not decode id_token_hint',
						undefined,
						err.message
					);
				}
				const {
					payload: { aud: clientId }
				} = oidc.require('IdTokenHint');

				if (params.client_id && params.client_id !== clientId) {
					throw new InvalidRequest(
						'client_id does not match the provided id_token_hint'
					);
				}
				client = await Client.find(clientId, {
					error: new InvalidClient(
						'unrecognized id_token_hint audience',
						'client not found'
					)
				});
				try {
					await IdToken.validate(params.id_token_hint, client, oidc.issuer);
				} catch (err) {
					if (err instanceof OIDCProviderError) {
						throw err;
					}

					throw new InvalidRequest(
						'could not validate id_token_hint',
						undefined,
						err.message
					);
				}
				oidc.entity('Client', client);
			} else if (params.client_id) {
				client = await Client.find(params.client_id, {
					error: new InvalidClient('client is invalid', 'client not found')
				});
				oidc.entity('Client', client);
			}

			/*
			 * A client may only end a sign-in it shares a session with.
			 *
			 * The sign-out ends whatever sign-in this *address* holds, which is the right answer only while
			 * the client signs into that same population. It does not have to: an `id_token_hint` is
			 * validated against the issuer, and the two buckets served at the root share one, so a token
			 * minted for one of them presented at the bare path ended the other's sign-in. A named bucket's
			 * token reaches the same hole from the other side — its client is refused at this address by
			 * `checkBucket`, but nothing refused its token here.
			 *
			 * Compared by **cookie name** rather than by bucket id, and that is the qualifier that makes
			 * this a refusal rather than a breakage: buckets that share a cookie share a sign-in, so the
			 * default bucket and every bucket with no address of its own must keep ending each other's —
			 * which is the behaviour their clients have always had at the bare endpoints.
			 */
			if (client) {
				const signsInto = await issuingBucket(
					await resolveBucketForRequest(client.clientId)
				);
				if (sessionCookieName(signsInto) !== sessionCookieName(oidc.bucket)) {
					throw new InvalidRequest(
						'client is not authorized at this address',
						undefined,
						'the client signs into a different user bucket than the one addressed'
					);
				}
			}

			if (client && params.post_logout_redirect_uri !== undefined) {
				if (
					!postLogoutRedirectUriAllowed(client, params.post_logout_redirect_uri)
				) {
					throw new InvalidRequest('post_logout_redirect_uri not registered');
				}
			} else if (params.post_logout_redirect_uri !== undefined) {
				params.post_logout_redirect_uri = undefined;
			}

			const secret = crypto.randomBytes(24).toString('hex');

			oidc.session.payload.state = {
				secret,
				clientId: oidc.entities.Client?.clientId,
				state: oidc.params.state,
				postLogoutRedirectUri: oidc.params.post_logout_redirect_uri
			};

			await setCookies();
			if (oidc.session.payload.accountId) {
				return logout(secret);
			}
			return logoutSuccess();
		},
		{
			response: { 200: RedirectOrHtmlResponse, 400: OAuthError }
		}
	);

export const logoutConfirmAction = new Elysia()
	.guard({
		body: t.Object({
			xsrf: t.String(),
			logout: t.Optional(t.Literal('true'))
		}),
		cookie: AuthorizationCookies
	})
	.post(
		routeNames.end_session_confirm,
		async ({ body, cookie, route, params, request }) => {
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
			const setCookies = await sessionHandler(oidc);

			const { session } = oidc;
			const { state } = session.payload;
			if (!state) {
				throw new InvalidRequest('could not find logout details');
			}
			if (state.secret !== body.xsrf) {
				throw new InvalidRequest('xsrf token invalid');
			}

			// A partial sign-out still tells the one client being signed out. A full sign-out tells
			// every client in the session, which `destroyProviderSession` handles as part of the
			// teardown it shares with the admin console's server-side logout.
			if (
				!body.logout &&
				state.clientId &&
				ApplicationConfig['backchannelLogout.enabled']
			) {
				await backchannelLogoutFor(session, [state.clientId], oidc);
			}

			if (state.clientId) {
				oidc.entity('Client', await Client.tryFind(state.clientId));
			}

			if (body.logout) {
				await destroyProviderSession(session, oidc);
				/*
				 * The addressed bucket's cookie, named from the same function that wrote it. A literal here
				 * would clear a name the browser is not holding — reporting a completed sign-out while the
				 * sign-in stayed alive — and, once buckets are separate cookies, would end the wrong
				 * population's sign-in if it matched anything at all.
				 */
				cookie[sessionCookieName(oidc.bucket)].set(expiredSessionCookie());
			} else if (state.clientId) {
				const grantId = session.grantIdFor(state.clientId);
				if (
					grantId &&
					!session.authorizationFor(state.clientId).persistsLogout
				) {
					await revoke(grantId, oidc);
				}
				session.payload.state = undefined;
				if (session.payload.authorizations) {
					delete session.payload.authorizations[state.clientId];
				}
				session.resetIdentifier();
			}

			eventBus.emit('end_session.success', oidc);
			await setCookies();

			const usePostLogoutUri = state.postLogoutRedirectUri;
			if (usePostLogoutUri) {
				const param = state.state != null ? { state: state.state } : {};
				const uri = redirectUri(state.postLogoutRedirectUri, param);
				return Response.redirect(uri, 303);
			}

			return logoutSuccess();
		},
		{
			response: { 200: RedirectOrHtmlResponse, 400: OAuthError }
		}
	);
