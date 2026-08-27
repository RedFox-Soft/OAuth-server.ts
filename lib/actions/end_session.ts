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
import { Client } from 'lib/models/client.js';
import { AuthorizationCookies, routeNames } from 'lib/consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
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
		async ({ query, cookie, route }) => {
			const oidc = new OIDCContext(query, {}, route);
			oidc.cookie = cookie;
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
				} = oidc.entities.IdTokenHint;

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
					await IdToken.validate(params.id_token_hint, client);
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

			if (client && params.post_logout_redirect_uri !== undefined) {
				if (
					!client.postLogoutRedirectUriAllowed(params.post_logout_redirect_uri)
				) {
					throw new InvalidRequest('post_logout_redirect_uri not registered');
				}
			} else if (params.post_logout_redirect_uri !== undefined) {
				params.post_logout_redirect_uri = undefined;
			}

			const secret = crypto.randomBytes(24).toString('hex');

			oidc.session.payload.state = {
				secret,
				clientId: oidc.client ? oidc.client.clientId : undefined,
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
		async ({ body, cookie, route }) => {
			const oidc = new OIDCContext(body, {}, route);
			oidc.cookie = cookie;
			const setCookies = await sessionHandler(oidc);

			if (!oidc.session.payload.state) {
				throw new InvalidRequest('could not find logout details');
			}
			if (oidc.session.payload.state.secret !== body.xsrf) {
				throw new InvalidRequest('xsrf token invalid');
			}

			const { session } = oidc;
			const { state } = session.payload;

			// A partial sign-out still tells the one client being signed out. A full sign-out tells
			// every client in the session, which `destroyProviderSession` handles as part of the
			// teardown it shares with the admin console's server-side logout.
			if (
				!body.logout &&
				state.clientId &&
				ApplicationConfig['backchannelLogout.enabled']
			) {
				await backchannelLogoutFor(session, [state.clientId], { oidc });
			}

			if (state.clientId) {
				oidc.entity('Client', await Client.tryFind(state.clientId));
			}

			if (body.logout) {
				await destroyProviderSession(session, { oidc });
				cookie._session.set(expiredSessionCookie());
			} else if (state.clientId) {
				const grantId = session.grantIdFor(state.clientId);
				if (
					grantId &&
					!session.authorizationFor(state.clientId).persistsLogout
				) {
					await revoke(grantId);
					eventBus.emit('grant.revoked', { oidc }, grantId);
				}
				session.payload.state = undefined;
				if (session.payload.authorizations) {
					delete session.payload.authorizations[state.clientId];
				}
				session.resetIdentifier();
			}

			eventBus.emit('end_session.success', { oidc });
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
