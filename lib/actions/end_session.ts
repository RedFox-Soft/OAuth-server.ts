import { Elysia, t } from 'elysia';
import * as crypto from 'node:crypto';

import {
	InvalidClient,
	InvalidRequest,
	OIDCProviderError
} from '../helpers/errors.ts';
import * as JWT from '../helpers/jwt.ts';
import redirectUri from '../helpers/redirect_uri.ts';
import instance from '../helpers/weak_cache.ts';
import revoke from '../helpers/revoke.ts';
import { IdToken } from 'lib/models/id_token.js';
import { Client } from 'lib/models/client.js';
import { AuthorizationCookies, routeNames } from 'lib/consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import sessionHandler from '../shared/session.ts';
import { logoutSuccess } from '../html/logoutSuccess.tsx';
import { logout } from '../html/logout.tsx';
import { provider } from '../provider.js';

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
	.get(routeNames.end_session, async ({ query, cookie, route }) => {
		const ctx = {
			cookie,
			_matchedRouteName: route
		};
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = query;
		const setCookies = await sessionHandler(ctx);
		const params = query;
		let client;
		if (params.id_token_hint) {
			try {
				const idTokenHint = JWT.decode(params.id_token_hint);
				ctx.oidc.entity('IdTokenHint', idTokenHint);
			} catch (err) {
				throw new InvalidRequest(
					'could not decode id_token_hint',
					undefined,
					err.message
				);
			}
			const {
				payload: { aud: clientId }
			} = ctx.oidc.entities.IdTokenHint;

			if (params.client_id && params.client_id !== clientId) {
				throw new InvalidRequest(
					'client_id does not match the provided id_token_hint'
				);
			}
			client = await Client.find(clientId);
			if (!client) {
				throw new InvalidClient(
					'unrecognized id_token_hint audience',
					'client not found'
				);
			}
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
			ctx.oidc.entity('Client', client);
		} else if (params.client_id) {
			client = await Client.find(params.client_id);
			if (!client) {
				throw new InvalidClient('client is invalid', 'client not found');
			}
			ctx.oidc.entity('Client', client);
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

		ctx.oidc.session.payload.state = {
			secret,
			clientId: ctx.oidc.client ? ctx.oidc.client.clientId : undefined,
			state: ctx.oidc.params.state,
			postLogoutRedirectUri: ctx.oidc.params.post_logout_redirect_uri
		};

		await setCookies();
		if (ctx.oidc.session.payload.accountId) {
			return logout(secret);
		}
		return logoutSuccess();
	});

export const logoutConfirmAction = new Elysia()
	.guard({
		body: t.Object({
			xsrf: t.String(),
			logout: t.Optional(t.Literal('true'))
		}),
		cookie: AuthorizationCookies
	})
	.post(routeNames.end_session_confirm, async ({ body, cookie, route }) => {
		const ctx = {
			cookie,
			_matchedRouteName: route
		};
		ctx.oidc = new OIDCContext(ctx);
		const setCookies = await sessionHandler(ctx);

		if (!ctx.oidc.session.payload.state) {
			throw new InvalidRequest('could not find logout details');
		}
		if (ctx.oidc.session.payload.state.secret !== body.xsrf) {
			throw new InvalidRequest('xsrf token invalid');
		}

		const {
			oidc: { session, params }
		} = ctx;
		const { state } = session.payload;

		const {
			features: { backchannelLogout }
		} = instance(provider).configuration;

		if (backchannelLogout.enabled) {
			const clientIds = Object.keys(session.authorizations || {});

			const back = [];

			for (const clientId of clientIds) {
				if (params.logout || clientId === state.clientId) {
					const client = await Client.find(clientId);
					if (client) {
						const sid = session.sidFor(client.clientId);
						if (client.backchannelLogoutUri) {
							const { accountId } = session;
							back.push(
								client.backchannelLogout(accountId, sid).then(
									() => {
										ctx.oidc.provider.emit(
											'backchannel.success',
											ctx,
											client,
											accountId,
											sid
										);
									},
									(err) => {
										ctx.oidc.provider.emit(
											'backchannel.error',
											ctx,
											err,
											client,
											accountId,
											sid
										);
									}
								)
							);
						}
					}
				}
			}

			await Promise.all(back);
		}

		if (state.clientId) {
			ctx.oidc.entity('Client', await Client.find(state.clientId));
		}

		if (body.logout) {
			if (session.payload.authorizations) {
				await Promise.all(
					Object.entries(session.payload.authorizations).map(
						async ([clientId, { grantId }]) => {
							// Drop the grants without offline_access
							// Note: tokens that don't get dropped due to offline_access having being added
							// later will still not work, as such they will be orphaned until their TTL hits
							if (
								grantId &&
								!session.authorizationFor(clientId).persistsLogout
							) {
								await revoke(ctx, grantId);
							}
						}
					)
				);
			}

			await session.destroy();
			cookie._session.remove();
		} else if (state.clientId) {
			const grantId = session.grantIdFor(state.clientId);
			if (grantId && !session.authorizationFor(state.clientId).persistsLogout) {
				await revoke(ctx, grantId);
				provider.emit('grant.revoked', ctx, grantId);
			}
			session.payload.state = undefined;
			if (session.payload.authorizations) {
				delete session.payload.authorizations[state.clientId];
			}
			session.resetIdentifier();
		}

		provider.emit('end_session.success', ctx);
		await setCookies();

		const usePostLogoutUri = state.postLogoutRedirectUri;
		if (usePostLogoutUri) {
			const param = state.state != null ? { state: state.state } : {};
			const uri = redirectUri(state.postLogoutRedirectUri, param);
			return Response.redirect(uri, 303);
		}

		return logoutSuccess();
	});
