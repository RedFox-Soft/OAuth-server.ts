import { hostOfRequest } from 'lib/consts/request_host.js';
import { Elysia, t, type Static } from 'elysia';
import { noQueryDup } from 'lib/plugins/noQueryDup.js';
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
import {
	OIDCContext,
	type OIDCCookies,
	type RequestBucket
} from 'lib/helpers/oidc_context.js';
import { issuerFor } from 'lib/configs/issuer.js';
import { formPost } from '../html/formPost.tsx';
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
	PageError,
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

type LogoutParams = Static<typeof logoutParameters>;

const logoutResponses = {
	200: RedirectOrHtmlResponse,
	400: PageError,
	500: PageError
};

/*
 * The address names the population being signed out of. This is what removed the compromise an
 * address-less design had to make: a sign-out carrying no client identifier could not name a
 * bucket, so it had to end every sign-in the browser held or refuse outright. Addressed, it ends
 * exactly one.
 */
function addressedBucket(routeParams: unknown, request: Request) {
	return requestBucketFor(
		(routeParams as { bucket?: string } | undefined)?.bucket,
		hostOfRequest(request)
	);
}

/*
 * The sign-out request itself, whichever method carried it. RP-Initiated Logout §2 requires GET and
 * POST on the one endpoint with the same meaning; one function is what keeps them meaning the same.
 */
async function endSession(
	params: LogoutParams,
	{
		cookie,
		route,
		bucket
	}: { cookie: OIDCCookies; route: string; bucket: RequestBucket }
) {
	const oidc = new OIDCContext({
		params,
		route,
		bucket,
		cookie
	});
	const setCookies = await sessionHandler(oidc);
	let client;
	if (params.id_token_hint) {
		try {
			const idTokenHint = JWT.decode(params.id_token_hint);
			oidc.entity('IdTokenHint', idTokenHint);
		} catch (err) {
			throw new InvalidRequest(
				'could not decode id_token_hint',
				undefined,
				err instanceof Error ? err.message : String(err)
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
		const unrecognized = new InvalidClient(
			'unrecognized id_token_hint audience',
			'client not found'
		);
		// An audience list names no single client to end the session for; the lookup refused it too.
		if (typeof clientId !== 'string') {
			throw unrecognized;
		}
		client = await Client.find(clientId, { error: unrecognized });
		try {
			await IdToken.validate(
				params.id_token_hint,
				client,
				oidc.issuer,
				oidc.bucket
			);
		} catch (err) {
			if (err instanceof OIDCProviderError) {
				throw err;
			}

			throw new InvalidRequest(
				'could not validate id_token_hint',
				undefined,
				err instanceof Error ? err.message : String(err)
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
			/* No resource here, so rule 3 cannot apply and the address only fills the slot. */
			await resolveBucketForRequest(client.clientId, undefined, oidc.bucket)
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
		return logout(
			secret,
			`${oidc.issuer}${routeNames.end_session_confirm}`,
			oidc.params.post_logout_redirect_uri
		);
	}
	return logoutSuccess();
}

export const logoutAction = new Elysia()
	// As at the authorization endpoint: a parameter sent twice is refused, not read one way.
	.derive(noQueryDup())
	.guard({
		query: logoutParameters,
		cookie: AuthorizationCookies
	})
	.get(
		routeNames.end_session,
		async ({ query, cookie, route, params, request }) =>
			endSession(query, {
				cookie,
				route,
				bucket: await addressedBucket(params, request)
			}),
		{ response: logoutResponses }
	);

const FORM_ENCODED = 'application/x-www-form-urlencoded';

/*
 * Its own instance, not a route on `logoutAction`: that instance's `noQueryDup` and query guard apply
 * to every route registered after them, and a post is read from its body alone — a query string on it
 * is neither validated nor merged, so no request can carry two values for one parameter by splitting
 * them between the two.
 */
export const logoutPostAction = new Elysia().post(
	routeNames.end_session,
	async ({ body, cookie, route, params, request }) => {
		// `parse: 'urlencoded'` forces the form decoder on any body, so a text/plain body shaped like a
		// form would otherwise be read as one.
		const mediaType = (request.headers.get('content-type') ?? '')
			.split(';')[0]
			.trim()
			.toLowerCase();
		if (mediaType !== FORM_ENCODED) {
			throw new InvalidRequest(`only ${FORM_ENCODED} is accepted`);
		}

		const bucket = await addressedBucket(params, request);
		const { _resubmitted: resubmitted, ...fields } = body;

		/*
		 * A relying party's sign-out form is a cross-site POST, and the sign-in cookie is `SameSite=Lax`,
		 * so the browser withholds it: a cookie-less post here is indistinguishable from a browser with no
		 * sign-in. Handled directly it would start an empty session, answer "signed out" while the real
		 * sign-in lived on, and overwrite the browser's session cookie with the empty one — ending the
		 * sign-in in this browser with no confirmation, no back-channel notice and nothing revoked.
		 *
		 * So it is bounced once: a page on this origin re-posts the same fields, and that post is same-site,
		 * so the cookie comes with it. Nothing about the session is read or written before the bounce. The
		 * marker bounds the exchange to one round trip whatever the browser does; a resubmission that still
		 * carries no cookie genuinely has no sign-in. The name read is the one `sessionHandler` reads —
		 * `signInBucket` is the addressed bucket until an authorization request resolves another, and this
		 * is not one. See wiki/concepts/cross-site-sign-out-post.md.
		 */
		if (!resubmitted && !cookie[sessionCookieName(bucket)]?.value) {
			const present = Object.fromEntries(
				Object.entries(fields).filter(
					(entry): entry is [string, string] => entry[1] !== undefined
				)
			);
			return formPost(
				undefined,
				`${issuerFor(bucket)}${routeNames.end_session}`,
				{
					...present,
					_resubmitted: '1'
				}
			);
		}

		return endSession(fields, { cookie, route, bucket });
	},
	{
		body: t.Object({
			...logoutParameters.properties,
			// The bounce page's own field: declared so the resubmission validates, never a sign-out parameter.
			_resubmitted: t.Optional(t.Literal('1'))
		}),
		cookie: AuthorizationCookies,
		parse: 'urlencoded',
		response: logoutResponses
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
				const param: Record<string, string> =
					state.state != null ? { state: state.state } : {};
				const uri = redirectUri(usePostLogoutUri, param);
				return Response.redirect(uri, 303);
			}

			return logoutSuccess();
		},
		{
			response: {
				200: RedirectOrHtmlResponse,
				400: PageError,
				500: PageError
			}
		}
	);
