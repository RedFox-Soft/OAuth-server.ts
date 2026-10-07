import { Elysia, t } from 'elysia';
import type { JWTPayload } from 'jose';

import { getBucketStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { routeNames } from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import { captureFault } from '../error_store/capture.js';
import { eventBus } from '../event_bus.js';
import type { FederationProvider } from '../federation/types.js';
import {
	InvalidRequest,
	InvalidToken,
	OIDCProviderError,
	RateLimited,
	UpstreamKeysUnavailable,
	UpstreamNotPermitted
} from '../helpers/errors.js';
import { chargeFailedCredential } from '../helpers/unauthenticated_charge.js';
import type { Session } from '../models/session.js';
import { originOf } from '../plugins/rateLimit.js';
import { authenticateUpstream } from './assertion.js';
import {
	accountLinkedTo,
	endSessions,
	sessionsFromUpstreamSession,
	sessionsOfSubject
} from './upstream_session.js';

/*
 * Inbound OpenID Connect Back-Channel Logout 1.0 at `<bucket issuer>/federation/backchannel-logout`
 * (specs/073): a bucket's upstream provider — Keycloak, Auth0, Ping — reports that a person signed out of an
 * upstream session, and the sessions here that came from it end. The second wire format over the core 072
 * built; who may send one and how it is authenticated are lib/upstream_signals/assertion.ts, unchanged.
 *
 * Softer than global token revocation by design: a logout reports a sign-out, not a compromise, so it ends
 * sessions as a sign-out here ends them and keeps offline access (§2.7). Keycloak's non-standard
 * `revoke_offline_access` event member is therefore ignored — ending offline access too is what SCIM
 * deactivation and global token revocation are for.
 *
 * Every refusal and every failure is answered 400 because §2.8 requires it, so a fault in this server is
 * recorded here, where it is answered, rather than by the shared handler that would have answered it 500.
 * The one exception is the failed-credential limit: a request it refuses was never judged, and is answered
 * as the token endpoint answers the same limit.
 */

export const BACKCHANNEL_LOGOUT_EVENT =
	'http://schemas.openid.net/event/backchannel-logout';

/* §2.4 recommends the explicit type; absent and the generic `JWT` are accepted by the core as well. */
const LOGOUT_TOKEN_TYPES = ['logout+jwt'];

const NO_STORE = { 'cache-control': 'no-store' };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): string | undefined {
	return typeof value === 'string' && value ? value : undefined;
}

/*
 * §2.4 and §2.6: the logout event, no `nonce` (what tells a logout token from an ID token), and someone to
 * log out. Other event members are ignored, Keycloak's `revoke_offline_access` among them.
 */
function logoutClaimsRefusal(claims: JWTPayload): string | undefined {
	const events = claims.events;
	if (!isRecord(events) || !isRecord(events[BACKCHANNEL_LOGOUT_EVENT])) {
		return 'events';
	}
	if (claims.nonce !== undefined) return 'nonce';
	if (!nonEmpty(claims.sub) && !nonEmpty(claims.sid)) return 'unattributable';
	return undefined;
}

function logoutTokenOf(request: Request, body: unknown): string {
	const contentType = request.headers.get('content-type') ?? '';
	if (!/^application\/x-www-form-urlencoded\b/i.test(contentType)) {
		throw new InvalidRequest('the logout token must be form-encoded');
	}
	const token = isRecord(body) ? nonEmpty(body.logout_token) : undefined;
	if (!token) throw new InvalidRequest('logout_token is required');
	return token;
}

/* The reason a refusal is reported under, for an operator; never sent to the caller. */
function reasonOf(error: OIDCProviderError): string {
	if (error instanceof UpstreamNotPermitted) return 'not_permitted';
	if (error instanceof UpstreamKeysUnavailable) return 'keys_unavailable';
	if (error instanceof InvalidToken) {
		return `credential:${error.error_detail ?? 'invalid'}`;
	}
	if (error instanceof InvalidRequest) return 'malformed_request';
	return 'error';
}

function answer(error: string): Response {
	return new Response(JSON.stringify({ error }), {
		status: 400,
		headers: { ...NO_STORE, 'content-type': 'application/json' }
	});
}

/*
 * With a session identifier: the sessions from that upstream session — only the subject's, when a subject is
 * named too, so a token cannot end somebody else's session by pairing their `sid` with its own `sub`. With a
 * subject alone: every session of that person from this provider, and no other of theirs.
 */
async function matching(
	bucket: UserBucket,
	provider: FederationProvider,
	claims: JWTPayload
): Promise<Session[]> {
	const sub = nonEmpty(claims.sub);
	const sid = nonEmpty(claims.sid);
	if (sid) {
		if (!sub) return sessionsFromUpstreamSession(bucket._id, provider, sid);
		const accountId = await accountLinkedTo(bucket._id, provider, sub);
		return accountId
			? sessionsFromUpstreamSession(bucket._id, provider, sid, accountId)
			: [];
	}
	return sub ? sessionsOfSubject(bucket._id, provider, sub) : [];
}

async function receive(
	request: Request,
	slug: string | undefined,
	server: unknown,
	body: unknown
): Promise<Response> {
	const addressed = await requestBucketFor(slug, hostOfRequest(request));
	let providerId: string | undefined;
	try {
		const token = logoutTokenOf(request, body);
		/* A bucket with no stored record holds no providers, so nobody can be authenticated for it. */
		const bucket = await getBucketStore().find(addressed._id);
		if (!bucket) throw new InvalidToken('unknown_provider');

		let authenticated;
		try {
			authenticated = await authenticateUpstream(bucket, token, {
				clientIdClaim: 'aud',
				audience: (provider) => provider.clientId,
				types: LOGOUT_TOKEN_TYPES,
				claimsRefusal: logoutClaimsRefusal,
				replayNamespace: 'bcl',
				permits: (provider) => provider.acceptsBackChannelLogout === true
			});
		} catch (error) {
			/* The strict per-origin charge shared with SCIM and global token revocation. */
			if (error instanceof InvalidToken) {
				chargeFailedCredential(
					originOf(request, server),
					(retryAfterSeconds) => new RateLimited(retryAfterSeconds, 'strict')
				);
			}
			throw error;
		}
		const { provider, claims } = authenticated;
		providerId = provider.id;

		const ended = await endSessions(await matching(bucket, provider, claims));
		eventBus.emit('upstream.logout.success', {
			bucketId: bucket._id,
			providerId: provider.id,
			ended
		});
		return new Response(null, { status: 200, headers: NO_STORE });
	} catch (error) {
		if (error instanceof RateLimited) throw error;
		if (error instanceof OIDCProviderError && error.status < 500) {
			const known =
				error instanceof UpstreamNotPermitted ? error.providerId : providerId;
			eventBus.emit('upstream.logout.refused', {
				bucketId: addressed._id,
				...(known ? { providerId: known } : {}),
				reason: reasonOf(error)
			});
			return answer(
				error instanceof UpstreamKeysUnavailable
					? 'temporarily_unavailable'
					: 'invalid_request'
			);
		}
		captureFault({
			surface: 'oauth',
			route: routeNames.federation_backchannel_logout,
			method: request.method,
			status: 500,
			errorCode: 'server_error',
			error,
			headers: request.headers
		});
		return answer('logout_failed');
	}
}

export const federationBackChannelLogout = new Elysia({
	name: 'federation-back-channel-logout'
}).post(
	routeNames.federation_backchannel_logout,
	({ request, params, server, body }) =>
		receive(
			request,
			/* Absent on the bare route: Elysia passes no params object where the path has none. */
			(params as Record<string, string | undefined> | undefined)?.bucket,
			server,
			body
		),
	/* Read by the handler rather than validated here, so a malformed body is answered as §2.8 says (400). */
	{ body: t.Unknown() }
);
