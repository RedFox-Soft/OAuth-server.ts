import { STATUS_CODES } from 'node:http';

import nanoid from '../helpers/nanoid.ts';
import { IdToken } from '../models/id_token.ts';
import { type Client } from '../models/client/types.ts';
import { type BackchannelAuthenticationRequest } from '../models/backchannel_authentication_request.ts';
import { guardedFetch } from './egress.ts';
import { issuingBucket } from '../admin/auth/bucketAddress.ts';

/*
 * The notifications this server sends to a client. They perform network requests and mint a logout
 * token, so they are not part of the client model; they sit on one object so a test can replace a
 * notification the way it replaces any other outbound call.
 *
 * Both endpoints are addresses the client registered, so both go through the egress boundary: a
 * notification is a POST this server makes to wherever a registrant pointed it.
 */
const NOTIFICATION_TIMEOUT_MS = 5_000;
export const clientNotifications = { ping, logout };

async function ping(
	client: Client,
	backchannelAuthenticationRequest: BackchannelAuthenticationRequest
) {
	const notificationToken =
		backchannelAuthenticationRequest?.payload.params?.client_notification_token;
	if (
		!client.backchannelClientNotificationEndpoint ||
		client.backchannelTokenDeliveryMode !== 'ping' ||
		!backchannelAuthenticationRequest ||
		!backchannelAuthenticationRequest.jti ||
		backchannelAuthenticationRequest.payload.kind !==
			'BackchannelAuthenticationRequest' ||
		typeof notificationToken !== 'string' ||
		!notificationToken
	) {
		throw new TypeError();
	}

	const endpoint = client.backchannelClientNotificationEndpoint;
	return guardedFetch(endpoint, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${notificationToken}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({
			auth_req_id: backchannelAuthenticationRequest.jti
		}),
		timeoutMs: NOTIFICATION_TIMEOUT_MS
	}).then((response) => {
		const { status } = response;
		if (status !== 204 && status !== 200) {
			throw Object.assign(
				new Error(
					`expected 204 No Content from ${endpoint}, got: ${status} ${STATUS_CODES[status] ?? 'Unknown'}`
				),
				{ response }
			);
		}
	});
}

/*
 * sid is absent when the session never recorded one for this client; it is only sent when required.
 *
 * The issuer is the bucket the ended session signed in to, not one derived from the client: the token
 * is a statement by the authorization server that ended the session, and a relying party checks its
 * `iss` against the issuer it discovered. A session without a bucket predates buckets and was the
 * default bucket's.
 */
async function logout(
	client: Client,
	sub: string | undefined,
	sid: string | undefined,
	bucketId?: string
) {
	const logoutToken = new IdToken(
		client,
		{ sub },
		await issuingBucket(bucketId)
	);
	logoutToken.mask = { sub: null };
	logoutToken.set('events', {
		'http://schemas.openid.net/event/backchannel-logout': {}
	});
	logoutToken.set('jti', nanoid());

	if (client.backchannelLogoutSessionRequired) {
		logoutToken.set('sid', sid);
	}

	// String(): what new URL() does to an absent value itself; callers check the URI is registered.
	const endpoint = String(client.backchannelLogoutUri);
	return guardedFetch(endpoint, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: new URLSearchParams({
			logout_token: await logoutToken.issue('logout')
		}),
		timeoutMs: NOTIFICATION_TIMEOUT_MS
	}).then((response) => {
		const { status } = response;
		if (status !== 200 && status !== 204) {
			throw Object.assign(
				new Error(
					`expected 200 OK from ${endpoint}, got: ${status} ${STATUS_CODES[status] ?? 'Unknown'}`
				),
				{ response }
			);
		}
	});
}
