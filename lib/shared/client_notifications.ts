import { STATUS_CODES } from 'node:http';

import nanoid from '../helpers/nanoid.ts';
import { IdToken } from '../models/id_token.ts';
import { type Client } from '../models/client/types.ts';
import { isPlainObject } from '../helpers/_/object.js';
import { type BackchannelAuthenticationRequest } from '../models/backchannel_authentication_request.ts';

/*
 * The notifications this server sends to a client. They perform network requests and mint a logout
 * token, so they are not part of the client model; they sit on one object so a test can replace a
 * notification the way it replaces any other outbound call.
 */
export const clientNotifications = { ping, logout };

async function ping(
	client: Client,
	backchannelAuthenticationRequest: BackchannelAuthenticationRequest
) {
	// The stored params are opaque to the model; the notification token is the one member read here.
	const params = backchannelAuthenticationRequest?.payload.params;
	const notificationToken = isPlainObject(params)
		? params.client_notification_token
		: undefined;
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
	return fetch(new URL(endpoint).href, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${notificationToken}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({
			auth_req_id: backchannelAuthenticationRequest.jti
		})
	}).then((response) => {
		const { status } = response;
		if (status !== 204 && status !== 200) {
			throw Object.assign(
				new Error(
					`expected 204 No Content from ${endpoint}, got: ${status} ${STATUS_CODES[status]}`
				),
				{ response }
			);
		}
	});
}

// sid is absent when the session never recorded one for this client; it is only sent when required.
async function logout(
	client: Client,
	sub: string | undefined,
	sid: string | undefined
) {
	const logoutToken = new IdToken(client, { sub });
	logoutToken.mask = { sub: null };
	logoutToken.set('events', {
		'http://schemas.openid.net/event/backchannel-logout': {}
	});
	logoutToken.set('jti', nanoid());

	if (client.backchannelLogoutSessionRequired) {
		logoutToken.set('sid', sid);
	}

	// String(): what new URL() does to an absent value itself; callers check the URI is registered.
	return fetch(new URL(String(client.backchannelLogoutUri)).href, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: new URLSearchParams({
			logout_token: await logoutToken.issue('logout')
		})
	}).then((response) => {
		const { status } = response;
		if (status !== 200 && status !== 204) {
			throw Object.assign(
				new Error(
					`expected 200 OK from ${client.backchannelLogoutUri}, got: ${status} ${STATUS_CODES[status]}`
				),
				{ response }
			);
		}
	});
}
