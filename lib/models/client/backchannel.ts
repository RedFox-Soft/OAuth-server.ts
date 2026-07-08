import { STATUS_CODES } from 'node:http';

import nanoid from '../../helpers/nanoid.ts';
import { IdToken } from '../id_token.ts';

// Network side-effecting client behaviours, extracted from the former Client
// methods. Each takes the client object first. Not pure (perform HTTP).

export async function backchannelPing(
	client,
	backchannelAuthenticationRequest
) {
	if (
		!client.backchannelClientNotificationEndpoint ||
		client.backchannelTokenDeliveryMode !== 'ping' ||
		!backchannelAuthenticationRequest ||
		!backchannelAuthenticationRequest.jti ||
		backchannelAuthenticationRequest.payload.kind !==
			'BackchannelAuthenticationRequest' ||
		!backchannelAuthenticationRequest.payload.params.client_notification_token
	) {
		throw new TypeError();
	}

	return fetch(new URL(client.backchannelClientNotificationEndpoint).href, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${backchannelAuthenticationRequest.payload.params.client_notification_token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({
			auth_req_id: backchannelAuthenticationRequest.jti
		})
	}).then((response) => {
		const { status } = response;
		if (status !== 204 && status !== 200) {
			const error = new Error(
				`expected 204 No Content from ${client.backchannelClientNotificationEndpoint}, got: ${status} ${STATUS_CODES[status]}`
			);
			error.response = response;
			throw error;
		}
	});
}

export async function backchannelLogout(client, sub, sid) {
	const logoutToken = new IdToken(client, { sub });
	logoutToken.mask = { sub: null };
	logoutToken.set('events', {
		'http://schemas.openid.net/event/backchannel-logout': {}
	});
	logoutToken.set('jti', nanoid());

	if (client.backchannelLogoutSessionRequired) {
		logoutToken.set('sid', sid);
	}

	return fetch(new URL(client.backchannelLogoutUri).href, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: new URLSearchParams({
			logout_token: await logoutToken.issue({ use: 'logout' })
		})
	}).then((response) => {
		const { status } = response;
		if (status !== 200 && status !== 204) {
			const error = new Error(
				`expected 200 OK from ${client.backchannelLogoutUri}, got: ${status} ${STATUS_CODES[status]}`
			);
			error.response = response;
			throw error;
		}
	});
}
