import { OIDCProviderError } from '../../helpers/errors.ts';
import { BackchannelAuthenticationRequest } from '../../models/backchannel_authentication_request.js';
import { Client } from '../../models/client.js';
import { Grant } from '../../models/grant.js';

/*
 * backchannelResult
 *
 * The counterpart to backchannel_request_response.ts. That module creates the
 * BackchannelAuthenticationRequest and hands it to the `triggerAuthenticationDevice` addon; this one
 * completes it once the end-user's authentication device answers — with a Grant when they approved,
 * or an OIDCProviderError when they did not. The client learns the outcome by polling the token
 * endpoint, or immediately via backchannelPing when it registered for ping delivery.
 *
 * Deployments call this (re-exported from lib/index.ts), which is why it takes ids as readily as
 * instances: the code that resolves an authentication device callback usually holds an auth_req_id
 * and a grant id, not the objects. It lives here rather than on the provider because it is CIBA
 * request lifecycle, not provider state — nothing it touches is per-provider.
 */
export async function backchannelResult(
	request,
	result,
	{ acr, amr, authTime, sessionUid, expiresWithSession, sid } = {}
) {
	if (typeof request === 'string' && request) {
		request = await BackchannelAuthenticationRequest.find(request, {
			ignoreExpiration: true,
			error: new Error('BackchannelAuthenticationRequest not found')
		});
	} else if (!(request instanceof BackchannelAuthenticationRequest)) {
		throw new TypeError('invalid "request" argument');
	}

	const client = await Client.find(request.payload.clientId, {
		error: new Error('Client not found')
	});

	if (typeof result === 'string' && result) {
		result = await Grant.find(result, {
			error: new Error('Grant not found')
		});
	}

	switch (true) {
		case result instanceof Grant:
			if (request.payload.clientId !== result.payload.clientId) {
				throw new Error('client mismatch');
			}

			if (request.payload.accountId !== result.payload.accountId) {
				throw new Error('accountId mismatch');
			}

			Object.assign(request.payload, {
				grantId: result.jti,
				acr,
				amr,
				authTime,
				sessionUid,
				expiresWithSession,
				sid
			});
			break;
		case result instanceof OIDCProviderError:
			Object.assign(request.payload, {
				error: result.error,
				errorDescription: result.error_description
			});
			break;
		default:
			throw new TypeError('invalid "result" argument');
	}

	await request.save();

	if (client.backchannelTokenDeliveryMode === 'ping') {
		await client.backchannelPing(request);
	}
}
