import { OIDCProviderError } from '../../helpers/errors.ts';
import { BackchannelAuthenticationRequest } from '../../models/backchannel_authentication_request.js';
import { Client } from '../../models/client.js';
import { Grant } from '../../models/grant.js';
import { clientNotifications } from '../../shared/client_notifications.ts';

/*
 * backchannelResult
 *
 * The counterpart to backchannel_request_response.ts. That module creates the
 * BackchannelAuthenticationRequest and hands it to the `triggerAuthenticationDevice` addon; this one
 * completes it once the end-user's authentication device answers — with a Grant when they approved,
 * or an OIDCProviderError when they did not. The client learns the outcome by polling the token
 * endpoint, or immediately via a ping notification when it registered for ping delivery.
 *
 * Deployments call this (re-exported from lib/index.ts), which is why it takes ids as readily as
 * instances: the code that resolves an authentication device callback usually holds an auth_req_id
 * and a grant id, not the objects. It lives here rather than on the provider because it is CIBA
 * request lifecycle, not provider state — nothing it touches is per-provider.
 */
/* An individual `acr` claim request, in either of the two forms §5.5.1 gives it. */
interface RequestedAcr {
	essential?: boolean;
	value?: string;
	values?: string[];
}

/*
 * Whether the context the authentication device reported meets a context the client *required*.
 * A merely preferred one — `acr_values`, or a claim without `essential: true` — never fails the
 * transaction: the specification has the server return the context that was satisfied instead.
 */
function satisfiesRequiredAcr(
	claims: { id_token?: { acr?: RequestedAcr } } | undefined,
	acr: string | undefined
): boolean {
	const request = claims?.id_token?.acr;
	if (!request?.essential) {
		return true;
	}
	if (Array.isArray(request.values)) {
		return acr !== undefined && request.values.includes(acr);
	}
	if (request.value !== undefined) {
		return request.value === acr;
	}
	// Essential, but naming no acceptable value: any context satisfies it, absence does not.
	return acr !== undefined;
}

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

			/*
			 * OIDC Core §5.5.1.1 requires an essential acr the authentication did not satisfy to be
			 * treated as a failed authentication attempt. There is no login page to return to here, so
			 * the failure this prevents is the opposite of the redirect flow's loop: a token issued
			 * quietly, carrying a context that does not match what the client required, or none at all.
			 *
			 * Recorded at this point rather than at token issuance because this is when the outcome
			 * becomes known: leaving the request marked successful would tell a ping-mode client to
			 * collect a token that will never exist.
			 */
			if (!satisfiesRequiredAcr(request.payload.claims, acr)) {
				Object.assign(request.payload, {
					error: 'transaction_failed',
					errorDescription:
						'the authentication performed did not satisfy the requested acr'
				});
				break;
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
		await clientNotifications.ping(client, request);
	}
}
