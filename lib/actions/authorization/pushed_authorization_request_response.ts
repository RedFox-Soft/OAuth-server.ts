import { UnsecuredJWT } from 'jose';

import { PUSHED_REQUEST_URN } from '../../consts/index.ts';
import epochTime from '../../helpers/epoch_time.ts';
import * as JWT from '../../helpers/jwt.ts';
import { ISSUER } from 'lib/configs/env.js';
import { nanoid } from 'nanoid';
import { PushedAuthorizationRequest } from 'lib/models/pushed_authorization_request.js';
import { provider } from 'lib/provider.ts';

const MAX_TTL = 60;

export default async function pushedAuthorizationRequestResponse(
	oidc,
	requestBody?: string
) {
	let ttl: number;
	let dpopJkt;
	const now = epochTime();
	let request: string;
	if (requestBody) {
		request = requestBody;
		const {
			payload: { exp = now, dpop_jkt: thumbprint }
		} = JWT.decode(request);
		ttl = exp - now;

		if (!Number.isInteger(ttl) || ttl > MAX_TTL) {
			ttl = MAX_TTL;
		}
		dpopJkt = thumbprint || oidc.params.dpop_jkt;
	} else {
		ttl = MAX_TTL;
		const payload = { ...oidc.params };

		if (payload.authorization_details) {
			payload.authorization_details = JSON.parse(payload.authorization_details);
		}

		request = new UnsecuredJWT(payload)
			.setJti(nanoid())
			.setIssuedAt(now)
			.setIssuer(oidc.client.clientId)
			.setAudience(ISSUER)
			.setExpirationTime(now + MAX_TTL)
			.setNotBefore(now)
			.encode();
		dpopJkt = oidc.params.dpop_jkt;
	}

	const requestObject = new PushedAuthorizationRequest({
		request,
		dpopJkt,
		trusted: oidc.client.clientAuthMethod !== 'none' || !!oidc.trusted?.length
	});

	const id = await requestObject.save(ttl);

	oidc.entity('PushedAuthorizationRequest', requestObject);

	// event payload kept `{ oidc }`-shaped (was `ctx`)
	provider.emit('pushed_authorization_request.success', { oidc }, oidc.client);
	return new Response(
		JSON.stringify({
			expires_in: ttl,
			request_uri: `${PUSHED_REQUEST_URN}${id}`
		}),
		{
			status: 201
		}
	);
}
