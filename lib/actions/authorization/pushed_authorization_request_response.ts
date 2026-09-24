import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { UnsecuredJWT } from 'jose';

import { PUSHED_REQUEST_URN } from '../../consts/index.ts';
import epochTime from '../../helpers/epoch_time.ts';
import * as JWT from '../../helpers/jwt.ts';
import { ISSUER } from 'lib/configs/env.js';
import { nanoid } from 'nanoid';
import { PushedAuthorizationRequest } from 'lib/models/pushed_authorization_request.js';
import { eventBus } from 'lib/event_bus.ts';

const MAX_TTL = 60;

export default async function pushedAuthorizationRequestResponse(
	oidc: OIDCContext<PipelineParams>,
	requestBody?: string
) {
	let ttl: number;
	let dpopJkt: string | undefined;
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
		// The request object passed the endpoint's schema, which declares dpop_jkt a string.
		dpopJkt =
			(typeof thumbprint === 'string' && thumbprint) || oidc.params.dpop_jkt;
	} else {
		ttl = MAX_TTL;
		// authorization_details is already an array here — the request parser coerces it and checkRar
		// normalizes it. Parsing it again stringified the array to "[object Object]" and threw, which
		// only stayed invisible because checkRar used to reject the array before this line ran.
		const payload = { ...oidc.params };

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
		trusted:
			oidc.client.tokenEndpointAuthMethod !== 'none' || !!oidc.trusted?.length
	});

	const id = await requestObject.save(ttl);

	oidc.entity('PushedAuthorizationRequest', requestObject);

	eventBus.emit('pushed_authorization_request.success', oidc, oidc.client);
	return {
		expires_in: ttl,
		request_uri: `${PUSHED_REQUEST_URN}${id}`
	};
}
