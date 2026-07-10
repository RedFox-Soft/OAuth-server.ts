import instance from '../../helpers/weak_cache.ts';
import { BackchannelAuthenticationRequest } from '../../models/backchannel_authentication_request.js';

export default async function backchannelRequestResponse(oidc) {
	const { ciba } = instance(oidc.provider).features;

	const request = new BackchannelAuthenticationRequest({
		accountId: oidc.account.accountId,
		claims: oidc.claims,
		client: oidc.client,
		nonce: oidc.params.nonce,
		params: { ...oidc.params },
		resource: Object.keys(oidc.resourceServers),
		scope: [...oidc.requestParamScopes].join(' ')
	});

	switch (request.payload.resource.length) {
		case 0:
			delete request.payload.resource;
			break;
		case 1:
			[request.payload.resource] = request.payload.resource;
			break;
	}

	oidc.entity('BackchannelAuthenticationRequest', request);

	const id = await request.save();

	const body = {
		expires_in: request.expiration,
		auth_req_id: id
	};

	await ciba.triggerAuthenticationDevice(
		{ oidc },
		request,
		oidc.account,
		oidc.client
	);

	return body;
}
