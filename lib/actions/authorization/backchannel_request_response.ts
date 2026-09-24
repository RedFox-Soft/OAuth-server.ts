import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { BackchannelAuthenticationRequest } from '../../models/backchannel_authentication_request.js';
import { triggerAuthenticationDevice } from '../../addon/index.js';

export default async function backchannelRequestResponse(
	oidc: OIDCContext<PipelineParams>
) {
	const resources = Object.keys(oidc.resourceServers);
	const request = new BackchannelAuthenticationRequest({
		/* The address the request was made to. */
		bucketId: oidc.bucket._id,
		accountId: oidc.require('Account').accountId,
		claims: oidc.claims,
		client: oidc.client,
		nonce: oidc.params.nonce,
		params: { ...oidc.params },
		// One resource is recorded as itself, several as the list, none not at all.
		resource: resources.length > 1 ? resources : resources[0],
		scope: [...oidc.requestParamScopes].join(' ')
	});

	oidc.entity('BackchannelAuthenticationRequest', request);

	const id = await request.save();

	const body = {
		expires_in: request.expiration,
		auth_req_id: id
	};

	await triggerAuthenticationDevice(
		oidc,
		request,
		oidc.require('Account'),
		oidc.client
	);

	return body;
}
