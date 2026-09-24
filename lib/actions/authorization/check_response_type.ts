import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParamsWith } from 'lib/consts/param_list.js';
import { InvalidRequest } from '../../helpers/errors.ts';
import { responseTypeAllowed } from 'lib/models/client.js';

/*
 * Validates requested response_type is supported by the provided and allowed in the client
 * configuration
 */
export default function checkResponseType(
	oidc: OIDCContext<PipelineParamsWith<'response_type'>>
) {
	const { params } = oidc;

	if (!responseTypeAllowed(oidc.client, params.response_type)) {
		throw new InvalidRequest(
			'requested response_type is not allowed for this client'
		);
	}
}
