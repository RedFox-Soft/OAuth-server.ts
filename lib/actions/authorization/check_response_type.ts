import { InvalidRequest } from '../../helpers/errors.ts';
import { responseTypeAllowed } from 'lib/models/client.js';

/*
 * Validates requested response_type is supported by the provided and allowed in the client
 * configuration
 */
export default function checkResponseType(oidc) {
	const { params } = oidc;

	if (!responseTypeAllowed(oidc.client, params.response_type)) {
		throw new InvalidRequest(
			'requested response_type is not allowed for this client'
		);
	}
}
