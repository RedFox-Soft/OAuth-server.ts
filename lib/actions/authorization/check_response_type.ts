import { InvalidRequest } from '../../helpers/errors.ts';

/*
 * Validates requested response_type is supported by the provided and allowed in the client
 * configuration
 */
export default function checkResponseType(oidc) {
	const { params } = oidc;

	if (!oidc.client.responseTypeAllowed(params.response_type)) {
		throw new InvalidRequest(
			'requested response_type is not allowed for this client'
		);
	}
}
