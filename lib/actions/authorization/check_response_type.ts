import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParamsWith } from 'lib/consts/param_list.js';
import {
	InvalidRequest,
	UnsupportedResponseType
} from '../../helpers/errors.ts';
import { sl1, sl1Exempt } from '../../sl1/rules.ts';
import { responseTypeAllowed } from 'lib/models/client.js';

/*
 * Validates requested response_type is supported by the provided and allowed in the client
 * configuration
 */
export default function checkResponseType(
	oidc: OIDCContext<PipelineParamsWith<'response_type'>>
) {
	const { params } = oidc;

	// IPSIE SL1 §3.2.1: "MUST require the value of `response_type` … to be `code`", whatever the client registered.
	if (sl1() && !sl1Exempt(oidc.client) && params.response_type !== 'code') {
		throw new UnsupportedResponseType();
	}

	if (!responseTypeAllowed(oidc.client, params.response_type)) {
		throw new InvalidRequest(
			'requested response_type is not allowed for this client'
		);
	}
}
