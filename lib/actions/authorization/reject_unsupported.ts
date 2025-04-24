import {
	InvalidRequest,
	RequestNotSupported,
	RequestUriNotSupported
} from '../../helpers/errors.ts';
import instance from '../../helpers/weak_cache.ts';
import { globalConfiguration } from '../../globalConfiguration.ts';

/*
 * Rejects request and request_uri parameters when not supported. Also rejects wmrm's relay mode.
 */
export default function rejectUnsupported(
	params: {
		request?: string;
		request_uri?: string;
		response_mode?: string;
		web_message_uri?: string;
	},
	endpoint: string
) {
	const {
		requestObjects,
		pushedAuthorizationRequests,
		webMessageResponseMode
	} = globalConfiguration.features;

	if (params.request !== undefined && !requestObjects.enabled) {
		throw new RequestNotSupported();
	}

	if (
		params.request_uri !== undefined &&
		(endpoint !== 'authorization' || !pushedAuthorizationRequests.enabled)
	) {
		throw new RequestUriNotSupported();
	}

	if (
		webMessageResponseMode.enabled &&
		params.response_mode?.includes('web_message') &&
		params.web_message_uri
	) {
		const error = new InvalidRequest(
			'Web Message Response Mode Relay Mode is not supported'
		);
		error.allow_redirect = false;
		throw error;
	}
}
