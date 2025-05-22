import {
	InvalidRequest,
	InvalidRequestUri,
	RequestUriNotSupported
} from '../../helpers/errors.ts';
import { PUSHED_REQUEST_URN } from '../../consts/index.ts';

/*
 * Validates request_uri is a PAR one when PAR is enabled and loads it. Throws
 */
export default async function loadPushedAuthorizationRequest(ctx) {
	const {
		params,
		provider: { PushedAuthorizationRequest }
	} = ctx.oidc;

	if (params.request !== undefined && params.request_uri !== undefined) {
		throw new InvalidRequest(
			'request and request_uri parameters MUST NOT be used together'
		);
	}
	if (params.request_uri === undefined) {
		return;
	}
	if (!params.request_uri.startsWith(PUSHED_REQUEST_URN)) {
		throw new RequestUriNotSupported();
	}
	if (!URL.canParse(params.request_uri)) {
		throw new InvalidRequestUri('invalid request_uri');
	}

	const [, id] = params.request_uri.split(PUSHED_REQUEST_URN);
	const pushedAuthorizationRequest = await PushedAuthorizationRequest.find(id, {
		ignoreExpiration: true
	});
	if (!pushedAuthorizationRequest?.isValid) {
		throw new InvalidRequestUri(
			'request_uri is invalid, expired, or was already used'
		);
	}
	ctx.oidc.entity('PushedAuthorizationRequest', pushedAuthorizationRequest);
	params.request = pushedAuthorizationRequest.request;
}
