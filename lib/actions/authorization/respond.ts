import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import { InvalidRequestUri } from '../../helpers/errors.ts';
import { responseModes } from 'lib/response_modes/index.js';
import processResponseTypes from '../../helpers/process_response_types.ts';
import { PushedAuthorizationRequest } from 'lib/models/pushed_authorization_request.js';
import { eventBus } from '../../event_bus.js';

/*
 * Based on the authorization request response mode either redirects with parameters in query or
 * fragment or renders auto-submitting form with the response members as hidden fields.
 *
 * If session management is supported stores User-Agent readable cookie with the session stated
 * used by the OP iframe to detect session state changes.
 *
 * @emits: authorization.success
 */
export default async function respond(oidc: OIDCContext) {
	let pushedAuthorizationRequest = oidc.entities.PushedAuthorizationRequest;

	/*
	 * `payload.parJti`, not `.parJti`. Model fields live on the payload and Interaction declares no
	 * accessor for this one, so the property read silently returned undefined — and since the resume
	 * path never runs loadPushedAuthorizationRequest, this lookup is the only thing that finds the
	 * pushed request after an interaction. It failing open is what let a request_uri survive its own
	 * flow and mint a second code (RFC 9126 §7.3).
	 */
	const carriedParJti = oidc.entities.Interaction?.payload?.parJti;
	if (!pushedAuthorizationRequest && carriedParJti) {
		pushedAuthorizationRequest = await PushedAuthorizationRequest.tryFind(
			carriedParJti,
			{ ignoreExpiration: true }
		);
	}

	if (pushedAuthorizationRequest?.payload.consumed) {
		throw new InvalidRequestUri(
			'request_uri is invalid, expired, or was already used'
		);
	}
	await pushedAuthorizationRequest?.consume();

	const out = await processResponseTypes(oidc);

	const { params } = oidc;

	if (params.state !== undefined) {
		out.state = params.state;
	}

	const { responseMode } = oidc;
	if (!responseMode.includes('jwt')) {
		/*
		 * RFC 9207: the issuer that produced this response, which is the bucket the request was
		 * addressed to — not the instance's own, unless the two are the same because this is the
		 * default bucket. A client checking `iss` against the metadata it discovered is checking exactly
		 * this, so a constant here would fail every named bucket.
		 */
		out.iss = oidc.issuer;
	}

	eventBus.emit('authorization.success', oidc, out);

	const handler = responseModes.get(responseMode);
	return await handler(oidc, params.redirect_uri, out);
}
