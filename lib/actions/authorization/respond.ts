import instance from '../../helpers/weak_cache.ts';
import { InvalidRequestUri } from '../../helpers/errors.ts';
import processResponseTypes from '../../helpers/process_response_types.ts';
import { PushedAuthorizationRequest } from 'lib/models/pushed_authorization_request.js';
import { ISSUER } from 'lib/configs/env.js';

/*
 * Based on the authorization request response mode either redirects with parameters in query or
 * fragment or renders auto-submitting form with the response members as hidden fields.
 *
 * If session management is supported stores User-Agent readable cookie with the session stated
 * used by the OP iframe to detect session state changes.
 *
 * @emits: authorization.success
 */
export default async function respond(oidc) {
	let pushedAuthorizationRequest = oidc.entities.PushedAuthorizationRequest;

	if (!pushedAuthorizationRequest && oidc.entities.Interaction?.parJti) {
		pushedAuthorizationRequest = await PushedAuthorizationRequest.find(
			oidc.entities.Interaction.parJti,
			{ ignoreExpiration: true }
		);
	}

	if (pushedAuthorizationRequest?.consumed) {
		throw new InvalidRequestUri(
			'request_uri is invalid, expired, or was already used'
		);
	}
	await pushedAuthorizationRequest?.consume();

	// processResponseTypes + response-mode handlers are `ctx`-shaped boundaries (the latter is a
	// public, user-registrable handler API), so they receive a `{ oidc }` payload.
	const out = await processResponseTypes({ oidc });

	const { params } = oidc;

	if (params.state !== undefined) {
		out.state = params.state;
	}

	const { responseMode } = oidc;
	if (!responseMode.includes('jwt')) {
		out.iss = ISSUER;
	}

	// event payload kept `{ oidc }`-shaped: tests assert `args[0][0].oidc.params`
	oidc.provider.emit('authorization.success', { oidc }, out);

	const handler = instance(oidc.provider).responseModes.get(responseMode);
	return await handler({ oidc }, params.redirect_uri, out);
}
