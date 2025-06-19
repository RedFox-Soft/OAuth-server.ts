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
export default async function respond(ctx) {
	let pushedAuthorizationRequest = ctx.oidc.entities.PushedAuthorizationRequest;

	if (!pushedAuthorizationRequest && ctx.oidc.entities.Interaction?.parJti) {
		pushedAuthorizationRequest = await PushedAuthorizationRequest.find(
			ctx.oidc.entities.Interaction.parJti,
			{ ignoreExpiration: true }
		);
	}

	if (pushedAuthorizationRequest?.consumed) {
		throw new InvalidRequestUri(
			'request_uri is invalid, expired, or was already used'
		);
	}
	await pushedAuthorizationRequest?.consume();

	const out = await processResponseTypes(ctx);

	const {
		oidc: { params }
	} = ctx;

	if (params.state !== undefined) {
		out.state = params.state;
	}

	const { responseMode } = ctx.oidc;
	if (!responseMode.includes('jwt')) {
		out.iss = ISSUER;
	}

	ctx.oidc.provider.emit('authorization.success', ctx, out);

	const handler = instance(ctx.oidc.provider).responseModes.get(responseMode);
	return await handler(ctx, params.redirect_uri, out);
}
