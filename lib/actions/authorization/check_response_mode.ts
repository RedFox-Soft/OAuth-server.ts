import {
	InvalidRequest,
	UnsupportedResponseMode
} from '../../helpers/errors.ts';
import instance from '../../helpers/weak_cache.ts';

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 */
export default function checkResponseMode(ctx) {
	const { params, client } = ctx.oidc;

	const mode = ctx.oidc.responseMode;

	if (
		mode !== undefined &&
		!instance(ctx.oidc.provider).responseModes.has(mode)
	) {
		params.response_mode = undefined;
		throw new UnsupportedResponseMode();
	}

	if (!ctx.oidc.client.responseModeAllowed(mode)) {
		throw new InvalidRequest(
			'requested response_mode is not allowed for this client or request'
		);
	}

	const JWT = /jwt/.test(mode);

	if (
		mode !== undefined &&
		JWT &&
		(/^HS/.test(client.authorizationSignedResponseAlg) ||
			/^(A|dir$)/.test(client.authorizationEncryptedResponseAlg))
	) {
		try {
			client.checkClientSecretExpiration(
				'client secret is expired, cannot issue a JWT Authorization response'
			);
		} catch (err) {
			const [explicit] = mode === 'jwt' ? [undefined] : mode.split('.');
			params.response_mode = explicit || undefined;
			throw err;
		}
	}
}
