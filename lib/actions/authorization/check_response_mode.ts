import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import {
	InvalidRequest,
	UnsupportedResponseMode
} from '../../helpers/errors.ts';
import { responseModes } from 'lib/response_modes/index.js';
import {
	checkClientSecretExpiration,
	responseModeAllowed
} from 'lib/models/client.js';

/*
 * Resolves and assigns params.response_mode if it was not explicitly requested. Validates id_token
 * and token containing responses do not use response_mode query.
 */
export default function checkResponseMode(oidc: OIDCContext<PipelineParams>) {
	const { params, client } = oidc;

	const mode = oidc.responseMode;

	if (mode !== undefined && !responseModes.has(mode)) {
		params.response_mode = undefined;
		throw new UnsupportedResponseMode();
	}

	if (!responseModeAllowed(oidc.client, mode)) {
		throw new InvalidRequest(
			'requested response_mode is not allowed for this client or request'
		);
	}

	const JWT = mode !== undefined && /jwt/.test(mode);
	const signedWithSecret =
		client.authorizationSignedResponseAlg?.startsWith('HS');
	const encryptedWithSecret =
		client.authorizationEncryptedResponseAlg !== undefined &&
		/^(A|dir$)/.test(client.authorizationEncryptedResponseAlg);

	if (mode !== undefined && JWT && (signedWithSecret || encryptedWithSecret)) {
		try {
			checkClientSecretExpiration(
				client,
				'client secret is expired, cannot issue a JWT Authorization response'
			);
		} catch (err) {
			const [explicit] = mode === 'jwt' ? [undefined] : mode.split('.');
			params.response_mode = explicit || undefined;
			throw err;
		}
	}
}
