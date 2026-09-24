import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { IdToken } from 'lib/models/id_token.js';
import { InvalidRequest, OIDCProviderError } from '../../helpers/errors.ts';

/*
 * Validates the incoming id_token_hint
 */
export default async function checkIdTokenHint(
	oidc: OIDCContext<PipelineParams>
) {
	if (oidc.params.id_token_hint !== undefined) {
		let idTokenHint;
		try {
			idTokenHint = await IdToken.validate(
				oidc.params.id_token_hint,
				oidc.client,
				oidc.issuer
			);
		} catch (err) {
			if (err instanceof OIDCProviderError) {
				throw err;
			}

			throw new InvalidRequest(
				'could not validate id_token_hint',
				undefined,
				err.message
			);
		}
		oidc.entity('IdTokenHint', idTokenHint);
	}
}
