import * as errors from '../helpers/errors.ts';
import { ApplicationConfig as config } from '../configs/application.js';

export function sectorIdentifierUriValidate(_client) {
	// @param client - the Client instance
	return true;
}

export async function assertClaimsParameter(_ctx, _claims, _client) {
	// @param ctx - koa request context
	// @param claims - parsed claims parameter
	// @param client - the Client instance
}

export async function assertJwtClaimsAndHeader(oidc, claims, _header, _client) {
	// @param oidc - the per-request oidc context
	// @param claims - parsed Request Object JWT Claims Set as object
	// @param header - parsed Request Object JWT Headers as object
	// @param client - the Client instance

	const requiredClaims = [];
	const isFapi = config['fapi.enabled'];

	if (isFapi) {
		requiredClaims.push('exp', 'aud', 'nbf');
	}

	if (oidc.route === 'backchannel_authentication') {
		requiredClaims.push('exp', 'iat', 'nbf', 'jti');
	}

	for (const claim of new Set(requiredClaims)) {
		if (claims[claim] === undefined) {
			throw new errors.InvalidRequestObject(
				`Request Object is missing the '${claim}' claim`
			);
		}
	}

	if (isFapi) {
		const diff = claims.exp - claims.nbf;
		if (Math.sign(diff) !== 1 || diff > 3600) {
			throw new errors.InvalidRequestObject(
				"Request Object 'exp' claim too far from 'nbf' claim"
			);
		}
	}
}
