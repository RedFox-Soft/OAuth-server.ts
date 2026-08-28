import * as errors from '../helpers/errors.ts';
import { ApplicationConfig as config } from '../configs/application.js';

export function sectorIdentifierUriValidate(_client) {
	// @param client - the Client instance
	return true;
}

// An override seam, not an unimplemented stub: the empty body is the default. The
// server's own structural validation of the claims parameter lives in the caller
// (lib/actions/authorization/check_claims.ts), which invokes this on every
// authorization request carrying `claims` while claimsParameter.enabled is set. The
// hook exists so a deployment can layer its own policy on top, via
// addons.override({ assertClaimsParameter }). Throw to reject; resolve to accept.
export async function assertClaimsParameter(_ctx, _claims, _client) {}

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
