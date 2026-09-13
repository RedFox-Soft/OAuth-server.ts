import { merge } from 'lib/helpers/_/object.js';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 */
export default function assignClaims(oidc) {
	const { params } = oidc;

	if (
		params.claims !== undefined &&
		ApplicationConfig['claimsParameter.enabled']
	) {
		oidc.claims = params.claims;
	}

	if (
		params.max_age !== undefined ||
		oidc.client.requireAuthTime ||
		oidc.prompts.has('login')
	) {
		merge(oidc.claims, { id_token: { auth_time: { essential: true } } });
	}

	const acrValues = params.acr_values;

	/*
	 * An individual `acr` claim request is authoritative, and `acr_values` alongside it does not
	 * alter its `essential` flag or its acceptable values.
	 *
	 * Two rules meet here. OIDC Registration §2 has `acr_values` **or an individual acr claim
	 * request** override a client's `default_acr_values`, and the defaults arrive as `acr_values`
	 * (assign_defaults), so merging over the claim request would let a registered default silently
	 * replace what this request asked for. OIDC Core §5.5.1.1 then leaves the client sending *both*
	 * forms explicitly unspecified — so what is owed there is determinism, not a particular winner,
	 * and merging was not deterministic in the way that matters: it kept `essential: true` from one
	 * form and took `values` from the other, composing a requirement the client never expressed.
	 */
	if (acrValues && !oidc.claims?.id_token?.acr) {
		merge(oidc.claims, {
			id_token: { acr: { values: acrValues.split(' ') } }
		});
	}
}
