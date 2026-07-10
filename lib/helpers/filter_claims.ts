import { type Grant } from 'lib/models/grant.js';

export default (
	source: Record<string, Record<string, unknown>> | undefined,
	target: string,
	grant: Grant
) => {
	const claims = { ...source?.[target] };
	const requested = Object.keys(claims);
	const granted = new Set(grant.getOIDCClaimsFiltered(new Set(requested)));

	for (const claim of requested) {
		if (['sub', 'sid', 'auth_time', 'acr', 'amr', 'iss'].includes(claim))
			continue;
		if (!granted.has(claim)) {
			delete claims[claim];
		}
	}
	return claims;
};
