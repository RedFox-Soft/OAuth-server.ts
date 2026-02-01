import { Grant } from './grant.js';

export class TrustedGrant extends Grant {
	getOIDCScopeFiltered(filter) {
		return Array.from(filter).join(' ');
	}

	getResourceScopeFiltered(_resource, filter) {
		return Array.from(filter).join(' ');
	}

	getOIDCClaimsFiltered(filter) {
		return Array.from(filter);
	}
}
