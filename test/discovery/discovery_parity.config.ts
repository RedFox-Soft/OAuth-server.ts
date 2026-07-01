import getConfig from '../default.config.js';

const config = getConfig();

// Discovery now derives its collections from ApplicationConfig. Mirror the provider's claims
// (base identity/session claims + the default.config claims) so the derived claims_supported /
// scopes_supported reproduce the pre-refactor baseline captured from the same provider config.
export const ApplicationConfig = {
	claims: {
		acr: null,
		sid: null,
		auth_time: null,
		iss: null,
		openid: ['sub'],
		...config.claims
	}
};

export default {
	config
};
