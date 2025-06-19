import { BaseToken } from './base_token.js';
import apply from './mixins/apply.ts';
import hasPolicies from './mixins/has_policies.ts';

export default (provider) =>
	class InitialAccessToken extends apply([hasPolicies(provider), BaseToken]) {
		static get IN_PAYLOAD() {
			return super.IN_PAYLOAD.filter((v) => v !== 'clientId');
		}
	};
