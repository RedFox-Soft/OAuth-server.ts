import { BaseToken } from './base_token.js';
import apply from './mixins/apply.ts';
import hasPolicies from './mixins/has_policies.ts';

export default (provider) =>
	class RegistrationAccessToken extends apply([
		hasPolicies(provider),
		BaseToken
	]) {};
