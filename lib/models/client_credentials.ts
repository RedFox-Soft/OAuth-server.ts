import setAudience from './mixins/set_audience.ts';
import isSenderConstrained from './mixins/is_sender_constrained.ts';
import apply from './mixins/apply.ts';
import { BaseToken } from './base_token.js';

export default () =>
	class ClientCredentials extends apply([
		setAudience,
		isSenderConstrained,
		BaseToken
	]) {
		static get IN_PAYLOAD() {
			return [...super.IN_PAYLOAD, 'aud', 'extra', 'scope'];
		}
	};
