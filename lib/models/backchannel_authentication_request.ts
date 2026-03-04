import { BaseToken } from './base_token.js';
import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import { authPayload } from './mixins/stores_auth.js';

export default () =>
	class BackchannelAuthenticationRequest extends apply([
		consumable,
		BaseToken
	]) {
		static isSessionBound = true;
		static get IN_PAYLOAD() {
			return [
				...super.IN_PAYLOAD,
				...authPayload,
				'grantId',
				'error',
				'errorDescription',
				'params'
			];
		}
	};
