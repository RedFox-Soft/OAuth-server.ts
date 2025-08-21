import { BaseToken } from './base_token.js';
import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import hasGrantId from './mixins/has_grant_id.ts';
import isSessionBound from './mixins/is_session_bound.ts';
import { authPayload } from './mixins/stores_auth.js';

export default () =>
	class BackchannelAuthenticationRequest extends apply([
		consumable,
		hasGrantId,
		isSessionBound,
		BaseToken
	]) {
		static get IN_PAYLOAD() {
			return [
				...super.IN_PAYLOAD,
				...authPayload,
				'error',
				'errorDescription',
				'params'
			];
		}
	};
