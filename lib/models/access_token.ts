import apply from './mixins/apply.ts';
import hasFormat from './mixins/has_format.ts';
import hasGrantType from './mixins/has_grant_type.ts';
import hasGrantId from './mixins/has_grant_id.ts';
import isSenderConstrained from './mixins/is_sender_constrained.ts';
import isSessionBound from './mixins/is_session_bound.ts';
import setAudience from './mixins/set_audience.ts';
import { BaseToken } from './base_token.js';

export default (provider) =>
	class AccessToken extends apply([
		hasGrantType,
		hasGrantId,
		isSenderConstrained,
		isSessionBound,
		setAudience,
		hasFormat(provider, 'AccessToken', BaseToken)
	]) {
		static get IN_PAYLOAD() {
			return [
				...super.IN_PAYLOAD,

				'accountId',
				'aud',
				'rar',
				'claims',
				'extra',
				'grantId',
				'scope',
				'sid'
			];
		}
	};
