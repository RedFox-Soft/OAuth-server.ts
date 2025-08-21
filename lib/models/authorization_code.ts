import { BaseToken } from './base_token.js';
import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import hasGrantId from './mixins/has_grant_id.ts';
import isSessionBound from './mixins/is_session_bound.ts';
import { authPayload } from './mixins/stores_auth.js';

const pkcePayload = ['codeChallenge', 'codeChallengeMethod'];

export class AuthorizationCode extends apply([
	consumable,
	isSessionBound,
	hasGrantId,
	BaseToken
]) {
	static get IN_PAYLOAD() {
		return [
			...super.IN_PAYLOAD,
			...pkcePayload,
			...authPayload,
			'redirectUri',
			'dpopJkt',
			'rar'
		];
	}
}
