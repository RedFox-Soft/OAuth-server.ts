import { BaseToken } from './base_token.js';
import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import hasGrantId from './mixins/has_grant_id.ts';
import isSessionBound from './mixins/is_session_bound.ts';
import storesAuth from './mixins/stores_auth.ts';
import storesPKCE from './mixins/stores_pkce.ts';

export class AuthorizationCode extends apply([
	consumable,
	isSessionBound,
	hasGrantId,
	storesAuth,
	storesPKCE,
	BaseToken
]) {
	static get IN_PAYLOAD() {
		return [...super.IN_PAYLOAD, 'redirectUri', 'dpopJkt', 'rar'];
	}
}
