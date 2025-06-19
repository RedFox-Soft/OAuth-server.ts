import epochTime from '../helpers/epoch_time.ts';
import { BaseToken } from './base_token.js';

import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import hasGrantId from './mixins/has_grant_id.ts';
import hasGrantType from './mixins/has_grant_type.ts';
import isSenderConstrained from './mixins/is_sender_constrained.ts';
import isSessionBound from './mixins/is_session_bound.ts';
import storesAuth from './mixins/stores_auth.ts';

export default (provider) =>
	class RefreshToken extends apply([
		consumable,
		hasGrantType,
		hasGrantId,
		isSenderConstrained,
		isSessionBound,
		storesAuth,
		BaseToken
	]) {
		constructor(...args) {
			super(...args);
			if (!this.iiat) {
				this.iiat = this.iat || epochTime();
			}
		}

		static get IN_PAYLOAD() {
			return [...super.IN_PAYLOAD, 'rar', 'rotations', 'iiat'];
		}

		/*
		 * totalLifetime()
		 * number of seconds since the very first refresh token chain iat
		 */
		totalLifetime() {
			return epochTime() - this.iiat;
		}
	};
