import constantEquals from '../helpers/constant_equals.ts';
import { BaseToken } from './base_token.js';

import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import hasGrantId from './mixins/has_grant_id.ts';
import isSessionBound from './mixins/is_session_bound.ts';
import storesAuth from './mixins/stores_auth.ts';

export class DeviceCode extends apply([
	consumable,
	hasGrantId,
	isSessionBound,
	storesAuth,
	BaseToken
]) {
	static async findByUserCode(userCode, { ignoreExpiration = false } = {}) {
		const stored = await this.adapter.findByUserCode(userCode);
		if (!stored) return;
		try {
			const payload = await this.verify(stored, { ignoreExpiration });
			if (!constantEquals(userCode, payload.userCode)) {
				return;
			}
			return this.instantiate(payload);
		} catch (err) {
			return;
		}
	}

	static get IN_PAYLOAD() {
		return [
			...super.IN_PAYLOAD,
			'error',
			'errorDescription',
			'params',
			'userCode',
			'inFlight',
			'deviceInfo'
		];
	}
}
