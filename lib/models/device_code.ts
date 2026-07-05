import { Type as t, type Static } from '@sinclair/typebox';
import constantEquals from '../helpers/constant_equals.ts';
import {
	BaseToken,
	BaseTokenPayload,
	SessionBoundPayload
} from './base_token.js';

import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import { authPayloadModel } from './mixins/stores_auth.js';

const DeviceCodePayload = t.Composite([
	BaseTokenPayload,
	SessionBoundPayload,
	authPayloadModel,
	t.Object({
		consumed: t.Boolean(),
		error: t.Optional(t.String()),
		errorDescription: t.Optional(t.String()),
		params: t.Optional(t.Unknown()),
		userCode: t.Optional(t.String()),
		inFlight: t.Optional(t.Boolean()),
		deviceInfo: t.Optional(t.Unknown())
	})
]);
export type DeviceCodePayloadType = Static<typeof DeviceCodePayload>;

export class DeviceCode extends apply([consumable, BaseToken]) {
	model = DeviceCodePayload;

	static async findByUserCode(userCode, { ignoreExpiration = false } = {}) {
		const stored = await this.adapter.findByUserCode(userCode);
		if (!stored) return;
		try {
			const payload = await this.verify(stored, { ignoreExpiration });
			if (!constantEquals(userCode, payload.userCode)) {
				return;
			}
			return new this(payload);
		} catch (err) {
			return;
		}
	}

	static isSessionBound = true;
}
