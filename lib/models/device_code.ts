import { Type as t, type Static } from '@sinclair/typebox';
import constantEquals from '../helpers/constant_equals.ts';
import {
	BaseToken,
	BaseTokenPayload,
	SessionBoundPayload
} from './base_token.js';

import consumable, { ConsumedPayload } from './mixins/consumable.ts';
import { authPayloadModel } from './mixins/stores_auth.js';
import { ttl } from '../configs/liveTime.js';

export const DeviceCodePayload = t.Object({
	...BaseTokenPayload.properties,
	...SessionBoundPayload.properties,
	...authPayloadModel.properties,
	consumed: ConsumedPayload,
	error: t.Optional(t.String()),
	errorDescription: t.Optional(t.String()),
	params: t.Optional(t.Unknown()),
	userCode: t.Optional(t.String()),
	inFlight: t.Optional(t.Boolean()),
	deviceInfo: t.Optional(t.Unknown())
});
export type DeviceCodePayloadType = Static<typeof DeviceCodePayload>;

export class DeviceCode extends consumable(BaseToken<DeviceCodePayloadType>) {
	declare payload: Omit<DeviceCodePayloadType, 'kind'> & { kind: string };
	model = DeviceCodePayload;

	get expiration(): number {
		return (this.expiresIn ||= ttl.DeviceCode(this, this.client));
	}

	static async findByUserCode(
		userCode: string,
		{ ignoreExpiration = false } = {}
	) {
		const stored = await this.adapter.findByUserCode(userCode);
		if (!stored) return;
		try {
			const payload = await this.verify(stored, { ignoreExpiration });
			if (
				typeof payload.userCode !== 'string' ||
				!constantEquals(userCode, payload.userCode)
			) {
				return;
			}
			return new this(payload);
		} catch (err) {
			return;
		}
	}

	static isSessionBound = true;
}
