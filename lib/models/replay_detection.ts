import crypto from 'node:crypto';
import { Type as t, type Static } from '@sinclair/typebox';
import epochTime from '../helpers/epoch_time.js';
import { BaseModel, BaseModelPayload } from './base_model.js';

export const ReplayDetectionPayload = t.Object({
	...BaseModelPayload.properties,
	iss: t.String()
});
export type ReplayDetectionPayloadType = Static<typeof ReplayDetectionPayload>;

export class ReplayDetection extends BaseModel<ReplayDetectionPayloadType> {
	static schema = ReplayDetectionPayload;

	/*
	 * Whether this is the first time the identifier was presented. One insert-if-absent rather than a
	 * lookup and a save: with those two, several requests presenting the same captured assertion or
	 * DPoP proof at once all looked before any saved, and every one of them was told it was first.
	 */
	static async unique(iss: string, jti: string, exp: number) {
		const id = crypto.hash('sha256', `${iss}${jti}`, 'base64url');
		const inst = new this({ jti: id, iss });
		/* At least a second: an identifier whose window has already closed is refused one layer up. */
		const ttl = Math.max(1, exp - epochTime());
		inst.payload.exp = epochTime() + ttl;

		// What save() would have stored, stored only if nothing live holds the identifier.
		const { payload } = await inst.getValueAndPayload();
		if (!payload) throw new TypeError('a replay record must have a payload');
		return this.adapter.create(id, payload, ttl);
	}
}
