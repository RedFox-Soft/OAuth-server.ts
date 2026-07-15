import crypto from 'node:crypto';
import { Type as t, type Static } from '@sinclair/typebox';
import epochTime from '../helpers/epoch_time.js';
import { BaseModel, BaseModelPayload } from './base_model.js';

const ReplayDetectionPayload = t.Composite([
	BaseModelPayload,
	t.Object({
		iss: t.String()
	})
]);
export type ReplayDetectionPayloadType = Static<typeof ReplayDetectionPayload>;

export class ReplayDetection extends BaseModel<ReplayDetectionPayloadType> {
	model = ReplayDetectionPayload;

	static async unique(iss: string, jti: string, exp: number) {
		const id = crypto.hash('sha256', `${iss}${jti}`, 'base64url');

		const found = await this.tryFind(id);

		if (found) {
			return false;
		}

		const payload = { jti: id, iss };
		const inst = new this(payload);

		await inst.save(exp - epochTime());

		return true;
	}
}
