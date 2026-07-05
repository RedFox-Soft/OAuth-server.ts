import crypto from 'node:crypto';
import epochTime from '../helpers/epoch_time.js';
import { BaseModel } from './base_model.js';
import type { BaseModelPayloadType } from './base_model.js';

export type ReplayDetectionPayloadType = BaseModelPayloadType & { iss: string };

export class ReplayDetection extends BaseModel {
	static async unique(iss: string, jti: string, exp: number) {
		const id = crypto.hash('sha256', `${iss}${jti}`, 'base64url');

		const found = await this.find(id);

		if (found) {
			return false;
		}

		const payload = { jti: id, iss };
		const inst = new this(payload);

		await inst.save(exp - epochTime());

		return true;
	}
}
