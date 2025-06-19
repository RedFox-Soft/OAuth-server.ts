import crypto from 'node:crypto';
import epochTime from '../helpers/epoch_time.js';
import { BaseModel } from './base_model.js';

export class ReplayDetection extends BaseModel {
	static get IN_PAYLOAD() {
		return [...super.IN_PAYLOAD, 'iss'];
	}

	static async unique(iss, jti, exp) {
		const id = crypto.hash('sha256', `${iss}${jti}`, 'base64url');

		const found = await this.find(id);

		if (found) {
			return false;
		}

		const inst = this.instantiate({ jti: id, iss });

		await inst.save(exp - epochTime());

		return true;
	}
}
