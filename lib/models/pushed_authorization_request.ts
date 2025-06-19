import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import { BaseModel } from './base_model.js';
import nanoid from 'lib/helpers/nanoid.js';

export class PushedAuthorizationRequest extends apply([consumable, BaseModel]) {
	static get IN_PAYLOAD() {
		return [...super.IN_PAYLOAD, 'request', 'dpopJkt', 'trusted'];
	}

	generateTokenId() {
		return nanoid();
	}
}
