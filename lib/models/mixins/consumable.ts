import { type BaseModel, type BaseModelPayloadType } from '../base_model.js';

type ConsumdedPayload = BaseModelPayloadType & { consumed: boolean };

export default function consumable<TPayload extends ConsumdedPayload>(
	superclass: typeof BaseModel<TPayload>
) {
	return class extends superclass {
		constructor(payload: TPayload) {
			if (typeof payload.consumed === 'undefined') {
				payload.consumed = false;
			}
			super(payload);
		}

		async consume() {
			await this.adapter.consume(this.id);
			this.emit('consumed');
		}

		get isValid() {
			return !this.payload.consumed && !this.isExpired;
		}
	};
}
