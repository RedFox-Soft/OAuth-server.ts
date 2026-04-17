import { type BaseModel, type BaseModelPayloadType } from '../base_model.js';

type ConsumdedPayload = BaseModelPayloadType & { consumed?: boolean };
type Opt<T, K extends keyof T> = Partial<Pick<T, K>> & Omit<T, K>;

export default function consumable<TPayload extends ConsumdedPayload>(
	superclass: typeof BaseModel<TPayload>
) {
	return class extends superclass {
		constructor(payload: Opt<TPayload, 'consumed'>) {
			payload.consumed ??= false;
			super(payload as TPayload);
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
