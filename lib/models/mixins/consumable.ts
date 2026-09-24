import { Type as t } from '@sinclair/typebox';
import { type BaseModel, type BaseModelPayloadType } from '../base_model.js';

/*
 * `false` until the item is consumed; then the second it was consumed at, which is what every adapter's
 * `consume` writes (memory, MongoDB and PostgreSQL alike). Declared as the boolean alone, the type said
 * a consumed item could not be read back.
 */
export const ConsumedPayload = t.Union([t.Boolean(), t.Number()]);

type ConsumdedPayload = BaseModelPayloadType & { consumed?: boolean | number };

// Generic over the concrete base class (TBase) rather than a fixed
// `typeof BaseModel`. Extending the type parameter preserves the passed class's
// own static members (e.g. BaseToken.revokeByGrantId), which a fixed parameter
// type would erase down to BaseModel's statics.
export default function consumable<
	TBase extends new (...args: any[]) => BaseModel<ConsumdedPayload>
>(superclass: TBase) {
	return class extends superclass {
		constructor(...args: any[]) {
			const [payload] = args as [ConsumdedPayload];
			payload.consumed ??= false;
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
