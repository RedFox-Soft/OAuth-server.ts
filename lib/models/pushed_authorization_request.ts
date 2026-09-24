import { Type as t, type Static } from '@sinclair/typebox';
import consumable, { ConsumedPayload } from './mixins/consumable.js';
import { BaseModel, BaseModelPayload } from './base_model.js';
import nanoid from 'lib/helpers/nanoid.js';

export const PushedAuthorizationRequestPayload = t.Object({
	...BaseModelPayload.properties,
	request: t.String(),
	dpopJkt: t.Optional(t.String()),
	trusted: t.Optional(t.Boolean()),
	consumed: ConsumedPayload
});
export type PushedAuthorizationRequestPayloadType = Static<
	typeof PushedAuthorizationRequestPayload
>;

export class PushedAuthorizationRequest extends consumable(BaseModel) {
	declare payload: PushedAuthorizationRequestPayloadType & { kind: string };
	model = PushedAuthorizationRequestPayload;

	constructor(
		payload: Omit<PushedAuthorizationRequestPayloadType, 'consumed'> & {
			consumed?: boolean | number;
		}
	) {
		super(payload);
	}

	generateTokenId() {
		return nanoid();
	}
}
