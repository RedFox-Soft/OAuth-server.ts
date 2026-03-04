import { Type as t, type Static } from '@sinclair/typebox';
import consumable from './mixins/consumable.js';
import { BaseModel, BaseModelPayload } from './base_model.js';
import nanoid from 'lib/helpers/nanoid.js';

const PushedAuthorizationRequestPayload = t.Composite([
	BaseModelPayload,
	t.Object({
		request: t.String(),
		dpopJkt: t.Optional(t.String()),
		trusted: t.Optional(t.Boolean()),
		consumed: t.Boolean()
	})
]);
type PushedAuthorizationRequestPayloadType = Static<
	typeof PushedAuthorizationRequestPayload
>;

export class PushedAuthorizationRequest extends consumable<PushedAuthorizationRequestPayloadType>(
	BaseModel
) {
	model = PushedAuthorizationRequestPayload;

	generateTokenId() {
		return nanoid();
	}
}
