import { Type as t, type Static } from '@sinclair/typebox';
import {
	BaseToken,
	BaseTokenPayload,
	SessionBoundPayload
} from './base_token.js';
import apply from './mixins/apply.ts';
import consumable from './mixins/consumable.ts';
import { authPayloadModel } from './mixins/stores_auth.js';

const BackchannelAuthenticationRequestPayload = t.Composite([
	BaseTokenPayload,
	SessionBoundPayload,
	authPayloadModel,
	t.Object({
		consumed: t.Boolean(),
		error: t.Optional(t.String()),
		errorDescription: t.Optional(t.String()),
		params: t.Optional(t.Unknown())
	})
]);
export type BackchannelAuthenticationRequestPayloadType = Static<
	typeof BackchannelAuthenticationRequestPayload
>;

export default () =>
	class BackchannelAuthenticationRequest extends apply([
		consumable,
		BaseToken
	]) {
		model = BackchannelAuthenticationRequestPayload;
		static isSessionBound = true;
	};
