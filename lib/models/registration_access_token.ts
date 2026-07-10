import { Type as t, type Static } from '@sinclair/typebox';
import { BaseToken, BaseTokenPayload } from './base_token.js';
import hasPolicies from './mixins/has_policies.ts';

const RegistrationAccessTokenPayload = t.Composite([
	BaseTokenPayload,
	t.Object({
		policies: t.Optional(t.Array(t.String()))
	})
]);
export type RegistrationAccessTokenPayloadType = Static<
	typeof RegistrationAccessTokenPayload
>;

export class RegistrationAccessToken extends hasPolicies(BaseToken) {
	model = RegistrationAccessTokenPayload;
}
