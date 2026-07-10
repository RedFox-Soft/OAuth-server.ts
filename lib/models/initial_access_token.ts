import { Type as t, type Static } from '@sinclair/typebox';
import { BaseModelPayload } from './base_model.js';
import { BaseToken } from './base_token.js';
import apply from './mixins/apply.ts';
import hasPolicies from './mixins/has_policies.ts';

// InitialAccessTokens are not client-bound, so the schema omits clientId (unlike other
// BaseToken descendants) and only persists the policies alongside the base fields.
const InitialAccessTokenPayload = t.Composite([
	BaseModelPayload,
	t.Object({
		policies: t.Optional(t.Array(t.String()))
	})
]);
export type InitialAccessTokenPayloadType = Static<
	typeof InitialAccessTokenPayload
>;

export default (provider: object) =>
	class InitialAccessToken extends apply([hasPolicies(provider), BaseToken]) {
		model = InitialAccessTokenPayload;
	};
