import { Type as t, type Static } from '@sinclair/typebox';
import { BaseModelPayload } from './base_model.js';
import { BaseToken, BaseTokenPayload } from './base_token.js';
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

export class InitialAccessToken extends hasPolicies(BaseToken) {
	// Cast: this schema omits the clientId that BaseToken's model type requires (see above).
	model = InitialAccessTokenPayload as unknown as typeof BaseTokenPayload;
}
