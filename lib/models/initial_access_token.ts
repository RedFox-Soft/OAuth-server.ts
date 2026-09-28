import { Type as t, type Static } from '@sinclair/typebox';
import { BaseModelPayload } from './base_model.js';
import { BaseToken, type BaseTokenPayloadType } from './base_token.js';
import hasPolicies from './mixins/has_policies.ts';

// InitialAccessTokens are not client-bound, so the schema omits clientId (unlike other
// BaseToken descendants) and only persists the policies alongside the base fields.
export const InitialAccessTokenPayload = t.Object({
	...BaseModelPayload.properties,
	policies: t.Optional(t.Array(t.String()))
});
export type InitialAccessTokenPayloadType = Static<
	typeof InitialAccessTokenPayload
>;

// Parameterised with the policies it carries; the base token type still names a clientId the schema omits.
export class InitialAccessToken extends hasPolicies<
	BaseTokenPayloadType & { policies?: string[] }
>(BaseToken) {
	static schema = InitialAccessTokenPayload;
}
