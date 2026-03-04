import { Type as t, type Static } from '@sinclair/typebox';
import { BaseToken, BaseTokenPayload } from './base_token.js';
import consumable from './mixins/consumable.js';
import { authPayloadModel } from './mixins/stores_auth.js';

const AuthorizationCodePayload = t.Composite([
	BaseTokenPayload,
	authPayloadModel,
	t.Object({
		codeChallenge: t.Optional(t.String()),
		codeChallengeMethod: t.Optional(t.Literal('S256')),
		redirectUri: t.Optional(t.String({ format: 'uri' })),
		dpopJkt: t.Optional(t.String()),
		rar: t.Optional(t.Array(t.Object({}))),
		consumed: t.Boolean()
	})
]);
export type AuthorizationCodePayloadType = Static<
	typeof AuthorizationCodePayload
>;

export class AuthorizationCode extends consumable<AuthorizationCodePayloadType>(
	BaseToken<AuthorizationCodePayloadType>
) {
	model = AuthorizationCodePayload;
	static isSessionBound = true;
}
