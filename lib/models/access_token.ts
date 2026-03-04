import { Type as t, type Static } from '@sinclair/typebox';
import constrained from './mixins/is_sender_constrained.js';
import { BaseToken, BaseTokenPayload } from './base_token.js';

const AccessTokenPayload = t.Composite([
	BaseTokenPayload,
	t.Object({
		rar: t.Optional(t.Object({})),
		claims: t.Optional(t.Object({})),
		extra: t.Optional(t.Object({})),
		scope: t.Optional(t.String()),
		sid: t.Optional(t.String()),
		gty: t.Optional(t.String()),
		'x5t#S256': t.Optional(t.String()),
		jkt: t.Optional(t.String())
	})
]);
type AccessTokenPayloadType = Static<typeof AccessTokenPayload>;

export class AccessToken extends constrained<AccessTokenPayloadType>(
	BaseToken
) {
	model = AccessTokenPayload;
	static isSessionBound = true;
}
