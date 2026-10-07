import { Type as t, type Static } from '@sinclair/typebox';
import constrained from './mixins/is_sender_constrained.js';
import {
	BaseToken,
	BaseTokenPayload,
	SessionBoundPayload,
	AudiencePayload
} from './base_token.js';
import { ttl } from '../configs/liveTime.js';

export const AccessTokenPayload = t.Object({
	...BaseTokenPayload.properties,
	...SessionBoundPayload.properties,
	...AudiencePayload.properties,
	rar: t.Optional(t.Array(t.Object({}, { additionalProperties: true }))),
	claims: t.Optional(t.Object({})),
	scope: t.Optional(t.String()),
	sid: t.Optional(t.String()),
	gty: t.Optional(t.String()),
	'x5t#S256': t.Optional(t.String()),
	jkt: t.Optional(t.String()),
	/*
	 * The user's groups when the authorization granted `groups` and the token is for a resource (specs/071
	 * research R9): the display names, or — above GROUPS_TOKEN_LIMIT — the userinfo URL to fetch them from.
	 */
	groups: t.Optional(t.Array(t.String())),
	groupsSource: t.Optional(t.String())
});
export type AccessTokenPayloadType = Static<typeof AccessTokenPayload>;

export class AccessToken extends constrained<AccessTokenPayloadType>(
	BaseToken
) {
	static schema = AccessTokenPayload;
	static isSessionBound = true;

	get expiration(): number {
		return (this.expiresIn ||= ttl.AccessToken(this, this.client));
	}
}
