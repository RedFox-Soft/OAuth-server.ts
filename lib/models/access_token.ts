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
	groupsSource: t.Optional(t.String()),
	/*
	 * When and how the person signed in, for a token issued after a person's interactive sign-in (specs/124 FR-019,
	 * RFC 9068 §2.2.1): what a check at the proxy tells a person's token from a machine's by, and what a later
	 * step-up compares. A refresh carries the original; a grant with no interactive sign-in carries none.
	 */
	authTime: t.Optional(t.Number()),
	acr: t.Optional(t.String()),
	amr: t.Optional(t.Array(t.String()))
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
