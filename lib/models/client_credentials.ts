import { Type as t, type Static } from '@sinclair/typebox';
import constrained from './mixins/is_sender_constrained.js';
import { BaseToken, BaseTokenPayload, AudiencePayload } from './base_token.js';
import { ttl } from '../configs/liveTime.js';

export const ClientCredentialsPayload = t.Object({
	...BaseTokenPayload.properties,
	...AudiencePayload.properties,
	scope: t.Optional(t.String()),
	'x5t#S256': t.Optional(t.String()),
	jkt: t.Optional(t.String()),
	/*
	 * A provisioning connection's token only: which of its secrets obtained it, as the first 16 hex characters
	 * of that secret's digest (specs/088 R2). What lets an administrator's end of one secret stop its tokens
	 * and leave the other's working. Never in an introspection answer, which lists its members by name.
	 */
	credentialRef: t.Optional(t.String())
});

export type ClientCredentialsPayload = Static<typeof ClientCredentialsPayload>;

export class ClientCredentials extends constrained(
	BaseToken<ClientCredentialsPayload>
) {
	static schema = ClientCredentialsPayload;

	get expiration(): number {
		return (this.expiresIn ||= ttl.ClientCredentials(this, this.client));
	}
}
