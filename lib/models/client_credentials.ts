import { Type as t, type Static } from '@sinclair/typebox';
import constrained from './mixins/is_sender_constrained.js';
import { BaseToken, BaseTokenPayload, AudiencePayload } from './base_token.js';

export const ClientCredentialsPayload = t.Object({
	...BaseTokenPayload.properties,
	...AudiencePayload.properties,
	scope: t.Optional(t.String()),
	'x5t#S256': t.Optional(t.String()),
	jkt: t.Optional(t.String())
});

export type ClientCredentialsPayload = Static<typeof ClientCredentialsPayload>;

export class ClientCredentials extends constrained(
	BaseToken<ClientCredentialsPayload>
) {
	model = ClientCredentialsPayload;
}
