import { t } from 'elysia';

const Provisioning = t.Union([t.Literal('jit'), t.Literal('existing_only')]);

/*
 * The provider bodies.
 *
 * Only `id`, `displayName`, `issuer`, `clientId` and `clientSecret` are required on create; everything else
 * has a default that is the safe reading — password-style trust off, no domain restriction, `email` as the
 * address claim. The shapes are validated here and the *rules* in ./validate.ts, so a rule reachable from
 * two routes has one definition.
 */
export const CreateProviderBody = t.Object({
	/*
	 * Names a recognised provider whose settings fill everything an administrator would otherwise have to
	 * know — so `id`, `displayName` and `issuer` become optional, and only the two values the upstream
	 * itself issues stay required.
	 *
	 * The field is consumed and discarded: it selects defaults, it is never stored, and the provider it
	 * produces is indistinguishable from one configured field by field. "Required unless a catalogue entry
	 * supplies it" is enforced once in ./service.ts rather than expressed as a schema union, so a body that
	 * names no entry and omits an issuer is refused with the message it has always been refused with.
	 */
	catalogueId: t.Optional(t.String({ minLength: 1 })),
	id: t.Optional(t.String({ minLength: 1, maxLength: 32 })),
	displayName: t.Optional(t.String({ minLength: 1 })),
	issuer: t.Optional(t.String({ minLength: 1 })),
	clientId: t.String({ minLength: 1 }),
	clientSecret: t.String({ minLength: 1 }),
	enabled: t.Optional(t.Boolean()),
	scopes: t.Optional(t.Array(t.String({ minLength: 1 }))),
	emailTrusted: t.Optional(t.Boolean()),
	provisioning: t.Optional(Provisioning),
	allowedEmailDomains: t.Optional(t.Array(t.String({ minLength: 1 }))),
	emailClaim: t.Optional(t.String({ minLength: 1 }))
});

/*
 * `id` is absent: a provider's identifier is in its path and appears in URLs the login page has already
 * rendered, so renaming one is deleting it and creating another.
 *
 * `clientSecret` is optional, and **absent means unchanged** — an operator renaming a provider should not
 * have to re-type a secret. The stored value can therefore only be replaced deliberately.
 */
export const UpdateProviderBody = t.Object({
	displayName: t.Optional(t.String({ minLength: 1 })),
	issuer: t.Optional(t.String({ minLength: 1 })),
	clientId: t.Optional(t.String({ minLength: 1 })),
	clientSecret: t.Optional(t.String({ minLength: 1 })),
	enabled: t.Optional(t.Boolean()),
	scopes: t.Optional(t.Array(t.String({ minLength: 1 }))),
	emailTrusted: t.Optional(t.Boolean()),
	provisioning: t.Optional(Provisioning),
	allowedEmailDomains: t.Optional(t.Array(t.String({ minLength: 1 }))),
	emailClaim: t.Optional(t.String({ minLength: 1 }))
});
