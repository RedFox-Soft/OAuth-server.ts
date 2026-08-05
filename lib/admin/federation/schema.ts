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
	id: t.String({ minLength: 1, maxLength: 32 }),
	displayName: t.String({ minLength: 1 }),
	issuer: t.String({ minLength: 1 }),
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
