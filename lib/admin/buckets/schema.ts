import { t } from 'elysia';

const VerificationMethod = t.Union([t.Literal('link'), t.Literal('code')]);

/*
 * `passwordLogin` is here; `federation` deliberately is not. Providers are reachable only through their own
 * routes, so a bucket PATCH cannot replace a set of upstream secrets in a request whose audit entry would
 * say only `federation` — and write-time issuer validation keeps a single choke point.
 */
export const CreateBucketBody = t.Object({
	name: t.String({ minLength: 1 }),
	roles: t.Optional(t.Array(t.String())),
	managedBy: t.Optional(t.Array(t.String())),
	passwordLogin: t.Optional(t.Boolean()),
	registrationOpen: t.Optional(t.Boolean()),
	emailVerificationRequired: t.Optional(t.Boolean()),
	verificationMethod: t.Optional(VerificationMethod)
});

export const UpdateBucketBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	roles: t.Optional(t.Array(t.String())),
	managedBy: t.Optional(t.Array(t.String())),
	passwordLogin: t.Optional(t.Boolean()),
	registrationOpen: t.Optional(t.Boolean()),
	emailVerificationRequired: t.Optional(t.Boolean()),
	verificationMethod: t.Optional(VerificationMethod)
});
