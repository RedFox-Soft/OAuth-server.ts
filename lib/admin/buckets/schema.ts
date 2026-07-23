import { t } from 'elysia';

const VerificationMethod = t.Union([t.Literal('link'), t.Literal('code')]);

export const CreateBucketBody = t.Object({
	name: t.String({ minLength: 1 }),
	roles: t.Optional(t.Array(t.String())),
	managedBy: t.Optional(t.Array(t.String())),
	registrationOpen: t.Optional(t.Boolean()),
	emailVerificationRequired: t.Optional(t.Boolean()),
	verificationMethod: t.Optional(VerificationMethod)
});

export const UpdateBucketBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	roles: t.Optional(t.Array(t.String())),
	managedBy: t.Optional(t.Array(t.String())),
	registrationOpen: t.Optional(t.Boolean()),
	emailVerificationRequired: t.Optional(t.Boolean()),
	verificationMethod: t.Optional(VerificationMethod)
});
