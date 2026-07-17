import { t } from 'elysia';

export const CreateBucketBody = t.Object({
	name: t.String({ minLength: 1 }),
	roles: t.Optional(t.Array(t.String())),
	managedBy: t.Optional(t.Array(t.String()))
});
