import { t } from 'elysia';

export const CreateProjectBody = t.Object({
	name: t.String({ minLength: 1 }),
	slug: t.String({ pattern: '^[a-z0-9-]+$' }),
	managedBy: t.Optional(t.Array(t.String()))
});

export const UpdateProjectBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	managedBy: t.Optional(t.Array(t.String()))
});

export const SetBucketBody = t.Object({
	bucketId: t.String()
});
