import { t } from 'elysia';

/*
 * `corsOrigins` is typed only as an array of strings here. The origin rule itself lives in
 * lib/helpers/cors_origin.ts and runs in the handler, so a rejection returns the admin_error shape and
 * can name the offending value — a TypeBox pattern would produce a generic validation error that tells
 * an operator nothing about which entry was wrong or what it should have been.
 */
export const CreateProjectBody = t.Object({
	name: t.String({ minLength: 1 }),
	slug: t.String({ pattern: '^[a-z0-9-]+$' }),
	managedBy: t.Optional(t.Array(t.String())),
	corsOrigins: t.Optional(t.Array(t.String()))
});

export const UpdateProjectBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	managedBy: t.Optional(t.Array(t.String())),
	corsOrigins: t.Optional(t.Array(t.String()))
});

export const SetBucketBody = t.Object({
	bucketId: t.String()
});
