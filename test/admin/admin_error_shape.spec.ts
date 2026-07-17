import { describe, it, expect } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { adminApp } from 'lib/admin/index.ts';

// adminApp's own onError must keep request-validation failures in the admin
// `{ error, message }` shape rather than letting them fall through to the global
// OAuth (RFC 6749) error handler used by the protocol routes.
const app = new Elysia().use(adminApp);
const client = treaty(app);

describe('admin API error shape', () => {
	it('returns an admin-shaped validation error, not an OAuth body', async () => {
		// name (minLength 1) and slug (pattern) are both invalid values → VALIDATION.
		const res = await client.admin.api.projects.post({ name: '', slug: '' });
		expect(res.status).toBe(422);
		const body = res.error?.value as { error?: string } | undefined;
		expect(body).toMatchObject({ error: 'invalid_request' });
		expect(body).not.toHaveProperty('error_description');
	});
});
