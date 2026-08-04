import { describe, it, expect, beforeAll } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { adminApp } from 'lib/admin/index.ts';
import bootstrap, { agent } from '../test_helper.js';

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

// Mounting adminApp on its own — which every other spec in this directory does — proves nothing about
// the real server. The root app registers the OAuth error handler *before* adminApp, so that handler
// answered first and every admin API error reached callers as `{ error: 'server_error',
// error_description: 'An unexpected error occurred' }`: right status, wrong shape, message gone. The
// admin console and any MCP agent both parse that body, so this is asserted against the composed app.
describe('admin API error shape through the real app', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('keeps the admin shape when adminApp is mounted on the root app', async () => {
		const res = await agent.admin.api.projects.get();

		expect(res.status).toBe(401);
		const body = (res.data ?? res.error?.value) as
			{ error?: string; message?: string } | undefined;
		expect(body?.error).toBe('admin_error');
		expect(body?.message).toBe('authentication required');
		expect(body).not.toHaveProperty('error_description');
	});
});
