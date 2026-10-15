import { describe, it, expect, beforeAll } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { adminApp } from 'lib/admin/index.ts';
import { Type } from '@sinclair/typebox';
import bootstrap, { agent } from '../test_helper.js';
import { shaped } from 'test/shape.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from './ownership_fixtures.ts';

// adminApp's own onError must keep request-validation failures in the admin
// `{ error, message }` shape rather than letting them fall through to the global
// OAuth (RFC 6749) error handler used by the protocol routes.
const app = new Elysia().use(adminApp);
const client = treaty(app);

/**
 * @proves An administrative failure reaches the console and the agent in the admin error shape
 * rather than as an OAuth body, including once adminApp is mounted on the root app; a refusal about
 * one field names that field; and a rejected request body is never sent back.
 */
describe('admin API error shape', () => {
	it('returns an admin-shaped validation error, not an OAuth body', async () => {
		// name (minLength 1) and slug (pattern) are both invalid values → VALIDATION.
		const res = await client.admin.api.buckets.post({
			name: '',
			slug: ''
		});
		expect(res.status).toBe(422);
		const body = res.error?.value;
		expect(body).toMatchObject({ error: 'invalid_request' });
		expect(body).not.toHaveProperty('error_description');
	});
});

/* A body the schema refuses, sent as the console would send it: no session is needed to be refused. */
async function rejected(
	path: string,
	body: Record<string, unknown>,
	cookie = ''
): Promise<{ status: number; text: string }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json', cookie },
			body: JSON.stringify(body)
		})
	);
	return { status: response.status, text: await response.text() };
}

const Refusal = Type.Object({
	error: Type.String(),
	message: Type.String(),
	field: Type.Optional(Type.String())
});

describe('admin refusals', () => {
	it('never echoes a rejected request body back in the 422 answer', async () => {
		const marker = 'Mk-7f3a9';

		const { status, text } = await rejected('/admin/api/admins', {
			email: 'new-admin@x.io',
			password: marker
		});

		expect(status).toBe(422);
		expect(text).not.toContain(marker);
	});

	it('never echoes a value of the wrong type back in the 422 answer', async () => {
		const marker = 731_942_658_013;

		const { status, text } = await rejected('/admin/api/admins', {
			email: 'new-admin@x.io',
			password: marker
		});

		expect(status).toBe(422);
		expect(text).not.toContain(String(marker));
	});

	it('names the field a request body was rejected for', async () => {
		const { status, text } = await rejected('/admin/api/admins', {
			email: 'new-admin@x.io',
			password: 'short'
		});

		expect(status).toBe(422);
		expect(shaped(Refusal, JSON.parse(text))).toMatchObject({
			error: 'invalid_request',
			field: 'password'
		});
	});

	it('names the slug when a new bucket asks for one already taken', async () => {
		const slug = `taken-${nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '')}`;
		const holder = await createAdministrator();
		await getBucketStore().create({
			name: 'Holder',
			slug,
			ownerGroupId: 'unassigned'
		});

		const { status, text } = await rejected(
			'/admin/api/buckets',
			{ name: 'Second', slug },
			await cookieFor(holder)
		);

		expect(status).toBe(409);
		expect(shaped(Refusal, JSON.parse(text)).field).toBe('slug');
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
		const res = await agent.admin.api.buckets.get();

		expect(res.status).toBe(401);
		const body = shaped(
			Type.Object({ error: Type.String(), message: Type.String() }),
			res.data ?? res.error.value
		);
		expect(body.error).toBe('admin_error');
		expect(body.message).toBe('authentication required');
		expect(body).not.toHaveProperty('error_description');
	});
});
