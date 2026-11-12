import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { apiHref, resolveAddress, ROUTES } from 'lib/admin/ui/frame/routes.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

function concrete(pattern: readonly string[]): string {
	return `/admin/${pattern
		.map((segment) =>
			segment.startsWith(':') ? `${segment.slice(1)}-1` : segment
		)
		.join('/')}`;
}

function get(path: string, cookie?: string): Promise<Response> {
	return elysia.handle(
		new Request(`http://e.ly${path}`, {
			headers: cookie ? { cookie } : {}
		})
	);
}

/* The address the server rendered the console at, read back from what the bundle hydrates with. */
function renderedPath(html: string): string | undefined {
	const props = /window\.PROPS=(\{.*?\})<\/script>/.exec(html)?.[1];
	if (!props) return undefined;
	return (JSON.parse(props) as { path?: string }).path;
}

let cookie: string;

/**
 * @proves Every console screen has an address of its own: a link, a bookmark or a reload opens that
 * screen, an address no screen matches says so, and a signed-out visit returns to it after sign-in.
 */
describe('console addresses', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		const user = await createAdministrator(
			'super',
			`addresses-${Date.now()}@x.io`
		);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
	});

	it('every address in the route table renders the console at that address', async () => {
		for (const route of ROUTES) {
			const path = concrete(route.pattern);
			const res = await get(path, cookie);
			expect({ path, status: res.status }).toEqual({ path, status: 200 });
			expect(res.headers.get('content-type')).toContain('text/html');
			expect(renderedPath(await res.text())).toBe(path);
		}
	});

	it('an address no screen matches is answered page not found with status 404', async () => {
		const res = await get('/admin/no-such-screen', cookie);
		expect(res.status).toBe(404);
		expect(res.headers.get('content-type')).toContain('text/html');
	});

	it('a mistyped console API address stays a JSON 404, never a page', async () => {
		const res = await get('/admin/api/no-such-route', cookie);
		expect(res.status).toBe(404);
		expect(res.headers.get('content-type')).not.toContain('text/html');
	});

	it('a signed-out request for a console address is sent to sign-in carrying that address', async () => {
		const res = await get('/admin/projects/b-1/keys?tab=retired');
		expect(res.status).toBe(302);
		const location = new URL(res.headers.get('location') ?? '', 'http://e.ly');
		expect(location.pathname).toBe('/admin/login');
		expect(location.searchParams.get('next')).toBe(
			'/admin/projects/b-1/keys?tab=retired'
		);
	});

	/*
	 * A held deprovisioning email names its connection's page by address, and emails sent before specs/100
	 * still say `/admin/buckets/...`: the link in an administrator's inbox must keep opening that page.
	 */
	it('an address from a held-connection email sent before the rename opens the same page at its new address', async () => {
		const res = await get('/admin/buckets/b-1/provisioning/conn-1', cookie);
		expect(res.status).toBe(302);
		expect(res.headers.get('location')).toBe(
			'/admin/projects/b-1/provisioning/conn-1'
		);
	});

	/*
	 * An API is named by its identifier, a URL, so its page's address carries slashes, a port and possibly a
	 * significant trailing slash inside one segment (specs/132 FR-004).
	 */
	it.each([
		'https://mcp.example.test/mcp',
		'https://mcp.example.test:8443/a/b',
		'https://api.example.test/v1/'
	])(
		'an API page address opens that exact API on that tab: %s',
		async (identifier) => {
			for (const [tab, key] of [
				[undefined, 'bucket.api'],
				['access', 'bucket.api.access'],
				['settings', 'bucket.api.settings']
			] as const) {
				const path = apiHref('b-1', identifier, tab);
				const resolved = resolveAddress(path);
				expect(resolved).toMatchObject({
					kind: 'page',
					route: { key, params: { project: 'b-1', api: identifier } }
				});
				const res = await get(path, cookie);
				expect({ path, status: res.status }).toEqual({ path, status: 200 });
				expect(
					resolveAddress(renderedPath(await res.text()) ?? '')
				).toMatchObject({
					kind: 'page',
					route: { key, params: { project: 'b-1', api: identifier } }
				});
			}
		}
	);

	it('the invitation link from the mail opens the accept page without a session', async () => {
		const res = await get('/admin/accept-invitation?token=abc');
		expect(res.status).toBe(200);
		const html = await res.text();
		expect(html).toContain('Accept the invitation');
		expect(html).toContain('"me":null');
	});
});
