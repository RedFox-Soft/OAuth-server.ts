import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ROUTES, resolveAddress } from 'lib/admin/ui/frame/routes.ts';
import { ACTIONS } from 'lib/admin/ui/frame/actions.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

function concrete(pattern: readonly string[]): string {
	return `/admin/${pattern
		.map((segment) =>
			segment.startsWith(':') ? `${segment.slice(1)}-1` : segment
		)
		.join('/')}`;
}

async function shell(path: string, cookie: string): Promise<string> {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, { headers: { cookie } })
	);
	return res.text();
}

/* The menu entry the rendered console marks as where the operator is. */
function highlighted(html: string): string | undefined {
	return /ant-menu-item-selected[^>]*data-menu-id="console-menu-([a-z-]+)"/.exec(
		html
	)?.[1];
}

let superCookie: string;
let plainCookie: string;

async function cookieFor(kind: 'super' | 'plain'): Promise<string> {
	const user = await createAdministrator(
		kind,
		`frame-${kind}-${Date.now()}@x.io`
	);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

/**
 * @proves Every console address draws a screen inside the frame, with the menu marking the section the
 * operator is in, and an instance page is withheld from an administrator who is not a super
 * administrator rather than replaced by another page.
 */
describe('console frame', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		superCookie = await cookieFor('super');
		plainCookie = await cookieFor('plain');
	});

	it('for every route-table entry, the console draws a screen and marks its section in the menu', async () => {
		for (const route of ROUTES.filter((r) => r.public !== true)) {
			const path = concrete(route.pattern);
			const html = await shell(path, superCookie);
			expect({ path, notFound: html.includes('Page not found') }).toEqual({
				path,
				notFound: false
			});
			expect({ path, section: highlighted(html) }).toEqual({
				path,
				section: route.section ?? undefined
			});
		}
	});

	it('an instance page opened by an administrator who is not a super administrator says so', async () => {
		for (const route of ROUTES.filter((r) => r.instance === true)) {
			const html = await shell(concrete(route.pattern), plainCookie);
			expect(html).toContain(
				'Only an instance administrator can open this page'
			);
		}
	});

	/*
	 * The console's own bucket moved to the Administrators page (specs/083). A bookmark or a link pasted in a
	 * ticket still names it as a bucket, and must land on the tab that means the same thing.
	 */
	it("an address of the console's bucket leads to the matching Administrators tab", () => {
		const lands = (path: string) => {
			const resolved = resolveAddress(path);
			return resolved.kind === 'redirect' ? resolved.to : resolved.kind;
		};
		expect(lands('/admin/buckets/admin')).toBe('/admin/administrators/sign-in');
		expect(lands('/admin/buckets/admin/identity-providers')).toBe(
			'/admin/administrators/identity-providers'
		);
		expect(lands('/admin/buckets/admin/activity')).toBe(
			'/admin/administrators/activity'
		);
		expect(lands('/admin/buckets/admin/users')).toBe('/admin/administrators');
		// Any other bucket keeps its own addresses.
		expect(lands('/admin/buckets/acme/sign-in')).toBe('page');
	});

	/*
	 * The compiler already refuses an id the table lacks; this is the other direction. A question in the
	 * table that no screen asks is a classification nobody is held to, and usually means a screen stopped
	 * asking it.
	 */
	it('every C1 and C2 action in the confirmation table is asked by some console screen', async () => {
		const asked = new Set<string>();
		for (const file of new Bun.Glob('lib/admin/ui/**/*.tsx').scanSync()) {
			const source = await Bun.file(file).text();
			// Asked through useConfirm, or worded from the table by an inline Popconfirm inside a dialog.
			for (const match of source.matchAll(
				/(?:confirm\(\s*|ACTIONS\[)'([a-zA-Z.]+)'/g
			)) {
				asked.add(match[1]);
			}
		}
		const unasked = Object.entries(ACTIONS)
			.filter(
				([, spec]) =>
					(spec.class === 'C1' || spec.class === 'C2') &&
					!('inline' in spec && spec.inline)
			)
			.map(([id]) => id)
			.filter((id) => !asked.has(id));
		expect(unasked).toEqual([]);
	});
});
