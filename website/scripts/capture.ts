import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { chromium, type BrowserContext, type Page } from 'playwright';

/*
 * Screenshots and the Open Graph image, produced at build time and never committed.
 *
 * The server is booted in this process on the in-memory adapter, so the captures always show the
 * console as built from this commit, with demo data that is created fresh every run. Two things
 * about the environment are load-bearing: NODE_ENV=test is what swaps the storage adapter for the
 * in-memory one, and MONGODB_URI/DATABASE_NAME must be *absent* because the adapter index selects the
 * Mongo stores by the presence of the URI — a developer's .env.local would otherwise point the run at
 * a real database. ISSUER must be the address the browser will use.
 */
process.env.NODE_ENV = 'test';
delete process.env.MONGODB_URI;
delete process.env.DATABASE_NAME;
process.env.ISSUER = 'http://localhost:3000';

const ORIGIN = process.env.ISSUER;
const ADMIN = {
	email: 'admin@example.com',
	password: 'Screenshots-Demo-2026!'
};
const USER_PASSWORD = 'AcmeDemo-2026!';
const VIEWPORT = { width: 1440, height: 900 } as const;
const OUT = resolve(import.meta.dir, '../public/screenshots');
const OG_OUT = resolve(import.meta.dir, '../public/og');

/*
 * The server reads three things off the *current working directory* rather than off its own module
 * path — the interaction HTML template (lib/interactions/serverRender.tsx), the console's HTML shell
 * (lib/admin/ui/serverRender.tsx) and the bundled client assets under public/ — so it only works
 * with the repository root as cwd. This script is invoked from website/ by hand and from
 * website/scripts/ by generate.ts, and every path it writes to is absolute, so moving cwd is free
 * here and is what stops the login page answering 500 with an ENOENT for its own template.
 */
process.chdir(resolve(import.meta.dir, '../..'));

/*
 * lib/index.ts listens on :3000 as a side effect of import, and on Windows a second listener binds
 * to an already-bound port silently instead of failing with EADDRINUSE. Without this check the
 * capture would seed a developer's real, Mongo-backed dev server with demo data instead of the
 * in-memory instance it thinks it booted.
 */
async function assertPortFree(): Promise<void> {
	let alreadyServing: boolean;
	try {
		await fetch(`${ORIGIN}/health`);
		alreadyServing = true;
	} catch {
		// A connection error is the expected state (nothing listening yet).
		alreadyServing = false;
	}
	if (alreadyServing) {
		throw new Error(
			'port 3000 is already serving — stop the local server before running the capture'
		);
	}
}
await assertPortFree();

// Dynamic imports so the environment above is in place before lib/ evaluates.
await import('../../lib/index.ts'); // listens on :3000
const { ensureAdminSeed } = await import('../../lib/admin/seed.ts');
await ensureAdminSeed();

async function waitForHealth(): Promise<void> {
	for (let i = 0; i < 50; i++) {
		try {
			if ((await fetch(`${ORIGIN}/health`)).ok) return;
		} catch {
			/* not up yet */
		}
		await Bun.sleep(100);
	}
	throw new Error('server did not come up on :3000');
}

async function api<T>(
	ctx: BrowserContext,
	method: string,
	path: string,
	body?: unknown
): Promise<T> {
	const res = await ctx.request.fetch(`${ORIGIN}${path}`, {
		method,
		headers: { 'content-type': 'application/json' },
		data: body === undefined ? undefined : JSON.stringify(body)
	});
	if (!res.ok()) {
		throw new Error(`${method} ${path} → ${res.status()} ${await res.text()}`);
	}
	return (await res.json()) as T;
}

/*
 * The console's sign-in leg. `GET /admin` redirects to `/admin/login`, which starts an authorization
 * code flow against this server's own issuer and lands on the interaction's login page — so the form
 * filled in here is `lib/interactions/loginPage.tsx`, not an admin-specific screen. Its inputs carry
 * placeholders rather than labels, which is why these are placeholder locators.
 */
async function signIn(
	page: Page,
	email: string,
	password: string
): Promise<void> {
	await page.goto(`${ORIGIN}/admin`);
	await page.getByPlaceholder('Username').fill(email);
	await page.getByPlaceholder('Password').fill(password);
	await page.getByRole('button', { name: 'Log in' }).click();
	await page.waitForURL(`${ORIGIN}/admin`);
}

interface Created {
	_id: string;
}

async function seed(
	ctx: BrowserContext
): Promise<{ projectName: string; bucketName: string }> {
	const group = await api<Created>(ctx, 'POST', '/admin/api/groups', {
		name: 'Acme Corp'
	});
	// The console's lists are scoped by the group held on the session, so everything created below
	// has to be created *after* the switch or it lands in the bootstrap administrator's personal group.
	await api(ctx, 'PUT', '/admin/api/scope', { groupId: group._id });
	const project = await api<Created>(ctx, 'POST', '/admin/api/projects', {
		name: 'Acme Web',
		slug: 'acme-web',
		corsOrigins: ['https://acme.example.com']
	});
	await api(ctx, 'POST', '/admin/api/projects', {
		name: 'Acme Mobile',
		slug: 'acme-mobile'
	});
	const bucket = await api<Created>(ctx, 'POST', '/admin/api/buckets', {
		name: 'Acme customers',
		roles: ['customer', 'support'],
		registrationOpen: true
	});
	await api(ctx, 'PUT', `/admin/api/projects/${project._id}/bucket`, {
		bucketId: bucket._id
	});
	/*
	 * Both clients are created through the API rather than the console's dialog, which is also what
	 * keeps the client secret out of frame: the value is returned once, to this script, and the
	 * "copy it now" modal that would have shown it never opens.
	 */
	await api(ctx, 'POST', `/admin/api/projects/${project._id}/clients`, {
		clientName: 'acme-web',
		applicationType: 'web',
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://acme.example.com/callback'],
		tokenEndpointAuthMethod: 'none',
		/*
		 * Named explicitly so the consent screen lists more than one permission. It has to be a subset
		 * of ApplicationConfig.scopes — `profile`/`email` are not among them on a default install, and
		 * the client route refuses metadata naming a scope the server does not support.
		 */
		scope: 'openid offline_access',
		requireConsent: true
	});
	await api(ctx, 'POST', `/admin/api/projects/${project._id}/clients`, {
		clientName: 'acme-backend',
		applicationType: 'web',
		grantTypes: ['client_credentials'],
		tokenEndpointAuthMethod: 'client_secret_basic'
	});
	for (const email of [
		'dana.rivera@example.com',
		'sam.okafor@example.com',
		'lee.tanaka@example.com'
	]) {
		await api(ctx, 'POST', `/admin/api/buckets/${bucket._id}/users`, {
			email,
			password: USER_PASSWORD,
			roles: ['customer']
		});
	}
	await api(ctx, 'PUT', '/admin/api/settings', {
		'clientCredentials.enabled': true,
		'deviceFlow.enabled': true
	});
	return { projectName: 'Acme Web', bucketName: 'Acme customers' };
}

/*
 * The end-user client is registered by the seed above and its generated id is not knowable from here,
 * so it is read back off the project. The console's own `admin-panel` client is in a different
 * project and never appears in this list.
 */
async function endUserClientId(
	ctx: BrowserContext,
	projectName: string
): Promise<string> {
	const projects = await api<{ _id: string; name: string }[]>(
		ctx,
		'GET',
		'/admin/api/projects'
	);
	const project = projects.find((p) => p.name === projectName);
	if (!project) throw new Error(`project ${projectName} is missing`);
	const clients = await api<{ clientId: string; clientName?: string }[]>(
		ctx,
		'GET',
		`/admin/api/projects/${project._id}/clients`
	);
	const client = clients.find((c) => c.clientName === 'acme-web');
	if (!client) throw new Error('client acme-web is missing');
	return client.clientId;
}

function pkce(): { challenge: string } {
	const verifier = Buffer.from(
		crypto.getRandomValues(new Uint8Array(32))
	).toString('base64url');
	const digest = new Bun.CryptoHasher('sha256').update(verifier).digest();
	return { challenge: Buffer.from(digest).toString('base64url') };
}

async function shoot(page: Page, name: string): Promise<void> {
	await page.waitForLoadState('networkidle');
	/*
	 * antd fades a table in on mount, and `networkidle` says nothing about that — the first run
	 * captured every list at part opacity, which reads as a greyed-out console. `animations:
	 * 'disabled'` finishes running CSS animations and transitions before the shot; the settle above it
	 * is for the ones that have not started yet when the click returns.
	 */
	await page.waitForTimeout(400);
	await page.screenshot({
		path: resolve(OUT, `${name}.png`),
		type: 'png',
		animations: 'disabled'
	});
	console.log(`screenshot: ${name}.png`);
}

/*
 * The console is a single-page shell: `lib/admin/ui/pages/Layout.tsx` keeps the current page in React
 * state and the sidebar switches it, so there is no per-page URL to navigate to and every capture
 * below a menu click. Same for the drill-downs — a project's clients and a bucket's users are
 * rendered by Projects.tsx swapping its own subtree, not by a route.
 */
async function openMenu(page: Page, label: string): Promise<void> {
	await page.getByRole('menuitem', { name: label }).click();
}

mkdirSync(OUT, { recursive: true });
mkdirSync(OG_OUT, { recursive: true });
await waitForHealth();

const setup = await fetch(`${ORIGIN}/admin/api/setup`, {
	method: 'POST',
	headers: { 'content-type': 'application/json' },
	body: JSON.stringify(ADMIN)
});
if (setup.status !== 201) {
	throw new Error(
		`first-run setup answered ${setup.status}: ${await setup.text()}`
	);
}

const browser = await chromium.launch();
try {
	const ctx = await browser.newContext({
		viewport: VIEWPORT,
		colorScheme: 'light'
	});
	const page = await ctx.newPage();
	await signIn(page, ADMIN.email, ADMIN.password);
	const names = await seed(ctx);
	const clientId = await endUserClientId(ctx, names.projectName);

	// Reloaded rather than continued: the scope switch happened on the session after this page was
	// rendered, and the console re-reads its lists on load.
	await page.goto(`${ORIGIN}/admin`);
	await shoot(page, 'admin-projects');

	await page
		.getByRole('row', { name: new RegExp(names.projectName) })
		.getByRole('button', { name: 'Clients' })
		.click();
	await shoot(page, 'admin-project-clients');
	await page.getByRole('button', { name: 'Projects' }).click();

	await openMenu(page, 'Buckets');
	await page
		.getByRole('row', { name: new RegExp(names.bucketName) })
		.getByRole('button', { name: 'Users' })
		.click();
	await shoot(page, 'admin-bucket-users');

	// "Grants & flows" is the first settings domain, so it is the pane the page opens on — no click.
	await openMenu(page, 'Settings');
	await shoot(page, 'admin-settings-grants');

	await openMenu(page, 'Audit');
	await shoot(page, 'admin-audit-trail');

	await openMenu(page, 'Keys');
	await shoot(page, 'admin-signing-keys');

	// End-user screens in a fresh context: no admin cookies, a real authorization request.
	const userCtx = await browser.newContext({
		viewport: VIEWPORT,
		colorScheme: 'light'
	});
	const userPage = await userCtx.newPage();
	const { challenge } = pkce();
	const auth = new URL(`${ORIGIN}/auth`);
	auth.search = new URLSearchParams({
		client_id: clientId,
		response_type: 'code',
		scope: 'openid offline_access',
		redirect_uri: 'https://acme.example.com/callback',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		/*
		 * Required for `offline_access` to survive: `lib/actions/authorization/check_scope.ts` drops it
		 * from an authorization request that does not ask for consent, so without this the consent screen
		 * has a single permission on it.
		 */
		prompt: 'consent',
		state: 'demo'
	}).toString();
	await userPage.goto(auth.href);
	await shoot(userPage, 'sign-in');
	await userPage.getByPlaceholder('Username').fill('dana.rivera@example.com');
	await userPage.getByPlaceholder('Password').fill(USER_PASSWORD);
	await userPage.getByRole('button', { name: 'Log in' }).click();
	await userPage.waitForURL(/\/ui\/[^/]+\/consent/);
	await shoot(userPage, 'consent');

	// Open Graph image from a local HTML template — the same browser, no extra tooling.
	const ogPage = await ctx.newPage();
	await ogPage.setViewportSize({ width: 1200, height: 630 });
	await ogPage.goto(`file://${resolve(import.meta.dir, 'og-template.html')}`);
	await ogPage.screenshot({
		path: resolve(OG_OUT, 'default.png'),
		type: 'png'
	});
	console.log('og: default.png');
} finally {
	// A close failure must not mask the original error thrown from the try block above.
	await browser.close().catch(() => {});
}
process.exit(0);
