import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { sentrySettingsRoutes } from 'lib/admin/settings/sentry/routes.ts';
import { settingsRoutes } from 'lib/admin/settings/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	configStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { SENTRY_DSN_MASK } from 'lib/admin/settings/sentry/schema.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * The Sentry card, and the one property that makes it different from every other settings surface:
 * the ingestion credential can be written but never read back.
 *
 * "Write-only" rather than "masked" is a deliberate distinction. A mask implies the value is held and
 * shown in part; here a read reports only *whether* one is stored. Nothing about its length, prefix
 * or shape leaves the server, because any of those narrow a guess at a credential that grants write
 * access to somebody's monitoring project.
 */
const app = new Elysia()
	.use(resolveAdmin)
	.use(sentrySettingsRoutes)
	.use(settingsRoutes);
const client = treaty(app);

const DSN = 'https://publickey@o0.ingest.invalid/1';
const OTHER_DSN = 'https://otherkey@o1.ingest.invalid/2';

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

const VALID = {
	enabled: false,
	dsn: DSN
};

const previousStore = ApplicationConfig['errorStore.enabled'];

describe('Sentry settings API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		await configStore.set({});
		ApplicationConfig['errorStore.enabled'] = previousStore;
	});

	afterEach(async () => {
		await configStore.set({});
		ApplicationConfig['errorStore.enabled'] = previousStore;
	});

	it('stores the credential and never returns it', async () => {
		const cookie = await cookieFor(['super_admin']);
		const put = await client.admin.api.settings.sentry.put(VALID, {
			headers: { cookie }
		});
		expect(put.status).toBe(200);

		const got = await client.admin.api.settings.sentry.get({
			headers: { cookie }
		});
		const data = got.data as Record<string, unknown>;
		expect(data.configured).toBe(true);
		/* Reported from the deployment, not from what was submitted — there is no field for it. */
		expect(data.environment).toBeString();

		/* Not the value, and not any part of it. */
		const serialized = JSON.stringify(data);
		expect(serialized).not.toContain(DSN);
		expect(serialized).not.toContain('publickey');
		expect(data).not.toHaveProperty('dsn');
	});

	it('reports configured false before anything is stored', async () => {
		const cookie = await cookieFor(['super_admin']);
		const got = await client.admin.api.settings.sentry.get({
			headers: { cookie }
		});
		expect((got.data as Record<string, unknown>).configured).toBe(false);
	});

	/* The sentinel lets the console save the rest of the card without holding the secret. */
	it('keeps the stored credential when the mask is sent back', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.sentry.put(VALID, { headers: { cookie } });

		const put = await client.admin.api.settings.sentry.put(
			{ ...VALID, dsn: SENTRY_DSN_MASK, enabled: false },
			{ headers: { cookie } }
		);
		expect(put.status).toBe(200);

		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['sentry.dsn']).toBe(DSN);
	});

	/*
	 * Unlike the SMTP card, empty means *clear* rather than keep — the input only appears when nothing
	 * is stored, so a blank submission cannot mean "untouched".
	 */
	it('clears the stored credential when an empty value is sent', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.sentry.put(VALID, { headers: { cookie } });
		await client.admin.api.settings.sentry.put(
			{ ...VALID, dsn: '' },
			{ headers: { cookie } }
		);

		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['sentry.dsn']).toBe('');
	});

	it('replaces the credential when a new one is sent', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.sentry.put(VALID, { headers: { cookie } });
		await client.admin.api.settings.sentry.put(
			{ ...VALID, dsn: OTHER_DSN },
			{ headers: { cookie } }
		);

		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['sentry.dsn']).toBe(OTHER_DSN);
	});

	/* Names in the trail, never values — the same rule the audit trail applies everywhere. */
	it('records that the credential changed without recording it', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.sentry.put(VALID, { headers: { cookie } });

		const { entries } = await adminAuditStore.list({
			targetType: 'ApplicationConfig'
		});
		const entry = entries.find((e) => e.action === 'sentry.settings.update');
		expect(entry).toBeDefined();
		expect(entry?.attributes).toContain('sentry.dsn');
		expect(JSON.stringify(entry)).not.toContain(DSN);
		expect(JSON.stringify(entry)).not.toContain('publickey');
	});

	/*
	 * An entry claiming a change that never happened is worse than no entry, on the one surface whose
	 * whole purpose is to be trusted about what did.
	 */
	it('records nothing when a submission changes nothing', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.sentry.put(VALID, { headers: { cookie } });
		const first = await adminAuditStore.list({
			targetType: 'ApplicationConfig'
		});

		await client.admin.api.settings.sentry.put(
			{ ...VALID, dsn: SENTRY_DSN_MASK },
			{ headers: { cookie } }
		);
		const second = await adminAuditStore.list({
			targetType: 'ApplicationConfig'
		});

		expect(second.entries.length).toBe(first.entries.length);
	});

	/*
	 * The console's only action once a credential is stored: stop reporting and forget it, in one call.
	 * It has to be one call — clearing a credential while reporting was still on would leave a
	 * configuration the server refuses, so the two cannot be separate steps.
	 */
	it('clears the credential and disables reporting together', async () => {
		const cookie = await cookieFor(['super_admin']);
		ApplicationConfig['errorStore.enabled'] = true;
		await client.admin.api.settings.sentry.put(
			{ ...VALID, enabled: true },
			{ headers: { cookie } }
		);

		const cleared = await client.admin.api.settings.sentry.put(
			{ ...VALID, enabled: false, dsn: '' },
			{ headers: { cookie } }
		);
		expect(cleared.status).toBe(200);
		expect((cleared.data as Record<string, unknown>).configured).toBe(false);
		expect((cleared.data as Record<string, unknown>).enabled).toBe(false);

		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['sentry.dsn']).toBe('');
		expect(stored['sentry.enabled']).toBe(false);
	});

	it('refuses enabling without a credential, naming what is missing', async () => {
		const cookie = await cookieFor(['super_admin']);
		ApplicationConfig['errorStore.enabled'] = true;

		const put = await client.admin.api.settings.sentry.put(
			{ ...VALID, enabled: true, dsn: '' },
			{ headers: { cookie } }
		);
		expect(put.status).toBe(422);
		expect(JSON.stringify(put.error?.value)).toContain('sentry.dsn');
	});

	/* The prerequisite that makes "reported but not recorded" unreachable. */
	it('refuses enabling without the error store, naming it', async () => {
		const cookie = await cookieFor(['super_admin']);
		ApplicationConfig['errorStore.enabled'] = false;

		const put = await client.admin.api.settings.sentry.put(
			{ ...VALID, enabled: true },
			{ headers: { cookie } }
		);
		expect(put.status).toBe(422);
		expect(JSON.stringify(put.error?.value)).toContain('errorStore.enabled');
	});

	/* The dispatch bound is a constant, so it is neither reported nor accepted here. */
	it('neither reports nor accepts a dispatch bound', async () => {
		const cookie = await cookieFor(['super_admin']);
		const got = await client.admin.api.settings.sentry.get({
			headers: { cookie }
		});
		expect(got.data as Record<string, unknown>).not.toHaveProperty(
			'queueDepth'
		);
	});

	it('refuses a project-scoped administrator on both verbs', async () => {
		const cookie = await cookieFor(['project_admin']);
		const got = await client.admin.api.settings.sentry.get({
			headers: { cookie }
		});
		expect(got.status).toBe(403);

		const put = await client.admin.api.settings.sentry.put(VALID, {
			headers: { cookie }
		});
		expect(put.status).toBe(403);
	});

	it('refuses an unauthenticated caller', async () => {
		const got = await client.admin.api.settings.sentry.get();
		expect(got.status).toBe(401);
	});

	/*
	 * The credential is absent from the generic settings catalog by design, which is what stops the
	 * generic read surface from ever returning it and the generic PUT from writing it.
	 */
	it('is absent from the generic settings surface', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.sentry.put(VALID, { headers: { cookie } });

		const got = await client.admin.api.settings.get({ headers: { cookie } });
		const body = got.data as { values: Record<string, unknown> };
		/*
		 * Key presence rather than `toHaveProperty`: these keys contain dots, and toHaveProperty reads a
		 * dot as a path separator — so `not.toHaveProperty('sentry.dsn')` looks for a nested
		 * `sentry.dsn` object that was never going to exist, and passes whether or not the flat key is
		 * there. A vacuous pass on exactly the assertion this test exists to make.
		 */
		const keys = Object.keys(body.values);
		expect(keys).not.toContain('sentry.dsn');
		expect(JSON.stringify(body)).not.toContain(DSN);
		/* The non-secret keys are ordinary catalog entries and do appear. */
		expect(keys).toContain('sentry.enabled');
	});

	it('is refused by the generic settings PUT', async () => {
		const cookie = await cookieFor(['super_admin']);
		const put = await client.admin.api.settings.put(
			{ 'sentry.dsn': OTHER_DSN },
			{ headers: { cookie } }
		);
		expect(put.status).toBe(422);
		expect(JSON.stringify(put.error?.value)).toContain('sentry.dsn');
	});

	/*
	 * A generic settings save merges onto the whole stored document, so it must not drop a credential
	 * written through the dedicated route. This is the regression that would silently disarm reporting
	 * on the next unrelated settings edit.
	 */
	it('survives an unrelated generic settings save', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.sentry.put(VALID, { headers: { cookie } });

		await client.admin.api.settings.put(
			{ 'dpop.requireNonce': true },
			{ headers: { cookie } }
		);

		const stored = (await configStore.get()) as Record<string, unknown>;
		expect(stored['sentry.dsn']).toBe(DSN);
	});
});
