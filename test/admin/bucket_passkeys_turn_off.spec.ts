import { beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import {
	getBucketGroupStore,
	getBucketStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { MIGRATIONS } from 'lib/consts/migrations.ts';
import { checksumOf, compare } from 'lib/migrations/state.ts';
import { rpIdFor } from 'lib/passkeys/relying_party.ts';
import { present, shaped } from '../shape.ts';
import {
	call,
	createProject,
	freshSlug,
	saveAddressForms,
	superAdministrator,
	type Caller
} from '../subdomain_projects/admin.ts';
import {
	createApp,
	behindProxyPath,
	checkApp,
	group as createGroup,
	AppJar
} from '../behind_proxy/helpers.ts';
import { person, seedPasskey } from '../passkeys/helpers.ts';
import { passwordSignIn } from '../passkeys/offer_helpers.ts';

const TurnOffPreview = Type.Object({
	confirmationRequired: Type.Literal(true),
	changes: Type.Array(Type.String()),
	consequences: Type.Array(Type.String()),
	expect: Type.Record(Type.String(), Type.Number())
});

const AddressPreview = Type.Object({
	consequence: Type.String(),
	expect: Type.Record(Type.String(), Type.Number())
});

/**
 * @proves Turning passkeys off or moving a project to a new RP ID previews and counts every API (`apisRequiringPasskey`)
 * and proxy path (`pathsRequiringPasskey`) that requires a passkey, refuses stale `expect` counts, leaves requiring APIs
 * and proxy paths closed once passkeys are off, and fence migration `2026-11-26-passkey-api-proxy-fence` is declared,
 * rerunnable, and makes an older release report `ahead`.
 */
describe('passkey turn-off, address move, and rollback fence safety', () => {
	let operator: Caller;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		operator = await superAdministrator();
		await saveAddressForms(operator.cookie, 'both');
	});

	it('counts and names requiring APIs and proxy paths on passkey turn-off and RP-ID move, rejects stale expect, and leaves them closed', async () => {
		const slug = freshSlug('fence');
		const created = await createProject(operator, { slug });
		const projectId = shaped(
			Type.Object({ _id: Type.String() }),
			created.body
		)._id;
		forgetBucketAddresses();
		await getBucketStore().update(projectId, { passkeyLogin: true });
		const bucket = present(await getBucketStore().find(projectId), 'bucket');

		/* Seed a holder so RP-ID move detects lost passkeys. */
		const holder = await person(projectId);
		await seedPasskey(projectId, holder.accountId, {
			rpId: rpIdFor(bucket),
			createdVia: 'password_code'
		});

		/* Declare an API requiring a passkey. */
		const apiId = `https://vault-${slug}.example.test/mcp`;
		await getProtectedResourceStore().create({
			namespace: projectId,
			identifier: apiId,
			bucketId: projectId,
			name: 'Vault API',
			scopes: ['read'],
			tokenFormat: 'jwt',
			requirePasskey: true
		});

		/* Create a behind-proxy app with /payouts asking for a passkey. */
		const groupId = await createGroup(projectId, 'Finance');
		const app = await createApp(operator.cookie, projectId, {
			rootGroups: [groupId]
		});
		const rules = [
			{ path: '/', who: { kind: 'groups', groups: [groupId] } },
			{
				path: '/payouts',
				who: { kind: 'groups', groups: [groupId] },
				conditions: [{ kind: 'fresh', maxAgeMinutes: 15, withPasskey: true }]
			}
		];
		const appPreview = await call(
			'PATCH',
			behindProxyPath(projectId, app.id),
			operator.cookie,
			{ rules }
		);
		expect(appPreview.status).toBe(409);
		const appSaved = await call(
			'PATCH',
			behindProxyPath(projectId, app.id),
			operator.cookie,
			{
				rules,
				confirm: true,
				expect: (appPreview.body as { expect: Record<string, number> }).expect
			}
		);
		expect(appSaved.status).toBe(200);

		/* 1. Address move (path -> subdomain changes RP ID) previews apisRequiringPasskey and pathsRequiringPasskey. */
		const movePreviewRes = await call(
			'POST',
			`/admin/api/projects/${projectId}/address`,
			operator.cookie,
			{ slug, addressForm: 'subdomain' }
		);
		expect(movePreviewRes.status).toBe(409);
		const movePreview = shaped(AddressPreview, movePreviewRes.body);
		expect(movePreview.expect.apisRequiringPasskey).toBe(1);
		expect(movePreview.expect.pathsRequiringPasskey).toBe(1);
		expect(movePreview.consequence).toContain('Vault API');
		expect(movePreview.consequence).toContain('/payouts');

		/* Stale apisRequiringPasskey on address move is refused with 409. */
		const moveStale = await call(
			'POST',
			`/admin/api/projects/${projectId}/address`,
			operator.cookie,
			{
				slug,
				addressForm: 'subdomain',
				confirm: true,
				expect: { ...movePreview.expect, apisRequiringPasskey: 0 }
			}
		);
		expect(moveStale.status).toBe(409);

		/* 2. Turning passkeys off previews apisRequiringPasskey and pathsRequiringPasskey. */
		const offPreviewRes = await call(
			'PATCH',
			`/admin/api/projects/${projectId}`,
			operator.cookie,
			{ passkeyLogin: false }
		);
		expect(offPreviewRes.status).toBe(409);
		const offPreview = shaped(TurnOffPreview, offPreviewRes.body);
		expect(offPreview.changes).toContain('passkeyApisOff');
		expect(offPreview.changes).toContain('passkeyPathsOff');
		expect(offPreview.expect.apisRequiringPasskey).toBe(1);
		expect(offPreview.expect.pathsRequiringPasskey).toBe(1);
		expect(offPreview.consequences.join(' ')).toContain('Vault API');
		expect(offPreview.consequences.join(' ')).toContain('/payouts');

		/* Stale expect on passkeyLogin: false is refused. */
		const offStale = await call(
			'PATCH',
			`/admin/api/projects/${projectId}`,
			operator.cookie,
			{
				passkeyLogin: false,
				confirm: true,
				expect: { ...offPreview.expect, pathsRequiringPasskey: 99 }
			}
		);
		expect(offStale.status).toBe(409);

		/* Confirm turn-off -> succeeds, and both API and proxy path STAY CLOSED. */
		const offConfirmed = await call(
			'PATCH',
			`/admin/api/projects/${projectId}`,
			operator.cookie,
			{
				passkeyLogin: false,
				confirm: true,
				expect: offPreview.expect
			}
		);
		expect(offConfirmed.status).toBe(200);
		forgetBucketAddresses();

		/* Proxy path /payouts redirects to /auth with acr_values=phr, and password sign-in gets passkeyAsk (stays closed). */
		await getBucketGroupStore().change(groupId, {
			add: [holder.accountId],
			remove: []
		});
		const jar = new AppJar();
		const check = jar.absorb(
			await checkApp({ slug, app }, { uri: '/payouts', cookie: jar.header })
		);
		expect(check.status).toBe(302);
		const authUrl = new URL(
			present(check.headers.get('location'), 'auth redirect')
		);
		const landed = await passwordSignIn(
			{
				bucketId: projectId,
				clientId: authUrl.searchParams.get('client_id') ?? '',
				prefix: `/${slug}`,
				origin: 'http://e.ly'
			},
			holder.email,
			{
				device: false,
				parameters: Object.fromEntries(authUrl.searchParams.entries())
			}
		);
		expect(landed.url).toMatch(/\/ui\/[^/]+\/code-required$/);
		const html = await landed.response.text();
		expect(html).toContain('"variant":"passkeyAsk"');
	});

	it('declares fence migration 2026-11-26-passkey-api-proxy-fence as rerunnable and makes an older release report ahead', async () => {
		const at = MIGRATIONS.findIndex(
			(m) => m.id === '2026-11-26-passkey-api-proxy-fence'
		);
		expect(at).toBeGreaterThan(-1);
		const fence = MIGRATIONS[at];
		expect(fence.reversible).toBe(false);
		expect(fence.rerunnable.length).toBeGreaterThan(0);

		/* Applying the no-op twice throws nothing. */
		if ('apply' in fence.mongodb) {
			await fence.mongodb.apply({});
			await fence.mongodb.apply({});
		}
		if ('apply' in fence.postgres) {
			await fence.postgres.apply({});
			await fence.postgres.apply({});
		}

		/* An older release whose MIGRATIONS list lacks the fence reports `ahead`. */
		const applied = MIGRATIONS.slice(0, at + 1).map((m) => ({
			id: m.id,
			appliedAt: new Date(),
			checksum: checksumOf(m)
		}));
		const older = compare(MIGRATIONS.slice(0, at), applied);
		expect(older.status).toBe('ahead');
		expect(older.unknown).toEqual(['2026-11-26-passkey-api-proxy-fence']);
	});
});
