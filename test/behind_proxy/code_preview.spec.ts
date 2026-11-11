import { beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import {
	adminAuditStore,
	getBucketGroupStore,
	getUserStore
} from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import { createAdministrator } from '../administrators.ts';
import {
	agentFor,
	confirm,
	tool,
	behindProxyPath,
	createApp,
	expectStatus,
	project,
	readApp,
	world,
	type Project,
	type World
} from './helpers.ts';

const Preview = Type.Object({
	confirmationRequired: Type.Literal(true),
	consequences: Type.Array(Type.String()),
	expect: Type.Object({
		withoutAuthenticator: Type.Number(),
		providerOnly: Type.Number()
	}),
	changes: Type.Array(Type.String()),
	paths: Type.Array(Type.String())
});

const CODE = { kind: 'fresh', maxAgeMinutes: 15, withCode: true } as const;
const FRESH = { kind: 'fresh', maxAgeMinutes: 15 } as const;

let w: World;

/* A person with a password and an authenticator app, one with a password only, one who has no password. */
async function people(of: Project, groupId?: string): Promise<void> {
	const users = getUserStore(of.id);
	const enrolled = await users.create(`enrolled-${nanoid()}@x.io`, 'h', true);
	await users.update(enrolled._id, {
		totp: {
			secret: 'JBSWY3DPEHPK3PXP',
			enrolledAt: new Date(),
			lastStep: 0,
			via: 'self'
		}
	});
	const plain = await users.create(`plain-${nanoid()}@x.io`, 'h', true);
	const federated = await users.create(`fed-${nanoid()}@x.io`, 'h', true);
	await users.update(federated._id, { passwordSet: false });
	if (groupId) {
		await getBucketGroupStore().change(groupId, {
			add: [enrolled._id, plain._id, federated._id],
			remove: []
		});
	}
}

function rulesWith(
	of: Project,
	admin: readonly Record<string, unknown>[],
	adminWho: Record<string, unknown> = { kind: 'groups', groups: [of.admins] }
) {
	return [
		{ path: '/', who: { kind: 'project' } },
		{ path: '/admin', who: adminWho, conditions: admin }
	];
}

async function updatesRecorded(appId: string): Promise<number> {
	const { entries } = await adminAuditStore.list({
		targetId: appId,
		action: 'behindproxy.update'
	});
	return entries.length;
}

/* A slug no other case of the file uses. */
function slug(): string {
	return `cp${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')
		.slice(0, 10)}`;
}

/**
 * @proves Asking for a code from an authenticator app on a path behind the proxy is described before it is made — how
 * many of the people who may open the path have no authenticator app, and how many can sign in only through a
 * provider — and applied only when confirmed with those counts; nothing is recorded until it applies, and keeping or
 * removing it needs no confirmation.
 */
describe('asking for a code on a path behind the proxy', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	it('is answered with the counts of the path’s people, applied only when confirmed with them, and listed where a code is asked', async () => {
		const acme = await project(slug());
		await people(acme, acme.admins);
		await people(acme);
		const app = await createApp(w.cookie, acme.id, {
			rootGroups: [acme.staff]
		});
		const path = behindProxyPath(acme.id, app.id);
		const recorded = await updatesRecorded(app.id);

		const asked = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE])
		});

		expect(asked.status).toBe(409);
		const preview = shaped(Preview, asked.body);
		expect(preview.expect).toEqual({
			withoutAuthenticator: 1,
			providerOnly: 1
		});
		expect(preview.paths).toEqual(['/admin']);
		expect(preview.changes).toEqual(['codeConditionOn']);
		expect(await updatesRecorded(app.id)).toBe(recorded);

		const stale = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE]),
			confirm: true,
			expect: { withoutAuthenticator: 0, providerOnly: 1 }
		});
		expect(stale.status).toBe(409);
		expect(shaped(Preview, stale.body).expect).toEqual(preview.expect);

		const applied = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE]),
			confirm: true,
			expect: preview.expect
		});
		expectStatus(applied, 200, 'confirming the code condition');
		expect(await updatesRecorded(app.id)).toBe(recorded + 1);
		const stored = await readApp(w.cookie, acme.id, app.id);
		expect(JSON.stringify(stored.rules)).toContain('"withCode":true');
		const summary = await admin(
			'GET',
			`/admin/api/projects/${acme.id}/summary`,
			w.cookie
		);
		expect(
			shaped(
				Type.Object({
					codeRequiredPaths: Type.Array(
						Type.Object({
							appId: Type.String(),
							name: Type.String(),
							paths: Type.Array(Type.String())
						})
					)
				}),
				summary.body
			).codeRequiredPaths
		).toEqual([{ appId: app.id, name: app.name, paths: ['/admin'] }]);
	});

	it('counts a project rule over everyone in the project, and each person of two groups once', async () => {
		const acme = await project(slug());
		await people(acme, acme.admins);
		await people(acme, acme.staff);
		await people(acme);
		const users = getUserStore(acme.id);
		const both = await users.create(`both-${nanoid()}@x.io`, 'h', true);
		await getBucketGroupStore().change(acme.admins, {
			add: [both._id],
			remove: []
		});
		await getBucketGroupStore().change(acme.staff, {
			add: [both._id],
			remove: []
		});
		const app = await createApp(w.cookie, acme.id, {
			rootGroups: [acme.staff]
		});
		const path = behindProxyPath(acme.id, app.id);

		const groups = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE], {
				kind: 'groups',
				groups: [acme.admins, acme.staff]
			})
		});
		const everyone = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE], { kind: 'project' })
		});

		expect(shaped(Preview, groups.body).expect).toEqual({
			withoutAuthenticator: 3,
			providerOnly: 2
		});
		expect(shaped(Preview, everyone.body).expect).toEqual({
			withoutAuthenticator: 4,
			providerOnly: 3
		});
	});

	it('needs no confirmation to keep a code condition, to remove it, or to save a fresh condition without one', async () => {
		const acme = await project(slug());
		await people(acme, acme.admins);
		const app = await createApp(w.cookie, acme.id, {
			rootGroups: [acme.staff]
		});
		const path = behindProxyPath(acme.id, app.id);

		const plain = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [FRESH])
		});
		expectStatus(plain, 200, 'a fresh condition without a code');
		const first = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE])
		});
		await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE]),
			confirm: true,
			expect: shaped(Preview, first.body).expect
		});

		const kept = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [CODE])
		});
		const removed = await admin('PATCH', path, w.cookie, {
			rules: rulesWith(acme, [FRESH])
		});

		expectStatus(kept, 200, 'keeping the code condition');
		expectStatus(removed, 200, 'removing the code from the condition');
		expect(
			JSON.stringify((await readApp(w.cookie, acme.id, app.id)).rules)
		).not.toContain('withCode');
	});

	/**
	 * @proves A code can be asked for only where a person signs in: never on a public path or a no-one rule.
	 */
	it('is refused on a path that takes no conditions', async () => {
		const acme = await project(slug());
		const app = await createApp(w.cookie, acme.id, {
			rootGroups: [acme.staff]
		});

		const onPublic = await admin(
			'PATCH',
			behindProxyPath(acme.id, app.id),
			w.cookie,
			{
				rules: rulesWith(acme, [CODE], { kind: 'public', subtree: false })
			}
		);

		expect(onPublic.status).toBe(422);
	});

	/**
	 * @proves An agent asks for a code on a path the way the console does: the call is held for confirmation, then
	 * answered with the same counts, and applied only when repeated with them; the app's conditions carry the flag.
	 */
	it('through MCP is previewed with the same counts and applied only when confirmed with them', async () => {
		const acme = await project(slug());
		await people(acme, acme.admins);
		const app = await createApp(w.cookie, acme.id, {
			rootGroups: [acme.staff]
		});
		const token = await agentFor(await createAdministrator('super'));
		const args = { id: acme.id, appId: app.id, rules: rulesWith(acme, [CODE]) };

		const described = await tool(token, 'behind_proxy_app_update', args);
		const previewed = await confirm(
			token,
			'behind_proxy_app_update',
			args,
			described
		);
		const shown = JSON.stringify(previewed.result?.structuredContent);
		const again = {
			...args,
			confirm: true,
			expect: { withoutAuthenticator: 1, providerOnly: 1 }
		};
		const applied = await confirm(
			token,
			'behind_proxy_app_update',
			again,
			await tool(token, 'behind_proxy_app_update', again)
		);
		const read = await tool(token, 'behind_proxy_app_get', {
			id: acme.id,
			appId: app.id
		});

		expect(shown).toContain('codeConditionOn');
		expect(shown).toContain('"withoutAuthenticator":1');
		expect(applied.result?.isError).not.toBe(true);
		expect(JSON.stringify(read.result?.structuredContent)).toContain(
			'"withCode":true'
		);
	});
});
