import { beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import {
	checkAccess,
	personOfView,
	rulesOfView,
	type PersonView,
	type RuleView
} from 'lib/behind_proxy/access_check.ts';
import type { Outcome } from 'lib/behind_proxy/decide.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import {
	DECISION_TABLE,
	type DecisionRow,
	type Role
} from './decision_table.ts';
import {
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	setRules,
	signInThrough,
	world,
	type AppView,
	type Member,
	type World
} from './helpers.ts';

/* The admin routes' answers the console's access check is built from, checked rather than cast. */
const WhoView = Type.Union([
	Type.Object({
		kind: Type.Literal('groups'),
		groups: Type.Array(
			Type.Object({
				id: Type.String(),
				name: Type.Union([Type.String(), Type.Null()])
			})
		)
	}),
	Type.Object({ kind: Type.Literal('project') }),
	Type.Object({ kind: Type.Literal('public'), subtree: Type.Boolean() }),
	Type.Object({ kind: Type.Literal('none') })
]);
const RulesView = Type.Object({
	address: Type.String(),
	rules: Type.Array(Type.Object({ path: Type.String(), who: WhoView }))
});
const UserView = Type.Object({
	active: Type.Boolean(),
	lockedLocally: Type.Optional(Type.Unknown()),
	groups: Type.Array(Type.Object({ id: Type.String() }))
});

/* What the proxy is told, as the outcome the decision names it. */
function outcomeOf(status: number): Outcome | 'other' {
	if (status === 200) return 'allow';
	if (status === 302 || status === 401) return 'sign_in';
	if (status === 403) return 'deny';
	return 'other';
}

/**
 * @proves The console's access check, built from what the admin routes answer about the app's rules and the person,
 * gives the same outcome and reason as the live check the proxy makes, for every row of the decision table.
 */
describe("the console's access check and the live check", () => {
	let w: World;
	let app: AppView;
	let rules: RuleView[];
	let address: string;
	const cookies = new Map<Role, string>();
	const people = new Map<Role, PersonView | null>();

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff]
		});
		await setRules(w.cookie, w.acme.id, app.id, [
			{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
			{ path: '/admin', who: { kind: 'groups', groups: [w.acme.admins] } },
			{ path: '/health', who: { kind: 'public', subtree: false } }
		]);
		const read = await admin(
			'GET',
			behindProxyPath(w.acme.id, app.id),
			w.cookie
		);
		expectStatus(read, 200, 'reading the app');
		const view = shaped(RulesView, read.body);
		rules = view.rules;
		address = view.address;

		const members: [Role, Member][] = [
			['staff', w.acme.staffMember],
			['admins', w.acme.adminMember]
		];
		people.set('none', null);
		for (const [role, member] of members) {
			const signedIn = await signInThrough({ slug: w.acme.slug, app }, member);
			cookies.set(role, signedIn.cookie);
			const user = await admin(
				'GET',
				`/admin/api/projects/${w.acme.id}/users/${member.accountId}`,
				w.cookie
			);
			expectStatus(user, 200, 'reading the person');
			people.set(role, shaped(UserView, user.body));
		}
	});

	describe('the decision table', () => {
		it.each(
			DECISION_TABLE.map(
				(row) => [row.person, row.method, row.rawPath, row] as const
			)
		)(
			'the console and the live check agree for %s %s %s',
			async (_person, _method, _path, row: DecisionRow) => {
				const live = await checkApp(
					{ slug: w.acme.slug, app },
					{
						uri: row.rawPath,
						method: row.method,
						cookie: cookies.get(row.person)
					}
				);

				const inConsole = checkAccess({
					rules: rulesOfView(rules),
					method: row.method,
					address: `${address}${row.rawPath}`,
					person: personOfView(people.get(row.person) ?? null)
				});

				const decided: { outcome: string; reason: string | null } = {
					outcome: inConsole.outcome,
					reason: inConsole.reason
				};
				expect(decided).toEqual({
					outcome: outcomeOf(live.status),
					reason: live.headers.get('x-auth-reason')
				});
				expect(inConsole.reason).toBe(row.reason);
			}
		);
	});
});
