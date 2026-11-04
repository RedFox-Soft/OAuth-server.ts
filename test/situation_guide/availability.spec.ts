import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import {
	availabilityOf,
	guideSelection,
	renderPrompt,
	type GuideViewer
} from 'lib/situation_guide/availability.ts';
import {
	GUIDE_FLAG_PANES,
	GUIDE_FLAG_SETTINGS,
	GUIDE_SITUATIONS,
	guideSituation,
	type GuideFlag,
	type GuideRoom
} from 'lib/consts/situation_guide.ts';
import { actionFor } from 'lib/admin/ui/pages/guide/targets.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { CATALOG_BY_KEY } from 'lib/admin/settings/catalog.ts';

const FLAGS = Object.keys(GUIDE_FLAG_SETTINGS) as GuideFlag[];
const allOn = Object.fromEntries(FLAGS.map((flag) => [flag, true])) as Record<
	GuideFlag,
	boolean
>;

function viewer(
	flags: Partial<Record<GuideFlag, boolean>> = {},
	overrides: Partial<GuideViewer> = {}
): GuideViewer {
	return {
		features: { ...allOn, ...flags },
		superAdmin: true,
		rights: { edit: true, manageUsers: true, changeAddress: true },
		planFeatures: {
			enterpriseSignIn: true,
			customSlug: true,
			customDomain: true
		},
		room: null,
		...overrides
	};
}

const ALL_RIGHTS = { edit: true, manageUsers: true, changeAddress: true };

/* A tenant on a plan allowing three of each, holding `held`. */
function onPlan(held: Partial<Record<GuideRoom, number>>): GuideViewer['room'] {
	return {
		plan: 'Free',
		limits: { applications: 3, apis: 3, connectedServices: 3 },
		usage: { applications: 0, apis: 0, connectedServices: 0, ...held }
	};
}

function situation(id: string) {
	const found = guideSituation(id);
	if (!found) throw new Error(`no situation ${id}`);
	return found;
}

/**
 * @proves Every answer in the guide tells the viewer truthfully whether they can set it up here, and why not.
 */
describe('what a guide answer offers the viewer', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('marks a switched-off feature with the setting that switches it on', () => {
		expect(
			availabilityOf(situation('device'), viewer({ deviceFlow: false }))
		).toEqual({
			state: 'switchedOff',
			settings: ['deviceFlow.enabled'],
			pane: 'grants'
		});
	});

	it('sends an instance act on a hosted service to the viewer’s own server', () => {
		expect(
			availabilityOf(
				situation('ipsie'),
				viewer({ plans: true }, { superAdmin: false })
			)
		).toEqual({ state: 'ownServer' });
	});

	it('sends an instance act on a self-hosted server to the viewer’s super administrator', () => {
		expect(
			availabilityOf(
				situation('ipsie'),
				viewer({ plans: false }, { superAdmin: false })
			)
		).toEqual({ state: 'askSuperAdmin' });
	});

	it('offers an instance act to a super administrator', () => {
		expect(availabilityOf(situation('ipsie'), viewer())).toEqual({
			state: 'ready'
		});
	});

	it('marks company sign-in on a plan without it as not on the plan', () => {
		expect(
			availabilityOf(
				situation('okta'),
				viewer(
					{ federation: true },
					{
						planFeatures: {
							enterpriseSignIn: false,
							customSlug: true,
							customDomain: false
						}
					}
				)
			)
		).toEqual({ state: 'notOnPlan', feature: 'enterpriseSignIn' });
	});

	it('never marks an answer not on the plan when plans do not apply', () => {
		for (const s of GUIDE_SITUATIONS) {
			expect(
				availabilityOf(s, viewer(allOn, { planFeatures: null })).state
			).not.toBe('notOnPlan');
		}
	});

	it('offers directory sync on a plan without enterprise sign-in', () => {
		expect(
			availabilityOf(
				situation('scim'),
				viewer(allOn, {
					planFeatures: {
						enterpriseSignIn: false,
						customSlug: false,
						customDomain: false
					}
				})
			).state
		).not.toBe('notOnPlan');
	});

	it('offers no new application, API or connected service where the plan’s limit is reached', () => {
		const full = onPlan({ applications: 3, apis: 3, connectedServices: 3 });
		for (const [id, limit] of [
			['server', 'applications'],
			['service', 'applications'],
			['api', 'apis'],
			['mcp', 'apis'],
			['connected', 'connectedServices']
		] as const) {
			expect(
				availabilityOf(situation(id), viewer(allOn, { room: full }))
			).toEqual({ state: 'planLimit', limit, plan: 'Free', max: 3 });
		}
	});

	it('offers the form while the plan has room for one more', () => {
		expect(
			availabilityOf(
				situation('server'),
				viewer(allOn, { room: onPlan({ applications: 2 }) })
			)
		).toEqual({ state: 'ready' });
	});

	it('never marks an answer at a plan limit when nothing limits the viewer', () => {
		for (const s of GUIDE_SITUATIONS) {
			expect(availabilityOf(s, viewer(allOn, { room: null })).state).not.toBe(
				'planLimit'
			);
		}
	});

	it('never marks an answer at a plan limit when the limit is unlimited', () => {
		const room = onPlan({ applications: 1000 });
		if (room) room.limits.applications = null;
		expect(
			availabilityOf(situation('server'), viewer(allOn, { room }))
		).toEqual({ state: 'ready' });
	});

	it('offers the MCP answer while either way for an agent host to identify itself is on', () => {
		for (const on of ['clientIdMetadataDocument', 'registration'] as const) {
			expect(
				availabilityOf(
					situation('mcp'),
					viewer({
						clientIdMetadataDocument: false,
						registration: false,
						[on]: true
					})
				)
			).toEqual({ state: 'ready' });
		}
	});

	it('marks the MCP answer switched off, naming both ways, when no agent host can identify itself', () => {
		expect(
			availabilityOf(
				situation('mcp'),
				viewer({ clientIdMetadataDocument: false, registration: false })
			)
		).toEqual({
			state: 'switchedOff',
			settings: ['clientIdMetadataDocument.enabled', 'registration.enabled'],
			pane: 'endpoints',
			anyOf: true
		});
	});

	it('offers a member without edit no form', () => {
		expect(
			availabilityOf(
				situation('spa'),
				viewer(allOn, { rights: { ...ALL_RIGHTS, edit: false } })
			)
		).toEqual({ state: 'needsRight', right: 'edit' });
	});

	it('asks for the user-management right where the answer manages users', () => {
		expect(
			availabilityOf(
				situation('offboard'),
				viewer(allOn, { rights: { ...ALL_RIGHTS, manageUsers: false } })
			)
		).toEqual({ state: 'needsRight', right: 'manageUsers' });
	});

	it('offers the own-address answer only to a viewer who may change the address', () => {
		expect(
			availabilityOf(
				situation('domain'),
				viewer(allOn, {
					superAdmin: false,
					rights: { ...ALL_RIGHTS, changeAddress: false }
				})
			)
		).toEqual({ state: 'needsRight', right: 'changeAddress' });
		expect(
			availabilityOf(situation('domain'), viewer(allOn, { superAdmin: false }))
		).toEqual({ state: 'ready' });
	});

	it('reads every switch from a setting that exists, so a working feature is never shown as off', () => {
		for (const key of Object.values(GUIDE_FLAG_SETTINGS)) {
			expect(Object.keys(ApplicationConfig)).toContain(key);
		}
	});

	it('opens each switch on the Settings pane that holds it, so "Open the setting" lands where it is switched', () => {
		for (const flag of FLAGS) {
			expect({
				flag,
				pane: CATALOG_BY_KEY.get(GUIDE_FLAG_SETTINGS[flag])?.domain
			}).toEqual({ flag, pane: GUIDE_FLAG_PANES[flag] });
		}
	});
});

describe('what an answer’s button does in a project with no address', () => {
	it('asks for an address before an application or an API is set up', () => {
		for (const id of ['server', 'spa', 'service', 'api', 'mcp']) {
			expect({ id, ...actionFor('p1', situation(id), viewer(), null) }).toEqual(
				{
					id,
					kind: 'needsAddress',
					href: '/admin/projects/p1/settings',
					what: 'issuer'
				}
			);
		}
	});

	it('sets them up once the project has an address', () => {
		expect(
			actionFor('p1', situation('server'), viewer(), 'https://auth.example/p1')
		).toEqual({
			kind: 'go',
			label: 'Set this up',
			href: '/admin/projects/p1/applications?situation=server'
		});
	});
});

describe('which answer the page opens on', () => {
	it('falls back to the tab default for an unknown or empty answer', () => {
		expect(guideSelection(new URLSearchParams('s=nope'))).toEqual({
			tab: 'product',
			id: 'server'
		});
		expect(guideSelection(new URLSearchParams('e='))).toEqual({
			tab: 'enterprise',
			id: 'okta'
		});
	});

	it('opens the enterprise answer when both tabs name one', () => {
		expect(guideSelection(new URLSearchParams('e=scim&s=spa'))).toEqual({
			tab: 'enterprise',
			id: 'scim'
		});
	});

	it('opens the product default with no query', () => {
		expect(guideSelection(new URLSearchParams(''))).toEqual({
			tab: 'product',
			id: 'server'
		});
	});
});

describe('the prompt handed to an agent', () => {
	it('prints neither null nor undefined and says the project needs an address when it has none', () => {
		const text = renderPrompt(situation('spa'), {
			issuer: null,
			console: 'https://auth.example/admin/projects/p'
		});
		expect(text).not.toMatch(/null|undefined|\{issuer\}|\{discovery\}/);
		expect(text).toContain('address');
	});

	it('names the issuer and its discovery document when the project has an address', () => {
		const text = renderPrompt(situation('spa'), {
			issuer: 'https://auth.example/p/',
			console: 'https://auth.example/admin/projects/p'
		});
		expect(text).toContain('issuer is https://auth.example/p and');
		expect(text).toContain(
			'https://auth.example/p/.well-known/openid-configuration'
		);
		expect(text).toContain('https://auth.example/admin/projects/p');
		expect(text).not.toMatch(/\{\w+\}/);
	});

	it('leaves no placeholder in any answer’s prompt', () => {
		for (const s of GUIDE_SITUATIONS) {
			for (const issuer of [null, 'https://auth.example']) {
				expect(
					renderPrompt(s, { issuer, console: 'https://auth.example/admin' })
				).not.toMatch(/\{(issuer|discovery|console)\}|null|undefined/);
			}
		}
	});
});
