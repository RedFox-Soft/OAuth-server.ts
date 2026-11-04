import {
	DEFAULT_ANSWER,
	GUIDE_FLAG_PANES,
	GUIDE_FLAG_SETTINGS,
	guideSituation,
	type GuideFlag,
	type GuideRoom,
	type GuideSettingsPane,
	type GuideSituation,
	type GuideTab
} from '../consts/situation_guide.js';

/*
 * What a guide answer can offer the person looking at it. Pure, and importing only the declaration, because the
 * console's browser bundle loads it: nothing here may reach the server.
 */

export interface GuideViewer {
	features: Record<GuideFlag, boolean>;
	superAdmin: boolean;
	/* The project's `can`. */
	rights: { edit: boolean; manageUsers: boolean; changeAddress: boolean };
	/* null: plans are off, or the project is a System project. */
	planFeatures: {
		enterpriseSignIn: boolean;
		customSlug: boolean;
		customDomain: boolean;
	} | null;
	/*
	 * The plan's limits and the project's use of them, from the project's summary. null when nothing limits the
	 * viewer: plans are off, the project is a System project, or the viewer is a super administrator. A null limit is
	 * unlimited.
	 */
	room: {
		plan: string;
		limits: Record<GuideRoom, number | null>;
		usage: Record<GuideRoom, number>;
	} | null;
}

export type Availability =
	| { state: 'ready' }
	/* `pane`: where the first of them is switched on. `anyOf`: switching on any one of them is enough. */
	| {
			state: 'switchedOff';
			settings: string[];
			pane: GuideSettingsPane;
			anyOf?: true;
	  }
	| { state: 'notOnPlan'; feature: string }
	/* The form would add one more where the plan allows `max`, and the project already holds them. */
	| { state: 'planLimit'; limit: GuideRoom; plan: string; max: number }
	| { state: 'ownServer' }
	| { state: 'askSuperAdmin' }
	| { state: 'needsRight'; right: 'edit' | 'manageUsers' | 'changeAddress' };

export function availabilityOf(
	s: GuideSituation,
	viewer: GuideViewer
): Availability {
	const { flags, anyOf, planFeature, room, role } = s.needs;
	if (role === 'super' && !viewer.superAdmin) {
		return viewer.features.plans
			? { state: 'ownServer' }
			: { state: 'askSuperAdmin' };
	}
	const off = (flags ?? []).filter((flag) => !viewer.features[flag]);
	if (off.length > 0) {
		return {
			state: 'switchedOff',
			settings: off.map((flag) => GUIDE_FLAG_SETTINGS[flag]),
			pane: GUIDE_FLAG_PANES[off[0]]
		};
	}
	if (anyOf && anyOf.length > 0 && anyOf.every((f) => !viewer.features[f])) {
		return {
			state: 'switchedOff',
			settings: anyOf.map((flag) => GUIDE_FLAG_SETTINGS[flag]),
			pane: GUIDE_FLAG_PANES[anyOf[0]],
			anyOf: true
		};
	}
	if (planFeature && viewer.planFeatures && !viewer.planFeatures[planFeature]) {
		return { state: 'notOnPlan', feature: planFeature };
	}
	const max = room && viewer.room ? viewer.room.limits[room] : null;
	if (room && viewer.room && max !== null && viewer.room.usage[room] >= max) {
		return { state: 'planLimit', limit: room, plan: viewer.room.plan, max };
	}
	if (role && role !== 'super' && !viewer.rights[role]) {
		return { state: 'needsRight', right: role };
	}
	return { state: 'ready' };
}

function validFor(tab: GuideTab, id: string | null): id is string {
	return id !== null && guideSituation(id)?.tab === tab;
}

/* The enterprise answer wins when both are named. */
export function guideSelection(query: URLSearchParams): {
	tab: GuideTab;
	id: string;
} {
	const e = query.get('e');
	const s = query.get('s');
	if (validFor('enterprise', e)) return { tab: 'enterprise', id: e };
	if (validFor('product', s)) return { tab: 'product', id: s };
	if (query.has('e')) {
		return { tab: 'enterprise', id: DEFAULT_ANSWER.enterprise };
	}
	return { tab: 'product', id: DEFAULT_ANSWER.product };
}

const NEEDS_ADDRESS = 'First give the project an address on its Settings.';

export function renderPrompt(
	s: GuideSituation,
	values: { issuer: string | null; console: string }
): string {
	const issuer = values.issuer?.replace(/\/+$/, '') ?? null;
	const withIssuer =
		issuer === null
			? s.prompt.replace(
					/[^.\n]*\{(?:issuer|discovery)\}[^\n]*?\.(?=\s|$)/g,
					NEEDS_ADDRESS
				)
			: s.prompt
					.replaceAll(
						'{discovery}',
						`${issuer}/.well-known/openid-configuration`
					)
					.replaceAll('{issuer}', issuer);
	return withIssuer.replaceAll('{console}', values.console);
}
