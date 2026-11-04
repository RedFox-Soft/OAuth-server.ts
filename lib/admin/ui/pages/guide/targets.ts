import type {
	GuidePart,
	GuideSituation,
	GuideTarget
} from '../../../../consts/situation_guide.js';
import {
	availabilityOf,
	type Availability,
	type GuideViewer
} from '../../../../situation_guide/availability.js';
import { bucketHref, sectionHref } from '../../frame/routes.js';

/* Where the public documentation lives; a guide answer that points at it opens it in a new tab. */
export const DOCS_ORIGIN = 'https://foxauth.dev';

/*
 * The address a guide answer's button opens. A project tab goes through `bucketHref`, an instance page through
 * its own console address, a page the project serves to its people to the project's issuer, and the docs to the
 * public site.
 *
 * The Settings page opens a pane by `?pane=<domain id>` (lib/admin/settings/catalog.ts SETTING_DOMAINS): it does
 * not read the `/admin/settings/:pane` segment, so the pane travels in the query.
 *
 * A project with no address of its own serves no pages to its people, so a `projectPage` target leads to the
 * project's Settings instead, where it is given one; the answer says why.
 */
export function targetHref(
	bucketId: string,
	t: GuideTarget,
	issuer: string | null = null
): string {
	if ('instance' in t) {
		if (t.instance === 'settings') {
			return t.pane
				? `/admin/settings?pane=${encodeURIComponent(t.pane)}`
				: '/admin/settings';
		}
		return t.area ? `/admin/administrators/${t.area}` : '/admin/administrators';
	}
	if ('area' in t) {
		const query = t.query ? `?${new URLSearchParams(t.query).toString()}` : '';
		return `${bucketHref(bucketId, t.area)}${query}`;
	}
	if ('section' in t) return sectionHref(t.section);
	if ('projectPage' in t) {
		return issuer
			? `${issuer.replace(/\/+$/, '')}/${t.projectPage}`
			: bucketHref(bucketId, 'settings');
	}
	return `${DOCS_ORIGIN}${t.docs}`;
}

/* Whether an address leaves the console: it then opens in a new tab rather than through the console's router. */
export function leavesConsole(href: string): boolean {
	return /^https?:\/\//.test(href);
}

/*
 * What an answer's button does for this viewer, decided once for the answer panel and the table of every situation:
 * go somewhere (with its label), first give the project an address, or not be offered here (with why).
 */
export type GuideAction =
	| { kind: 'go'; label: string; href: string }
	/* `page`: a page the project serves to its people; `issuer`: what the button sets up runs at the project's issuer. */
	| { kind: 'needsAddress'; href: string; what: 'page' | 'issuer' }
	| {
			kind: 'blocked';
			availability: Exclude<Availability, { state: 'ready' }>;
	  };

export function actionFor(
	bucketId: string,
	s: GuideSituation,
	viewer: GuideViewer,
	issuer: string | null
): GuideAction {
	const availability = availabilityOf(s, viewer);
	if (availability.state !== 'ready') return { kind: 'blocked', availability };
	const target = s.action.target;
	if (issuer === null) {
		/*
		 * With no address the project is no issuer of its own: its applications sign in at the server's bare
		 * endpoints, and its APIs sit in the root namespace, where only a super administrator declares.
		 */
		if ('projectPage' in target) {
			return {
				kind: 'needsAddress',
				href: bucketHref(bucketId, 'settings'),
				what: 'page'
			};
		}
		if (
			'area' in target &&
			(target.area === 'applications' || target.area === 'apis')
		) {
			return {
				kind: 'needsAddress',
				href: bucketHref(bucketId, 'settings'),
				what: 'issuer'
			};
		}
	}
	return {
		kind: 'go',
		label: s.action.kind === 'form' ? 'Set this up' : s.action.label,
		href: targetHref(bucketId, target, issuer)
	};
}

/*
 * What an answer's button does for this viewer, in one word and a glyph, for the answer, its option and its row in the
 * table: read off `actionFor`, so the mark and the button cannot disagree. `scheduled`: the project is read-only
 * until it is restored, which is what a missing right then means.
 */
export interface GuideStatus {
	tone: 'ready' | 'closed';
	glyph: GuidePart | 'fixed';
	word: string;
}

export function statusOf(action: GuideAction, scheduled: boolean): GuideStatus {
	if (action.kind === 'go')
		return { tone: 'ready', glyph: 'fixed', word: 'Ready' };
	if (action.kind === 'needsAddress') {
		return { tone: 'closed', glyph: 'globe', word: 'Needs an address' };
	}
	const availability = action.availability;
	switch (availability.state) {
		case 'switchedOff':
			return { tone: 'closed', glyph: 'server', word: 'Switched off' };
		case 'notOnPlan':
			return { tone: 'closed', glyph: 'cloud', word: 'Not on your plan' };
		case 'planLimit':
			return { tone: 'closed', glyph: 'cloud', word: 'Plan limit reached' };
		case 'ownServer':
			return { tone: 'closed', glyph: 'server', word: 'Own server' };
		case 'askSuperAdmin':
			return { tone: 'closed', glyph: 'team', word: 'Super administrator' };
		case 'needsRight':
			return scheduled
				? { tone: 'closed', glyph: 'clock', word: 'Scheduled for deletion' }
				: { tone: 'closed', glyph: 'team', word: 'Needs a right' };
	}
}
