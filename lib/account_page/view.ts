import { sanitiseClientName } from '../interactions/clientName.js';
import {
	describeGranted,
	redirectKind,
	type ConsentGroup,
	type GrantedSoFar,
	type SortingContext
} from '../interactions/consentView.js';
import type { ProvenanceTier } from '../models/client/provenance.js';
import { ACCOUNT_PAGE_TEXTS } from './texts.js';

/*
 * What one row of the connected-applications page says (specs/095 R7), decided here from facts the route
 * read; the markup only draws it. Pure, so the decisions are the same wherever the facts come from.
 */

export interface GrantFacts {
	/* Consent waived: such a grant records no permissions, because the application gets what it asks for. */
	trusted: boolean;
	/* Milliseconds, as a grant keeps its own times. */
	createdAt: number;
	/* What the grant holds, with whatever the person declined already taken out. */
	granted: GrantedSoFar;
}

export interface ApplicationFacts {
	clientId: string;
	/* Absent when the client no longer resolves: its leftover access is still the person's to remove. */
	client?: { name?: string; redirectUris: readonly string[] };
	tier: ProvenanceTier;
	logo?: string;
	grants: GrantFacts[];
	/* Epoch seconds. */
	lastTokenAt?: number;
	liveRefresh: boolean;
}

export interface ApplicationRow {
	clientId: string;
	name: string;
	/* Where it signs people in: web hosts, at most three, and how many more. */
	hosts: string[];
	moreHosts: number;
	/* It signs people in only through a program or app on their own device. */
	onDevice: boolean;
	logo?: string;
	trusted: boolean;
	groups: { see: ConsentGroup; act: ConsentGroup; other: ConsentGroup };
	/* Nothing else to list, but it can confirm who the person is (it holds `openid`). */
	confirmsIdentity: boolean;
	givenAt: Date;
	lastTokenAt?: Date;
	/*
	 * A refresh token under its grants is live. Not merely `offline_access` granted: without a live refresh
	 * token nothing outlasts the sign-out, and the marker would claim access that is not there.
	 */
	keepsAccess: boolean;
}

const HOSTS_SHOWN = 3;

function union(grants: readonly GrantFacts[]): GrantedSoFar {
	const scopes = new Set<string>();
	const claims = new Set<string>();
	const resources = new Map<string, Set<string>>();
	const rar: unknown[] = [];
	for (const { granted } of grants) {
		for (const scope of granted.oidcScopes) scopes.add(scope);
		for (const claim of granted.oidcClaims) claims.add(claim);
		for (const [indicator, list] of Object.entries(granted.resourceScopes)) {
			const set = resources.get(indicator) ?? new Set<string>();
			for (const scope of list) set.add(scope);
			resources.set(indicator, set);
		}
		rar.push(...granted.rar);
	}
	return {
		oidcScopes: [...scopes],
		oidcClaims: [...claims],
		resourceScopes: Object.fromEntries(
			[...resources].map(([indicator, set]) => [indicator, [...set]])
		),
		rar
	};
}

function isEmpty(group: ConsentGroup): boolean {
	return !group.items.length && !group.resources.length && !group.rar.length;
}

export function applicationRow(
	facts: ApplicationFacts,
	context: SortingContext
): ApplicationRow {
	const hosts: string[] = [];
	let device = false;
	for (const uri of facts.client?.redirectUris ?? []) {
		const where = redirectKind(uri);
		if (where.kind === 'web' && where.host) {
			if (!hosts.includes(where.host)) hosts.push(where.host);
		} else if (where.kind === 'loopback' || where.kind === 'private-use') {
			device = true;
		}
	}

	/* The consent page's fallback chain, so an application is called the same thing on both pages. */
	const name = facts.client
		? (sanitiseClientName(facts.client.name) ?? hosts.at(0) ?? facts.clientId)
		: ACCOUNT_PAGE_TEXTS.deletedApp;

	const granted = union(facts.grants);
	const groups = describeGranted(context, granted);
	const trusted = facts.grants.some((g) => g.trusted);

	return {
		clientId: facts.clientId,
		name,
		hosts: hosts.slice(0, HOSTS_SHOWN),
		moreHosts: Math.max(0, hosts.length - HOSTS_SHOWN),
		onDevice: hosts.length === 0 && device,
		...(facts.tier === 'this-organization' && facts.logo
			? { logo: facts.logo }
			: undefined),
		trusted,
		groups,
		confirmsIdentity:
			isEmpty(groups.see) &&
			isEmpty(groups.act) &&
			isEmpty(groups.other) &&
			granted.oidcScopes.includes('openid'),
		givenAt: new Date(Math.min(...facts.grants.map((g) => g.createdAt))),
		...(facts.lastTokenAt !== undefined
			? { lastTokenAt: new Date(facts.lastTokenAt * 1000) }
			: undefined),
		keepsAccess: facts.liveRefresh
	};
}

/* Newest access first: what the person most likely came to look at. */
export function byNewest(a: ApplicationRow, b: ApplicationRow): number {
	return b.givenAt.getTime() - a.givenAt.getTime();
}
