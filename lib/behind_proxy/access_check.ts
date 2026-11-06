import { canSignIn } from '../end_users/can_sign_in.js';
import { attributesOfRecord, type Condition } from './conditions.js';
import {
	decide,
	withConditions,
	type Decision,
	type PathRule,
	type Person,
	type PlainWho
} from './decide.js';

/*
 * The console's access check (specs/122 FR-037): who would get in, for which address, under the saved rules and the
 * edited ones. It runs in the browser on the same `decide()` as the live check, and this module turns what the
 * admin routes answer — the app's rules, a person with their groups — into that decision's input, so the console
 * cannot ask a different question from the one the proxy's check asks (FR-011). There is no dry-run route: it would
 * need an audit entry for every click.
 *
 * Bundled into the console, so it imports only what `decide()` and `canSignIn` do: nothing.
 */

/* A rule's "who" as the admin routes answer it: groups by id, each with its name now, or null once deleted. */
export type WhoView =
	| { kind: 'groups'; groups: readonly { id: string; name: string | null }[] }
	| { kind: 'project' }
	| { kind: 'public'; subtree: boolean }
	| { kind: 'none' };

export interface RuleView {
	path: string;
	who: WhoView;
	/* The rule's own conditions (specs/124); the ones of the paths above it apply too. */
	conditions?: Condition[];
}

/* A person as the admin routes answer them (`GET …/users/:uid`): their standing and their groups. */
export interface PersonView {
	active: boolean;
	lockedLocally?: unknown;
	groups?: readonly { id: string }[];
	profile?: {
		title?: unknown;
		enterprise?: Readonly<Record<string, unknown>>;
	};
	claims?: Readonly<Record<string, unknown>>;
}

export function whoOfView(who: WhoView): PlainWho {
	return who.kind === 'groups'
		? { kind: 'groups', groupIds: who.groups.map((group) => group.id) }
		: who;
}

export function rulesOfView(rules: readonly RuleView[]): PathRule[] {
	return rules.map((rule) => ({
		path: rule.path,
		who: withConditions(whoOfView(rule.who), rule.conditions ?? [])
	}));
}

/* Null for "not signed in". */
export function personOfView(view: PersonView | null): Person | null {
	if (!view) return null;
	return {
		canSignIn: canSignIn(view),
		groupIds: (view.groups ?? []).map((group) => group.id).sort(),
		attributes: attributesOfRecord(view)
	};
}

export interface RequestTarget {
	/* The host as typed, or null when only a path was. */
	host: string | null;
	/* The path and query exactly as typed: what the proxy would send in `X-Forwarded-Uri`. */
	rawPath: string;
}

/*
 * An address pasted from a browser, split without the URL parser: the parser resolves dot segments and decodes
 * some escapes, and the proxy sends the path as the browser sent it, so the check must see the same text.
 */
export function targetOf(address: string): RequestTarget {
	const typed = address.trim();
	const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(typed);
	if (!scheme && typed.startsWith('/')) return { host: null, rawPath: typed };
	const rest = scheme ? typed.slice(scheme[0].length) : typed;
	const end = rest.search(/[/?#]/);
	const host = end === -1 ? rest : rest.slice(0, end);
	const after = end === -1 ? '' : rest.slice(end);
	return {
		host: host === '' ? null : host.toLowerCase(),
		rawPath: after.startsWith('/') ? after : `/${after}`
	};
}

export interface AccessCheckInput {
	rules: readonly PathRule[];
	method: string;
	/* A full address from the browser, or a path. */
	address: string;
	person: Person | null;
	/* What conditions are judged on (specs/124); a null input is one the administrator did not give. */
	from?: string | null;
	at?: number | null;
	timeZone?: string | null;
}

/*
 * Every condition is judged, and an input not given is "unknown" rather than a failure: the answer is then "allowed
 * if these hold", with the rest of the decision exactly as the proxy's check makes it.
 */
export function checkAccess({
	rules,
	method,
	address,
	person,
	from = null,
	at = null,
	timeZone = null
}: AccessCheckInput): Decision {
	return decide({
		rules,
		method,
		rawPath: targetOf(address).rawPath,
		person,
		address: from,
		at,
		timeZone,
		explain: true
	});
}
