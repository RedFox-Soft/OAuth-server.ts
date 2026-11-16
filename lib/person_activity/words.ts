import { ANOTHER_TOOL, MAX_TOOLS_PER_ROW } from '../consts/person_activity.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import type {
	ActivityBrowser,
	ActivityReason,
	ActivitySystem,
	PersonActivityRow
} from '../adapters/types.js';

/*
 * Every word the console and an agent read about a person's activity (specs/133 data-model §2). One table, a `Record`
 * over every reason, so a new reason cannot ship without its words. A phrase stays true later: it names the rule's
 * path, the tool row or the API as recorded, never a sentence computed from today's rules (research R18). The only
 * values inserted are names an administrator set, the recorded rule and tool, and a count; never text a request
 * carried.
 */

export interface PlaceNames {
	/* The application, app behind the proxy or API, by the name it has today. */
	place: string | null;
	/* The token's client for an API row, by name. */
	client: string | null;
	provider: string | null;
}

interface Values {
	kind: PersonActivityRow['kind'];
	app: string;
	api: string;
	/* The application an API was called through, by name. */
	client: string;
	rule: string;
	tool: string | null;
	provider: string;
	count: number;
	requireCode: boolean;
}

const OUTCOMES: Record<PersonActivityRow['outcome'], string> = {
	let_in: 'Let in',
	sign_in_again: 'Asked to sign in again',
	refused: 'Refused'
};

const toolOr = (v: Values, fallback: string) => v.tool ?? fallback;

const REASONS: Record<ActivityReason, (v: Values) => string> = {
	signed_in: () => 'Let in',
	wrong_password: () => 'Wrong password',
	locked: () => 'Right password, but the account is locked',
	deactivated: () => 'Right password, but the account is deactivated',
	email_unverified: () =>
		'Right password, but the email address isn’t verified',
	wrong_code: () => 'Wrong code from the authenticator app',
	code_required: (v) =>
		v.kind === 'api'
			? `Signed in without a code; ${v.api} asks for one`
			: `${v.app} asks for a code; this sign-in gave none`,
	provider_closed: (v) =>
		`Signed in through ${v.provider}, but the account is locked or deactivated`,
	not_in_group: (v) =>
		v.kind === 'api'
			? `Not in the groups that may call ${toolOr(v, v.api)}`
			: `Not in the groups that may open ${v.rule}`,
	cannot_sign_in: () => 'Deactivated or locked',
	not_from_network: () => 'From a network the conditions keep out',
	outside_hours: () => 'Outside the hours the conditions allow',
	attribute_mismatch: () => 'Lacks the attribute the conditions ask for',
	network_facts_unknown: () =>
		'Network facts were not available; closed for everyone',
	rule_no_one: (v) => `${v.rule} lets no one in`,
	ambiguous_path: () => 'The path could not be read in one way only',
	unsafe_value: () =>
		'Their email or a group name holds a character a header cannot carry',
	sign_in_again: (v) =>
		v.requireCode
			? `Signed in without a code; ${v.rule} asks for one`
			: `Signed in too long ago for ${v.rule}`,
	sign_in_not_fresh: (v) => `Signed in too long ago for ${v.api}`,
	no_person: (v) => `The token stands for no person ${v.api} accepts`,
	tool_not_listed: (v) => `${toolOr(v, 'The tool')} is not in the API’s table`,
	tool_unnamed: () => 'The app didn’t name the tool it called',
	old_client: () => 'App too old to name its tool',
	bad_mcp_header: () => 'The app sent a malformed MCP header',
	insufficient_scope: (v) => `Without the permission ${toolOr(v, v.api)} needs`,
	used: (v) =>
		v.kind === 'api' ? `${v.api} through ${v.client}` : `Used ${v.app}`,
	other: (v) => `Not recorded one by one: ${String(v.count)} more`
};

function fill(text: string, values: Record<string, string>): string {
	return text.replace(
		/\{(\w+)\}/g,
		(whole, key: string) => values[key] ?? whole
	);
}

/* What the person was shown, in the console's language: a refused sign-in answers the same for a hidden reason. */
function sawTextOf(reason: ActivityReason, v: Values): string | null {
	const signIn = SIGN_IN_TEXTS.en;
	switch (reason) {
		case 'wrong_password':
		case 'locked':
		case 'deactivated':
			return signIn.errors.invalidCredentials;
		case 'wrong_code':
			return signIn.errors.invalidCode;
		case 'email_unverified':
			return fill(signIn.errors.verificationOutstanding, {
				email: 'their email address'
			});
		case 'code_required':
			return v.kind === 'signIn'
				? fill(signIn.codeRequired.headingApp, { app: v.app })
				: null;
		case 'provider_closed':
			return PLAIN_TEXTS.en.federation.inactive.title;
		default:
			return null;
	}
}

const METHODS: Record<NonNullable<PersonActivityRow['method']>, string> = {
	password: 'Password',
	password_code: 'Password and a code from an authenticator app',
	provider: 'Through {provider}'
};

const BROWSERS: Record<ActivityBrowser, string> = {
	chrome: 'Chrome',
	edge: 'Edge',
	firefox: 'Firefox',
	safari: 'Safari',
	opera: 'Opera',
	samsung: 'Samsung Internet',
	other: 'Other browser'
};

const SYSTEMS: Record<ActivitySystem, string | null> = {
	windows: 'Windows',
	macos: 'macOS',
	ios: 'iOS',
	android: 'Android',
	linux: 'Linux',
	chromeos: 'ChromeOS',
	other: null
};

export function deviceWords(
	device: PersonActivityRow['device']
): string | null {
	if (!device) return null;
	const system = SYSTEMS[device.system];
	const browser = BROWSERS[device.browser];
	return system === null ? browser : `${browser} on ${system}`;
}

export interface RowWords {
	outcome: string;
	reason: string;
	sawText: string | null;
	method: string | null;
	device: string | null;
}

export function toolWords(tool: string | undefined): string | null {
	if (tool === undefined) return null;
	return tool === ANOTHER_TOOL ? 'another tool' : tool;
}

export function wordsOf(row: PersonActivityRow, names: PlaceNames): RowWords {
	const values: Values = {
		kind: row.kind,
		app: names.place ?? 'The app',
		api: names.place ?? 'The API',
		client: names.client ?? 'an application',
		rule: row.place.rule ?? 'this path',
		tool: toolWords(row.place.tool),
		provider: names.provider ?? 'a provider',
		count: row.count,
		requireCode: row.freshness?.requireCode === true
	};
	return {
		outcome: OUTCOMES[row.outcome],
		reason: REASONS[row.reason](values),
		sawText: sawTextOf(row.reason, values),
		method:
			row.method === undefined
				? null
				: fill(METHODS[row.method], { provider: values.provider }),
		device: deviceWords(row.device)
	};
}

export function outcomeWords(outcome: PersonActivityRow['outcome']): string {
	return OUTCOMES[outcome];
}

export function reasonWords(
	reason: ActivityReason,
	kind: PersonActivityRow['kind']
): string {
	return REASONS[reason]({
		kind,
		app: 'The app',
		api: 'The API',
		client: 'an application',
		rule: 'this path',
		tool: null,
		provider: 'a provider',
		count: 0,
		requireCode: false
	});
}

/*
 * The proxy checks behind one use row (specs/134 У6): a page is many checks, so the number is said only here, never
 * as a count of visits.
 */
export function checksWords(count: number): string {
	return `${String(count)} ${count === 1 ? 'check' : 'checks'} by the proxy; every image and script of a page is one`;
}

export interface ToolsView {
	/* Sorted for reading; the store keeps them in the order first seen. */
	names: string[];
	/* How many beyond the two the row shows. */
	more: number;
	/* The row reached its bound: more tools may have been used than are kept. */
	atBound: boolean;
	/* "search_files, read_file and 2 more", or "… and 18 or more" at the bound. */
	words: string;
}

export function toolsView(
	tools: readonly string[] | undefined
): ToolsView | null {
	if (!tools || tools.length === 0) return null;
	const names = tools
		.map((tool) => toolWords(tool) ?? tool)
		.sort((a, b) => a.localeCompare(b));
	const shown = names.slice(0, 2).join(', ');
	const more = Math.max(0, names.length - 2);
	const atBound = tools.length >= MAX_TOOLS_PER_ROW;
	const words =
		more === 0
			? shown
			: `${shown} and ${String(more)}${atBound ? ' or' : ''} more`;
	return { names, more, atBound, words };
}
