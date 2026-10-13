import { isLoopbackRedirect } from '../client_metadata_document/identifier.js';
import type { ScopeDescription } from '../adapters/types.js';
import type { ProvenanceTier } from '../models/client/provenance.js';
import { isStandardOidcScope } from '../consts/oidc_scopes.js';
import {
	isConfusableWith,
	RESERVED_NAME_WORDS,
	sanitiseClientName
} from './clientName.js';

/*
 * What the consent page shows, worked out on the server from the interaction and handed to the page whole.
 *
 * Data, never sentences: the page turns this into words from one catalog (consentTexts.ts), so the server
 * render and the browser's hydration read the same values and the same words. Everything the page shows
 * must therefore be in here — a value computed in the component alone vanishes on hydration.
 *
 * The decisions behind each field are in specs/092-understandable-consent (research.md) and
 * wiki/concepts/consent-screen-decisions.md.
 */

export type ConsentMode = 'sign-in' | 'full' | 'device';

export type RedirectKind = 'web' | 'loopback' | 'private-use' | 'none';

/* A kind of personal data a standard scope or claim releases, worded by the page's catalog. */
export type DataCategory =
	| 'profile'
	| 'profileName'
	| 'profilePhoto'
	| 'profileDetails'
	| 'email'
	| 'address'
	| 'phone'
	| 'groups';

/*
 * One thing the app is asking for: a data category, an administrator's sentence, or — when nobody
 * described it — only its technical name. `codes` are the technical names it stands for.
 */
export interface ConsentItem {
	category?: DataCategory;
	text?: string;
	codes: string[];
	/* In a one-line summary, the resource an undescribed item belongs to — otherwise "api:read" twice reads as a mistake. */
	resource?: string;
}

export interface ResourceBlock {
	indicator: string;
	name?: string;
	host: string;
	items: ConsentItem[];
}

export interface RarBlock {
	label: string;
	fields: { field: RarField; values: string }[];
}

export interface ConsentGroup {
	items: ConsentItem[];
	resources: ResourceBlock[];
	rar: RarBlock[];
}

export type WarningReason = 'acts' | 'offline' | 'confusable' | 'host-mismatch';

export type ConsentWarning =
	| { kind: 'admin' }
	| { kind: 'loopback' }
	| { kind: 'device' }
	| { kind: 'unverified'; reasons: WarningReason[] };

export interface ConsentView {
	uid: string;
	mode: ConsentMode;
	logoSrc: string;
	/* The header: the bucket's display name, else its address. Only ever server data. */
	service: { displayName?: string; host: string };
	client: { name: string; tier: ProvenanceTier };
	redirect: {
		kind: RedirectKind;
		host?: string;
		scheme?: string;
		/* A document client's own host, set only when it differs from where it sends the browser. */
		documentHost?: string;
	};
	/* `id` goes back with the form, so a decision is only ever applied to the account it was shown for. */
	account: { id: string; label: string };
	canSwitchAccount: boolean;
	warning?: ConsentWarning;
	/*
	 * Whether one sentence says it all: only standard personal data is asked for. Separate from `mode`,
	 * which decides the headline — a device sign-in can be either.
	 */
	compact: boolean;
	/* When compact: the categories shared, already narrowed to what the person actually has. */
	signInData: DataCategory[];
	groups: { see: ConsentGroup; act: ConsentGroup; other: ConsentGroup };
	keepsAccessUntil?: string;
	previouslyAllowed: ConsentItem[];
	afterApproval: ConsentItem[];
	nothingRequested?: 'first' | 'repeat';
	device?: { userCode: string; requestedAgo: string };
}

/*
 * The shape hydration starts from before the server's props are spread over it. Never what a person
 * sees: the server always sends a whole view, and this only keeps the component typed and total.
 */
export function emptyConsentView(uid: string): ConsentView {
	return {
		uid,
		mode: 'full',
		logoSrc: '',
		service: { host: '' },
		client: { name: '', tier: 'self-registered' },
		redirect: { kind: 'none' },
		account: { id: '', label: '' },
		canSwitchAccount: false,
		compact: false,
		signInData: [],
		groups: {
			see: { items: [], resources: [], rar: [] },
			act: { items: [], resources: [], rar: [] },
			other: { items: [], resources: [], rar: [] }
		},
		previouslyAllowed: [],
		afterApproval: []
	};
}

// The subset of the consent prompt's `details` this view consumes.
export interface PromptDetails {
	missingOIDCScope?: string[];
	missingOIDCClaims?: string[];
	missingResourceScopes?: Record<string, string[]>;
	// The requested authorization details that are not already granted — the same subset the prompt
	// computed to decide whether to interrupt at all, so the End-User is never asked to re-approve
	// something they have already approved.
	rar?: unknown[];
}

/* What an existing grant already holds, for "you already allowed". */
export interface GrantedSoFar {
	oidcScopes: string[];
	oidcClaims: string[];
	resourceScopes: Record<string, string[]>;
	rar: unknown[];
}

export interface DeclaredResourceFacts {
	name?: string;
	scopeDescriptions?: Partial<Record<string, ScopeDescription>>;
}

export interface ConsentInput {
	uid: string;
	logoSrc: string;
	service: { displayName?: string; host: string };
	client: {
		id: string;
		name?: string;
		tier: ProvenanceTier;
		/* Set for a client resolved from a metadata document: the host of its client_id. */
		documentHost?: string;
		/*
		 * Every redirect URI the client registered is a loopback address. Such a client cannot prove which
		 * local program receives the answer, so it is warned about; one that also registered a web address
		 * proved a place the answer can go, and its loopback use is stated without alarm.
		 */
		loopbackOnly?: boolean;
	};
	redirectUri?: string;
	account: { id: string; email?: string; name?: string; login?: string };
	/* The person's claims as a sign-in would release them, to say only what they actually have. */
	userClaims: Record<string, unknown>;
	details: PromptDetails;
	granted?: GrantedSoFar;
	resources: Partial<Record<string, DeclaredResourceFacts>>;
	/* Instance descriptions of custom OpenID scopes (setting `consent.scopeDescriptions`). */
	scopeDescriptions: Partial<Record<string, string>>;
	// Type identifier → operator label, resolved by the caller so this module reads no configuration.
	rarLabels: Partial<Record<string, string>>;
	/* The administrative MCP's resource identifier, when this request asks for it. */
	adminResource?: string;
	keepsAccessUntil?: string;
	canSwitchAccount: boolean;
	device?: { userCode: string; requestedAgo: string };
}

/*
 * Where the answer goes, told apart the way the person needs it told: a web address they can weigh, a
 * program on this computer nobody can identify, an app on this device claiming a scheme anyone may claim,
 * or nowhere at all (a device sign-in has no redirect). The host is the parser's own ASCII form —
 * converting an internationalised name back to Unicode is what lets a look-alike pass as the original.
 */
export function redirectKind(uri: string | undefined): {
	kind: RedirectKind;
	host?: string;
	scheme?: string;
} {
	if (!uri) return { kind: 'none' };
	const parsed = URL.parse(uri);
	if (!parsed) return { kind: 'none' };
	if (isLoopbackRedirect(uri)) return { kind: 'loopback' };
	if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
		return { kind: 'web', host: parsed.hostname };
	}
	return { kind: 'private-use', scheme: parsed.protocol.replace(/:$/, '') };
}

const NAME_CLAIMS = [
	'name',
	'given_name',
	'family_name',
	'middle_name',
	'nickname',
	'preferred_username'
];
const PROFILE_DETAIL_CLAIMS = [
	'profile',
	'website',
	'gender',
	'birthdate',
	'zoneinfo',
	'locale',
	'updated_at'
];

function hasValue(claims: Record<string, unknown>, claim: string): boolean {
	const value = claims[claim];
	return value !== undefined && value !== null && value !== '';
}

/* The categories `profile` releases for this person, so the page promises nothing they do not have. */
function profileCategories(claims: Record<string, unknown>): DataCategory[] {
	const name = NAME_CLAIMS.some((c) => hasValue(claims, c));
	const photo = hasValue(claims, 'picture');
	const details = PROFILE_DETAIL_CLAIMS.some((c) => hasValue(claims, c));
	const out: DataCategory[] = [];
	if (name && photo) out.push('profile');
	else if (name) out.push('profileName');
	else if (photo) out.push('profilePhoto');
	if (details) out.push('profileDetails');
	return out;
}

/* The category an individually requested claim belongs to, or undefined for one nobody worded. */
function claimCategory(claim: string): DataCategory | undefined {
	if (NAME_CLAIMS.includes(claim)) return 'profileName';
	if (claim === 'picture') return 'profilePhoto';
	if (PROFILE_DETAIL_CLAIMS.includes(claim)) return 'profileDetails';
	if (claim === 'email' || claim === 'email_verified') return 'email';
	if (claim === 'address') return 'address';
	if (claim === 'phone_number' || claim === 'phone_number_verified')
		return 'phone';
	if (claim === 'groups') return 'groups';
	return undefined;
}

// Claims every sign-in carries; asking for one by name adds nothing a person would read.
const PROTOCOL_CLAIMS = new Set([
	'sub',
	'acr',
	'amr',
	'sid',
	'auth_time',
	'iss'
]);

function scopeCategories(
	scope: string,
	claims: Record<string, unknown>
): DataCategory[] {
	switch (scope) {
		case 'profile':
			return profileCategories(claims);
		case 'email':
			return hasValue(claims, 'email') ? ['email'] : [];
		case 'address':
			return hasValue(claims, 'address') ? ['address'] : [];
		case 'phone':
			return hasValue(claims, 'phone_number') ? ['phone'] : [];
		case 'groups':
			return ['groups'];
		default:
			return [];
	}
}

const RAR_FIELDS = [
	'actions',
	'locations',
	'datatypes',
	'privileges',
	'identifier'
] as const;
export type RarField = (typeof RAR_FIELDS)[number];

function rarBlock(
	entry: unknown,
	labels: Partial<Record<string, string>>
): RarBlock | undefined {
	if (entry === null || typeof entry !== 'object') return undefined;
	const detail = entry as Record<string, unknown>;
	const type = typeof detail.type === 'string' ? detail.type : '';
	const fields: RarBlock['fields'] = [];
	for (const field of RAR_FIELDS) {
		const value = detail[field];
		if (value === undefined) continue;
		// check_rar admits strings and lists of strings here; anything else is shown as the JSON it is.
		const values = Array.isArray(value)
			? value.join(', ')
			: typeof value === 'string'
				? value
				: JSON.stringify(value);
		fields.push({ field, values });
	}
	// An unlabelled type is reachable only if the configured map changed while an interaction was in
	// flight; the identifier is shown rather than the detail hidden.
	return { label: labels[type]?.trim() || type, fields };
}

function emptyGroup(): ConsentGroup {
	return { items: [], resources: [], rar: [] };
}

function hostOfIndicator(indicator: string): string {
	return URL.parse(indicator)?.hostname || indicator;
}

/* Adds category items once each, keeping the order in which they were first asked for. */
function pushCategories(
	group: ConsentGroup,
	categories: DataCategory[],
	code: string
) {
	for (const category of categories) {
		const existing = group.items.find((i) => i.category === category);
		if (existing) {
			if (!existing.codes.includes(code)) existing.codes.push(code);
		} else {
			group.items.push({ category, codes: [code] });
		}
	}
}

function resourceBlock(
	group: ConsentGroup,
	indicator: string,
	facts: DeclaredResourceFacts | undefined
): ResourceBlock {
	let block = group.resources.find((r) => r.indicator === indicator);
	if (!block) {
		block = {
			indicator,
			...(facts?.name ? { name: facts.name } : {}),
			host: hostOfIndicator(indicator),
			items: []
		};
		group.resources.push(block);
	}
	return block;
}

interface Asked {
	oidcScopes: string[];
	oidcClaims: string[];
	resourceScopes: Record<string, string[]>;
	rar: unknown[];
}

/*
 * Sorts what is asked into "see", "act for you" and "not described".
 *
 * A standard scope is data the person can picture, so it is "see". A resource scope is "see" only when
 * its administrator declared it so; described without a kind it is "act", because on a page that decides
 * access, understating what an app can do is the failure that matters. Anything nobody described is shown
 * by its technical name rather than guessed at — honest, and the signal that it was not described.
 */
function sortAsked(input: ConsentInput, asked: Asked) {
	const see = emptyGroup();
	const act = emptyGroup();
	const other = emptyGroup();

	for (const scope of asked.oidcScopes) {
		if (scope === 'openid' || scope === 'offline_access') continue;
		if (isStandardOidcScope(scope)) {
			pushCategories(see, scopeCategories(scope, input.userClaims), scope);
			continue;
		}
		const description = input.scopeDescriptions[scope]?.trim();
		if (description) act.items.push({ text: description, codes: [scope] });
		else other.items.push({ codes: [scope] });
	}

	for (const claim of asked.oidcClaims) {
		if (PROTOCOL_CLAIMS.has(claim)) continue;
		const category = claimCategory(claim);
		if (category) pushCategories(see, [category], claim);
		else other.items.push({ codes: [claim] });
	}

	for (const [indicator, scopes] of Object.entries(asked.resourceScopes)) {
		// The administrative MCP is stated once, by its own block; its `openid` is not a thing to list.
		if (indicator === input.adminResource) continue;
		const facts = input.resources[indicator];
		for (const scope of scopes) {
			const described = facts?.scopeDescriptions?.[scope];
			const text = described?.description.trim();
			if (text) {
				const target = described?.kind === 'see' ? see : act;
				resourceBlock(target, indicator, facts).items.push({
					text,
					codes: [scope]
				});
			} else {
				resourceBlock(other, indicator, facts).items.push({ codes: [scope] });
			}
		}
	}

	for (const entry of asked.rar) {
		const block = rarBlock(entry, input.rarLabels);
		if (block) act.rar.push(block);
	}

	return { see, act, other };
}

function isEmptyGroup(group: ConsentGroup): boolean {
	return !group.items.length && !group.resources.length && !group.rar.length;
}

/*
 * A group's items as one flat list, for the one-line "you already allowed" and the summary. A resource's
 * undescribed scopes become one entry naming the resource, since in a single sentence their codes alone
 * would not say where they apply.
 */
function flatten(group: ConsentGroup): ConsentItem[] {
	return [
		...group.items,
		...group.resources.flatMap((r) => {
			const described = r.items.filter((i) => i.text);
			const bare = r.items.filter((i) => !i.text).flatMap((i) => i.codes);
			return bare.length
				? [...described, { codes: bare, resource: r.name ?? r.host }]
				: described;
		}),
		...group.rar.map((r) => ({ text: r.label, codes: [] }))
	];
}

/* The same line twice says nothing new, so a summary lists each once. */
function unique(items: ConsentItem[]): ConsentItem[] {
	const seen = new Set<string>();
	return items.filter((item) => {
		const key = `${item.category ?? ''}|${item.text ?? ''}|${item.codes.join(' ')}|${item.resource ?? ''}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

function accountLabel(account: ConsentInput['account']): string {
	return account.email || account.name || account.login || '';
}

export function buildConsentView(input: ConsentInput): ConsentView {
	const details = input.details;
	const redirect = redirectKind(input.redirectUri);
	const name =
		sanitiseClientName(input.client.name) ?? redirect.host ?? input.client.id;
	const documentHost =
		input.client.documentHost &&
		redirect.host &&
		input.client.documentHost !== redirect.host
			? input.client.documentHost
			: undefined;

	const asked: Asked = {
		oidcScopes: details.missingOIDCScope ?? [],
		oidcClaims: details.missingOIDCClaims ?? [],
		resourceScopes: details.missingResourceScopes ?? {},
		rar: details.rar ?? []
	};
	const groups = sortAsked(input, asked);

	const offline = input.keepsAccessUntil !== undefined;
	const customScopeAsked = asked.oidcScopes.some(
		(s) => !isStandardOidcScope(s)
	);
	const resourceAsked = Object.values(asked.resourceScopes).some(
		(s) => s.length > 0
	);
	const compact =
		!input.adminResource &&
		!offline &&
		!customScopeAsked &&
		!resourceAsked &&
		!asked.rar.length &&
		isEmptyGroup(groups.act) &&
		isEmptyGroup(groups.other);
	const mode: ConsentMode = input.device
		? 'device'
		: compact
			? 'sign-in'
			: 'full';

	const acts = !isEmptyGroup(groups.act) || !isEmptyGroup(groups.other);
	const notOwn = input.client.tier !== 'this-organization';
	const confusable =
		notOwn &&
		isConfusableWith(name, [
			input.service.displayName,
			input.service.host,
			...RESERVED_NAME_WORDS
		]);

	const reasons: WarningReason[] = [];
	if (notOwn) {
		if (acts) reasons.push('acts');
		if (offline) reasons.push('offline');
		if (confusable) reasons.push('confusable');
		if (documentHost) reasons.push('host-mismatch');
	}

	// One warning at most, and the gravest wins: a warning on every page is a warning nobody reads.
	const warning: ConsentWarning | undefined = input.adminResource
		? { kind: 'admin' }
		: input.client.loopbackOnly
			? { kind: 'loopback' }
			: input.device
				? { kind: 'device' }
				: reasons.length
					? { kind: 'unverified', reasons }
					: undefined;

	const granted = input.granted;
	const previously = granted
		? sortAsked(input, {
				oidcScopes: granted.oidcScopes,
				oidcClaims: granted.oidcClaims,
				resourceScopes: granted.resourceScopes,
				rar: granted.rar
			})
		: undefined;
	const previouslyAllowed = previously
		? unique([
				...flatten(previously.see),
				...flatten(previously.act),
				...flatten(previously.other)
			])
		: [];

	const newItems = [
		...flatten(groups.see),
		...flatten(groups.act),
		...flatten(groups.other)
	];
	const escalates = acts || offline;
	// Long-lived access is no list item of its own, yet on its own it is an escalation worth summing up.
	const afterApproval =
		previouslyAllowed.length && escalates
			? unique([...previouslyAllowed, ...newItems])
			: [];

	const askedAnything =
		asked.oidcScopes.length > 0 ||
		asked.oidcClaims.length > 0 ||
		resourceAsked ||
		asked.rar.length > 0;

	return {
		uid: input.uid,
		mode,
		logoSrc: input.logoSrc,
		service: input.service,
		client: { name, tier: input.client.tier },
		redirect: { ...redirect, ...(documentHost ? { documentHost } : {}) },
		account: { id: input.account.id, label: accountLabel(input.account) },
		canSwitchAccount: input.canSwitchAccount,
		...(warning ? { warning } : {}),
		compact,
		signInData: compact
			? groups.see.items.flatMap((i) => i.category ?? [])
			: [],
		groups,
		...(input.keepsAccessUntil
			? { keepsAccessUntil: input.keepsAccessUntil }
			: {}),
		previouslyAllowed,
		afterApproval,
		...(!askedAnything && !input.adminResource && !input.device
			? { nothingRequested: granted ? 'repeat' : 'first' }
			: {}),
		...(input.device ? { device: input.device } : {})
	};
}
