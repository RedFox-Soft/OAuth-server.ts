import { OMNIBUS_SCOPES } from '../../../../resources/scopes.js';
import type { ToolsTableView } from '../../../../behind_proxy/tools.js';
import type { AddressesView } from '../behind-proxy/appView.js';

/*
 * One declared API as the admin API shows it, read by the project's APIs list and by the API's own page (specs/132),
 * with the words both say about it.
 */

export type ScopeKind = 'see' | 'act';

export type CheckedBy = 'server' | 'proxy';

export interface ResourceConnection {
	issuer: string;
	audience: string;
	metadata: Record<string, unknown>;
	metadataUrl: string | null;
	challenge: string | null;
	/* Where the proxy asks and where the project serves the metadata; null unless the proxy checks. */
	check: { verifyUrl: string; metadataUrl: string } | null;
}

export interface ResourceView {
	identifier: string;
	name: string;
	scopes: string[];
	scopeDescriptions?: Record<string, { description: string; kind?: ScopeKind }>;
	tokenFormat: 'jwt' | 'opaque';
	accessTokenTTL: number;
	trailingSlashSignificant: boolean;
	/* The application that exchanges the access tokens this API receives for people's upstream tokens (specs/118). */
	exchangedBy?: string;
	/* Whether the API's own server checks its tokens (spec 107) or the operator's proxy asks this project (specs/123). */
	checkedBy: CheckedBy;
	tools?: ToolsTableView;
	/* How the person behind a token must have signed in (specs/130, specs/143). */
	requireCode: boolean;
	requirePasskey: boolean;
	signInEveryMinutes: number | null;
	/* When who may get in last changed (specs/134); absent until the first such save. */
	accessSavedAt?: string;
	/* What the proxy's checks showed about the addresses it passes (specs/124); only when the proxy checks. */
	addresses?: AddressesView;
	/* What the API itself must serve and check, as the server states it (spec 107). */
	connection?: ResourceConnection;
}

/* The admin API's address of a project's APIs, or of one of them. */
export function resourcesApi(bucketId: string, identifier?: string): string {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/resources`;
	return identifier === undefined
		? base
		: `${base}/${encodeURIComponent(identifier)}`;
}

export const TOKEN_FORMAT_OPTIONS = [
	{
		label: 'Self-contained (verified against this server’s keys)',
		value: 'jwt'
	},
	{ label: 'Opaque (checked back with this server)', value: 'opaque' }
];

export const CHECKED_BY_OPTIONS: { label: string; value: CheckedBy }[] = [
	{ label: 'Your server', value: 'server' },
	{ label: 'Your proxy', value: 'proxy' }
];

/*
 * What the consent page will say about each scope. A row left empty sends nothing for that scope, and the
 * page then shows it by its technical name under "not described" — honest, but no help to the person
 * deciding.
 */
export const KIND_OPTIONS: { label: string; value: ScopeKind }[] = [
	{ label: 'Acts for the person', value: 'act' },
	{ label: 'Only lets it see', value: 'see' }
];

/* Per scope, as typed in a form: what it lets an app do and whether it only sees. */
export type DescriptionsInput = Record<
	string,
	{ description?: string; kind?: ScopeKind }
>;

export function splitScopes(raw: string): string[] {
	return raw
		.split(/[\s,]+/)
		.map((scope) => scope.trim())
		.filter((scope) => scope.length > 0);
}

export function describedScopes(
	scopes: string[],
	descriptions: DescriptionsInput | undefined
): Record<string, { description: string; kind?: ScopeKind }> {
	const out: Record<string, { description: string; kind?: ScopeKind }> = {};
	for (const scope of scopes) {
		const entry = descriptions?.[scope];
		const description = entry?.description?.trim();
		if (!description) continue;
		out[scope] = { description, ...(entry?.kind ? { kind: entry.kind } : {}) };
	}
	return out;
}

export function describeWindow(seconds: number): string {
	if (seconds % 3600 === 0) {
		const hours = seconds / 3600;
		return `${hours} hour${hours === 1 ? '' : 's'}`;
	}
	if (seconds % 60 === 0) {
		const minutes = seconds / 60;
		return `${minutes} minute${minutes === 1 ? '' : 's'}`;
	}
	return `${seconds} seconds`;
}

/*
 * What the operator is told about their scope list, computed from the same `OMNIBUS_SCOPES` the route
 * refuses. Sharing the list is the point: a console warning about a different set than the server
 * enforces would teach the wrong rule.
 */
export function scopeAdvice(raw: string): string | null {
	const scopes = splitScopes(raw);
	if (scopes.length === 0) return null;

	const omnibus = scopes.find((scope) =>
		OMNIBUS_SCOPES.includes(scope.toLowerCase())
	);
	if (omnibus) {
		return `${omnibus} will be refused: it grants everything to every client that arrives. Name the scopes the resource actually distinguishes.`;
	}
	if (scopes.length > 4) {
		return `A client given no scope guidance requests all ${scopes.length} of these at once. This list is the baseline for basic use, not a catalogue of everything the resource could ever permit.`;
	}
	return null;
}

/*
 * What removing an API does, for its confirmation (specs/085, specs/099): the project's own applications may hold
 * machine tokens for it, so the question names them. A failed read leaves the question without names rather than
 * blocking it.
 */
export function removalConsequences(
	clients:
		| {
				clientId: string;
				clientName?: string;
				registeredDynamically?: boolean;
		  }[]
		| null
): string[] {
	const apps = (clients ?? [])
		.filter((c) => !c.registeredDynamically)
		.map((c) => c.clientName || c.clientId);
	return [
		'Token issuance for this audience stops on the next request.',
		apps.length > 0
			? `These applications can no longer get tokens for it: ${apps.join(', ')}. Their current tokens work until they expire.`
			: 'A live integration loses access as its current tokens expire.'
	];
}
