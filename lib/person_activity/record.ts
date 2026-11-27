import { meets } from '../helpers/acr_satisfaction.ts';
import { randomUUID } from 'node:crypto';

import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { dayOf } from '../activity/periods.js';
import type {
	ActivityReason,
	ActivityPlace,
	PersonActivityRow,
	ToolsTable
} from '../adapters/types.js';
import type { Believed } from '../behind_proxy/believed_address.js';
import { proves } from '../behind_proxy/believed_address.js';
import type { Decision, Reason } from '../behind_proxy/decide.js';
import type { ApiReason } from '../behind_proxy/answers.js';
import { parseAddress, type Address } from '../behind_proxy/net.js';
import {
	ApplicationConfig,
	onSettingsApplied
} from '../configs/application.js';
import {
	ANOTHER_TOOL,
	PERSON_ACTIVITY_DAYS
} from '../consts/person_activity.js';
import { callerAddressOf } from '../helpers/caller_address.js';
import type { InteractionResult } from '../helpers/oidc_context.js';
import { factsOf, formatAddress, personAddressOf } from './address.js';
import { activityId, discard, note } from './buffer.js';
import { deviceOf } from './device.js';

/*
 * The four places a person's activity is noted from (specs/133 contracts/recording.md). Each call is synchronous,
 * never throws and never reads anything: it is on the path of a sign-in or a proxy check, and at the password door
 * it must cost a found account exactly what a missing one costs (S5). Nothing is noted while the instance setting is
 * off, and for the administrators' project only sign-ins are (specs/137 research R1): a stolen administrator password
 * should show where it was used, and nothing there is behind the proxy.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

onSettingsApplied((appliedKeys) => {
	if (
		appliedKeys.includes('personActivity.enabled') &&
		!ApplicationConfig['personActivity.enabled']
	) {
		discard();
	}
});

function recording(bucketId: string, kind: PersonActivityRow['kind']): boolean {
	if (!ApplicationConfig['personActivity.enabled']) return false;
	return bucketId !== ADMIN_BUCKET_ID || kind === 'signIn';
}

/* The place in a fixed key order, so the same place always digests to the same row id. */
function placeKey(place: ActivityPlace): string[] {
	return [
		place.clientId ?? '',
		place.appOrigin ?? '',
		place.appId ?? '',
		place.resource ?? '',
		place.rule ?? '',
		place.tool ?? '',
		place.providerId ?? ''
	];
}

interface Noted {
	bucketId: string;
	accountId: string;
	kind: PersonActivityRow['kind'];
	outcome: PersonActivityRow['outcome'];
	reason: ActivityReason;
	place: ActivityPlace;
	at: Date;
	address?: { value: Address; from: 'sign_in' | 'proxy' };
	method?: PersonActivityRow['method'];
	freshness?: PersonActivityRow['freshness'];
	device?: PersonActivityRow['device'];
	tools?: string[];
}

function rowOf(noted: Noted): PersonActivityRow {
	const day = dayOf(noted.at);
	const id =
		noted.reason === 'signed_in'
			? randomUUID()
			: activityId([
					noted.bucketId,
					noted.accountId,
					day,
					noted.kind,
					noted.outcome,
					noted.reason,
					noted.freshness?.requirePasskey
						? 'passkey'
						: noted.freshness?.requireCode
							? 'code'
							: '',
					...placeKey(noted.place),
					/*
					 * A refusal at the passkey door is a row of its own (specs/139), so it never merges with the password
					 * door's and takes its words. Appended only then: every other row keeps the id it always had.
					 */
					...(noted.method === 'passkey' ? ['passkey'] : [])
				]);
	const facts = noted.address
		? factsOf(noted.address.value, noted.at.getTime())
		: undefined;
	return {
		_id: id,
		bucketId: noted.bucketId,
		accountId: noted.accountId,
		day,
		kind: noted.kind,
		outcome: noted.outcome,
		reason: noted.reason,
		place: noted.place,
		...(noted.method === undefined ? {} : { method: noted.method }),
		...(noted.freshness === undefined ? {} : { freshness: noted.freshness }),
		...(noted.address
			? {
					address: formatAddress(noted.address.value),
					addressFrom: noted.address.from
				}
			: {}),
		...(facts === undefined ? {} : { facts }),
		...(noted.device === undefined ? {} : { device: noted.device }),
		...(noted.tools === undefined ? {} : { tools: noted.tools }),
		count: 1,
		firstAt: noted.at,
		lastAt: noted.at,
		expiresAt: new Date(noted.at.getTime() + PERSON_ACTIVITY_DAYS * DAY_MS)
	};
}

function safely(noting: () => void): void {
	try {
		noting();
	} catch (error) {
		// Recording must never change an answer; a note that cannot be built is dropped and said so.
		console.error('activity note dropped', { error });
	}
}

function signInAddress(request: Request): Noted['address'] {
	const address = personAddressOf(callerAddressOf(request));
	return address ? { value: address, from: 'sign_in' } : undefined;
}

/* The app a sign-in through `proxy.<bucketId>` was for: its redirect URI was validated against the project's apps. */
function signInPlace(
	bucketId: string,
	clientId: string | undefined,
	redirectUri: string | undefined,
	providerId?: string
): ActivityPlace {
	let appOrigin: string | undefined;
	if (clientId === `proxy.${bucketId}` && redirectUri) {
		try {
			appOrigin = new URL(redirectUri).origin;
		} catch {
			appOrigin = undefined;
		}
	}
	return {
		...(clientId === undefined ? {} : { clientId }),
		...(appOrigin === undefined ? {} : { appOrigin }),
		...(providerId === undefined ? {} : { providerId })
	};
}

type Login = NonNullable<InteractionResult['login']>;

export function noteSignedIn(input: {
	bucketId: string;
	accountId: string;
	clientId: string | undefined;
	redirectUri: string | undefined;
	login: Login;
	request: Request;
}): void {
	if (!recording(input.bucketId, 'signIn')) return;
	safely(() => {
		const providerId = input.login.upstream?.providerId;
		/*
		 * A passkey sign-in reports the multi-factor context a password and a code do, so it is told apart by its methods
		 * first: `pop` is reported by a passkey sign-in only (lib/consts/amr.ts, specs/139 FR-034).
		 */
		const method: PersonActivityRow['method'] =
			providerId !== undefined
				? 'provider'
				: input.login.amr?.includes('pop')
					? 'passkey'
					: meets(input.login.acr, 'multi_factor')
						? 'password_code'
						: 'password';
		const device = deviceOf(input.request.headers.get('user-agent'));
		note(
			rowOf({
				bucketId: input.bucketId,
				accountId: input.accountId,
				kind: 'signIn',
				outcome: 'let_in',
				reason: 'signed_in',
				place: signInPlace(
					input.bucketId,
					input.clientId,
					input.redirectUri,
					providerId
				),
				at: new Date(),
				address: signInAddress(input.request),
				method,
				...(device === undefined ? {} : { device })
			})
		);
	});
}

export type SignInRefusal =
	| 'wrong_password'
	| 'locked'
	| 'deactivated'
	| 'email_unverified'
	| 'wrong_code'
	| 'code_required'
	| 'provider_closed'
	/* A passkey of a known account refused at the passkey door (specs/139): never for a passkey nobody here holds. */
	| 'passkey_refused'
	/* An application requires a passkey and this sign-in was not one (specs/142). */
	| 'passkey_required';

export function noteSignInRefused(input: {
	bucketId: string;
	accountId: string;
	reason: SignInRefusal;
	clientId: string | undefined;
	providerId?: string;
	/* The API whose own requirement turned the sign-in away, when the application did not (specs/130). */
	resource?: string;
	/* The door that refused, where it was not the password's: what the person saw there differs (specs/139 FR-014). */
	method?: 'passkey';
	request: Request;
}): void {
	if (!recording(input.bucketId, 'signIn')) return;
	safely(() => {
		note(
			rowOf({
				bucketId: input.bucketId,
				accountId: input.accountId,
				kind: 'signIn',
				outcome: 'refused',
				reason: input.reason,
				place: {
					...signInPlace(
						input.bucketId,
						input.clientId,
						undefined,
						input.providerId
					),
					...(input.resource === undefined ? {} : { resource: input.resource })
				},
				at: new Date(),
				address: signInAddress(input.request),
				...(input.method === undefined ? {} : { method: input.method })
			})
		);
	});
}

/*
 * The app check's reasons a person can be refused or asked again for. Those with no person (`no_session`) or about
 * the request rather than the person (`missing_forwarded`, `not_found`, `rate_limited`) are never noted.
 */
const APP_REASONS: Partial<Record<Reason, ActivityReason>> = {
	not_in_group: 'not_in_group',
	cannot_sign_in: 'cannot_sign_in',
	rule_no_one: 'rule_no_one',
	ambiguous_path: 'ambiguous_path',
	unsafe_value: 'unsafe_value',
	not_from_network: 'not_from_network',
	network_facts_unknown: 'network_facts_unknown',
	outside_hours: 'outside_hours',
	attribute_mismatch: 'attribute_mismatch',
	sign_in_again: 'sign_in_again'
};

export function noteAppCheck(input: {
	app: { _id: string; bucketId: string };
	accountId: string | null;
	decision: Pick<
		Decision,
		| 'outcome'
		| 'reason'
		| 'rule'
		| 'maxAgeSeconds'
		| 'requireCode'
		| 'requirePasskey'
	>;
	believed: Believed;
}): void {
	const { app, accountId, decision } = input;
	if (accountId === null || decision.outcome === 'allow') return;
	if (!recording(app.bucketId, 'app')) return;
	const reason = APP_REASONS[decision.reason];
	if (reason === undefined) return;
	safely(() => {
		/* The person's address only when the proxy proved, with the project's key, that it passes it (FR-010). */
		const proven =
			input.believed.address !== null && proves(input.believed.flags)
				? parseAddress(input.believed.address)
				: null;
		const freshness: PersonActivityRow['freshness'] =
			decision.outcome === 'sign_in'
				? {
						...(decision.requirePasskey
							? { requirePasskey: true as const }
							: decision.requireCode
								? { requireCode: true as const }
								: {}),
						...(decision.maxAgeSeconds === undefined
							? {}
							: { maxAgeSeconds: decision.maxAgeSeconds })
					}
				: undefined;
		note(
			rowOf({
				bucketId: app.bucketId,
				accountId,
				kind: 'app',
				outcome: decision.outcome === 'sign_in' ? 'sign_in_again' : 'refused',
				reason,
				place: {
					appId: app._id,
					...(decision.rule === null ? {} : { rule: decision.rule })
				},
				at: new Date(),
				...(proven
					? { address: { value: proven, from: 'proxy' as const } }
					: {}),
				...(freshness === undefined ? {} : { freshness })
			})
		);
	});
}

const API_REASONS: Partial<Record<ApiReason, ActivityReason>> = {
	cannot_sign_in: 'cannot_sign_in',
	not_in_group: 'not_in_group',
	attribute_mismatch: 'attribute_mismatch',
	not_from_network: 'not_from_network',
	network_facts_unknown: 'network_facts_unknown',
	outside_hours: 'outside_hours',
	no_person: 'no_person',
	tool_not_listed: 'tool_not_listed',
	tool_unnamed: 'tool_unnamed',
	old_client: 'old_client',
	bad_mcp_header: 'bad_mcp_header',
	insufficient_scope: 'insufficient_scope',
	unsafe_value: 'unsafe_value',
	passkey_required: 'passkey_required',
	code_required: 'code_required',
	sign_in_not_fresh: 'sign_in_not_fresh'
};

/*
 * The tool an API row names (research R5): a row of the API's table, by the name the administrator gave it, or
 * "another tool". The request's own `Mcp-Name` never reaches the store: it is the caller's text.
 */
export function recordedTool(
	table: ToolsTable | undefined,
	named: string | null
): string | undefined {
	if (named === null) return undefined;
	const row = table?.rows.find((candidate) => candidate.name === named);
	return row ? row.name : ANOTHER_TOOL;
}

export function noteApiCheck(input: {
	api: { bucketId: string; identifier: string; tools?: ToolsTable };
	accountId: string | null;
	clientId: string | null;
	outcome: 'refused' | 'sign_in_again';
	reason: ApiReason;
	tool: string | null;
}): void {
	const { api, accountId } = input;
	if (accountId === null) return;
	if (!recording(api.bucketId, 'api')) return;
	const reason = API_REASONS[input.reason];
	if (reason === undefined) return;
	safely(() => {
		const tool = recordedTool(api.tools, input.tool);
		/* Never an address: the caller of an API is the agent's host, not the person (FR-010, У8). */
		note(
			rowOf({
				bucketId: api.bucketId,
				accountId,
				kind: 'api',
				outcome: input.outcome,
				reason,
				place: {
					resource: api.identifier,
					...(input.clientId === null ? {} : { clientId: input.clientId }),
					...(tool === undefined ? {} : { tool })
				},
				at: new Date()
			})
		);
	});
}

/*
 * What a person used (specs/134 research R1): an app behind the proxy or an API checked at it let them through. One
 * row a person, place and UTC day, with the checks counted; never an address, network facts, a device or the rule,
 * because a day of where and how someone works is more than an administrator needs to see what they use (S11).
 */
export function noteAppUse(input: {
	app: { _id: string; bucketId: string };
	accountId: string;
}): void {
	const { app, accountId } = input;
	if (!recording(app.bucketId, 'app')) return;
	safely(() => {
		note(
			rowOf({
				bucketId: app.bucketId,
				accountId,
				kind: 'app',
				outcome: 'let_in',
				reason: 'used',
				place: { appId: app._id },
				at: new Date()
			})
		);
	});
}

/*
 * An API's use (specs/134 research R1, R3): one row a person, API, application and day; the tool is not in the row's
 * identity but in its bounded list, a row of the API's table or "another tool", never the caller's text.
 */
export function noteApiUse(input: {
	api: { bucketId: string; identifier: string; tools?: ToolsTable };
	accountId: string;
	clientId: string | null;
	tool: string | null;
}): void {
	const { api, accountId } = input;
	if (!recording(api.bucketId, 'api')) return;
	safely(() => {
		const tool = recordedTool(api.tools, input.tool);
		note(
			rowOf({
				bucketId: api.bucketId,
				accountId,
				kind: 'api',
				outcome: 'let_in',
				reason: 'used',
				place: {
					resource: api.identifier,
					...(input.clientId === null ? {} : { clientId: input.clientId })
				},
				at: new Date(),
				...(tool === undefined ? {} : { tools: [tool] })
			})
		);
	});
}
