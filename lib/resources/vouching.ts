import { EgressRefused, guardedFetch, readBounded } from '../shared/egress.js';
import { canonicalizeResourceIdentifier } from './canonical.js';

/*
 * Whether a declared resource's own metadata currently vouches for its declaration — a diagnostic, and
 * nothing more.
 *
 * It was once a condition of declaring, when identifiers were unique across the instance and a
 * declaration was a claim on somebody's server. Namespaces made that claim impossible — a declaration
 * is unique only within its own issuer's namespace, and the root namespace is a super administrator's —
 * so nothing blocks on this any more. What is left is the question an operator asks when an MCP client
 * cannot find this server: does the resource say it trusts the issuer its tokens carry?
 *
 * Discovery follows the MCP authorization specification's order, stopping at the first document found:
 *
 *   1. the `resource_metadata` parameter of a `Bearer` challenge on an unauthenticated request;
 *   2. the path-inserted well-known address (RFC 9728 §3.1);
 *   3. the host's root well-known address.
 *
 * The request is a GET, not the POST an MCP client would send: a diagnostic must not make an unsafe
 * request to somebody else's server. A server that does not challenge a GET falls through to the
 * well-known steps, as the specification does for a missing header.
 *
 * Every request goes through the egress boundary, including a metadata URL the resource named, since
 * that address is the resource's choice. The status carries only values this server produced — no text
 * the resource returned — so an agent reading it through the management surface reads nothing a third
 * party wrote.
 */

const TIMEOUT_MS = 5_000;
/* A metadata document is a handful of fields; anything near this bound is not one. */
const MAX_METADATA_BYTES = 64 * 1024;

export type VouchingStep = 'challenge' | 'path_inserted' | 'root';

export type VouchingReason =
	| 'unreachable'
	| 'blocked_address'
	| 'not_https'
	| 'no_metadata'
	| 'resource_mismatch'
	| 'issuer_not_listed'
	| 'malformed';

export interface VouchingStatus {
	readonly status: 'vouched' | 'not_vouched' | 'not_checked';
	readonly step?: VouchingStep;
	readonly reason?: VouchingReason;
	readonly expectedIssuer: string;
}

/* RFC 9728 §3.1: the well-known segment goes between the host and the resource's path. */
function pathInserted(identifier: URL): string {
	const path = identifier.pathname === '/' ? '' : identifier.pathname;
	return `${identifier.origin}/.well-known/oauth-protected-resource${path}`;
}

function withoutTrailingSlash(value: string): string {
	return value.endsWith('/') ? value.slice(0, -1) : value;
}

/*
 * The `resource_metadata` a `Bearer` challenge names, if any. Read leniently — quoted or bare, in any
 * of several challenges — because a malformed header is the resource's problem to fix and is reported
 * the same way as a missing one: discovery simply moves on to the well-known steps.
 */
function challengedMetadata(header: string | null): string | undefined {
	if (!header || !/\bbearer\b/i.test(header)) return undefined;
	const match = /resource_metadata\s*=\s*(?:"([^"]*)"|([^\s,]+))/i.exec(header);
	const value = match?.[1] ?? match?.[2];
	if (!value) return undefined;
	try {
		const url = new URL(value);
		return url.protocol === 'https:' ? url.href : undefined;
	} catch {
		return undefined;
	}
}

type Found =
	| { kind: 'document'; step: VouchingStep; document: unknown }
	| { kind: 'refused'; reason: VouchingReason };

async function fetchDocument(url: string): Promise<unknown | undefined> {
	const response = await guardedFetch(url, {
		headers: { accept: 'application/json' },
		timeoutMs: TIMEOUT_MS,
		httpsRedirectsOnly: true
	});
	if (!response.ok) return undefined;
	return JSON.parse(await readBounded(response, MAX_METADATA_BYTES));
}

async function discover(url: URL): Promise<Found> {
	let reached = false;

	const attempt = async (
		step: VouchingStep,
		target: string
	): Promise<Found | undefined> => {
		try {
			const document = await fetchDocument(target);
			reached = true;
			return document === undefined
				? undefined
				: { kind: 'document', step, document };
		} catch (error) {
			if (error instanceof SyntaxError)
				return { kind: 'refused', reason: 'malformed' };
			if (
				error instanceof EgressRefused &&
				error.reason === 'blocked_address'
			) {
				return { kind: 'refused', reason: 'blocked_address' };
			}
			return undefined;
		}
	};

	try {
		const challenge = await guardedFetch(url, {
			headers: { accept: 'application/json, text/event-stream' },
			timeoutMs: TIMEOUT_MS,
			httpsRedirectsOnly: true
		});
		reached = true;
		const named =
			challenge.status === 401
				? challengedMetadata(challenge.headers.get('www-authenticate'))
				: undefined;
		await challenge.body?.cancel().catch(() => undefined);
		if (named) {
			const found = await attempt('challenge', named);
			if (found) return found;
		}
	} catch (error) {
		if (error instanceof EgressRefused && error.reason === 'blocked_address') {
			return { kind: 'refused', reason: 'blocked_address' };
		}
	}

	for (const [step, target] of [
		['path_inserted', pathInserted(url)],
		['root', `${url.origin}/.well-known/oauth-protected-resource`]
	] as const) {
		if (step === 'root' && target === pathInserted(url)) continue;
		const found = await attempt(step, target);
		if (found) return found;
	}

	return { kind: 'refused', reason: reached ? 'no_metadata' : 'unreachable' };
}

export async function checkVouching(
	identifier: string,
	expectedIssuer: string,
	options: { trailingSlashSignificant?: boolean } = {}
): Promise<VouchingStatus> {
	const url = new URL(identifier);
	if (url.protocol !== 'https:') {
		return { status: 'not_checked', reason: 'not_https', expectedIssuer };
	}

	const found = await discover(url);
	if (found.kind === 'refused') {
		return found.reason === 'blocked_address'
			? { status: 'not_checked', reason: 'blocked_address', expectedIssuer }
			: { status: 'not_vouched', reason: found.reason, expectedIssuer };
	}

	const { step, document } = found;
	if (typeof document !== 'object' || document === null) {
		return { status: 'not_vouched', step, reason: 'malformed', expectedIssuer };
	}
	const { resource, authorization_servers: servers } = document as Record<
		string,
		unknown
	>;

	/*
	 * RFC 9728 §3.3: the document describes the resource it was fetched for, or it is not to be used.
	 * Compared canonically, the way declarations and requests are, so an upper-case host in the
	 * document — which the MCP specification asks servers to accept — does not count against it.
	 */
	const described =
		typeof resource === 'string'
			? canonicalizeResourceIdentifier(resource, options)
			: undefined;
	if (!described?.ok || described.identifier !== identifier) {
		return {
			status: 'not_vouched',
			step,
			reason: 'resource_mismatch',
			expectedIssuer
		};
	}

	const listed =
		Array.isArray(servers) &&
		servers.some(
			(server) =>
				typeof server === 'string' &&
				withoutTrailingSlash(server) === withoutTrailingSlash(expectedIssuer)
		);
	return listed
		? { status: 'vouched', step, expectedIssuer }
		: {
				status: 'not_vouched',
				step,
				reason: 'issuer_not_listed',
				expectedIssuer
			};
}
