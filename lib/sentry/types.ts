import type { ErrorOrigin, ErrorSurface } from '../adapters/types.js';

/*
 * What may leave this server toward Sentry, named exhaustively.
 *
 * A whitelist, for the same reason `error_store/redact.ts` is one: a blacklist of forbidden fields
 * fails the first time a new field appears upstream, and it fails silently, on a channel nobody
 * audits until an incident. Nothing here copies a record and removes the sensitive parts — it names
 * what is taken, and everything unnamed is absent by construction.
 *
 * Narrower than the internal record it is projected from, deliberately. `actor` is excluded because
 * it carries an end-user's id and email, and `userAgent` because it identifies a device; neither is
 * something a third party needs to know which endpoint is broken.
 */
export interface SentryFailureEvent {
	at: Date;
	surface: ErrorSurface;
	/* Elysia's matched route *pattern* (`/admin/api/clients/:id`), never the requested path. */
	route: string;
	method: string;
	errorCode: string;
	status: number;
	message: string;
	fingerprint: string;
	reference: string;
	clientId: string | null;
	/*
	 * The caller's NETWORK address, at whatever level the store applied — not a code location, despite
	 * `ErrorOccurrence.origin` internally being exactly that. The two are one rename away from being
	 * confused, and confusing them is the worst outcome available here: this field already ships, so
	 * repurposing it would leave an operator's saved filters working and quietly meaning something
	 * else. `codeLocation` below is the code one. Neither name may migrate onto the other.
	 */
	origin: string | null | 'not-captured';
	/*
	 * Where in the server the fault arose, copied from the record rather than derived. The record
	 * parses it out of the stack with the message discarded, so it is the one form of "where" that is
	 * already known to carry no request data — which is why this is sendable and a raw stack is not.
	 */
	codeLocation: ErrorOrigin;
	/* Names only — never values. */
	submittedFields: string[];
	environment: string;
	instance: string;
	release?: string;
}

/*
 * The permitted key set, as data rather than as a type alone.
 *
 * The type gives compile-time closure; this gives the runtime check that a shipped envelope's keys
 * are *equal* to it. Both are needed: a value can acquire a key at runtime that the type never
 * admitted, which is precisely the case FR-009 asks to drop rather than send.
 */
export const PERMITTED_EVENT_KEYS = [
	'at',
	'surface',
	'route',
	'method',
	'errorCode',
	'status',
	'message',
	'fingerprint',
	'reference',
	'clientId',
	'origin',
	'codeLocation',
	'submittedFields',
	'environment',
	'instance',
	'release'
] as const satisfies readonly (keyof SentryFailureEvent)[];

/*
 * The same enumeration one level down, because permission that stops at a boundary is not permission.
 *
 * `codeLocation` is the only field on the event with an interior, and an interior the outer check
 * cannot see is exactly where a request identifier would end up being added a year from now — shipped
 * to a third party with no test failing. Enumerating it makes that addition a decision someone has to
 * make on purpose, which is the same bargain the outer list strikes.
 */
export const PERMITTED_LOCATION_KEYS = [
	'file',
	'line',
	'frame'
] as const satisfies readonly (keyof ErrorOrigin)[];

/*
 * A startup failure, reported before the error store exists.
 *
 * The one exception to "every outbound event comes from an internal record", and deliberately
 * impoverished so that it looks like the exception it is: at this point there is no request to
 * describe and no record to reference.
 */
export interface SentryStartupEvent {
	kind: string;
	phase: string;
	environment: string;
	instance: string;
	release?: string;
}

export const PERMITTED_STARTUP_KEYS = [
	'kind',
	'phase',
	'environment',
	'instance',
	'release'
] as const satisfies readonly (keyof SentryStartupEvent)[];
