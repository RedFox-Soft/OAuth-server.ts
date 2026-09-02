import type { ErrorSurface } from '../adapters/types.js';

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
	origin: string | null | 'not-captured';
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
	'submittedFields',
	'environment',
	'instance',
	'release'
] as const satisfies readonly (keyof SentryFailureEvent)[];

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
