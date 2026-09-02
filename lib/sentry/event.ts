import type { ErrorOccurrence, ErrorRecord } from '../adapters/types.js';
import { PERMITTED_EVENT_KEYS, type SentryFailureEvent } from './types.js';

export interface EventLabels {
	environment: string;
	instance: string;
	release?: string;
}

/*
 * The internal record, projected onto what may leave this server.
 *
 * Assembled by naming what is taken, never by copying the record and deleting the sensitive parts.
 * The difference is not stylistic: a delete-list fails the first time a field is added upstream, and
 * it fails silently, on a channel nobody audits until an incident. Here a new field on ErrorRecord is
 * simply absent until someone adds it to `SentryFailureEvent` and to the permitted list — and the
 * projection spec asserts key-set *equality*, so that addition cannot happen unnoticed.
 *
 * Two fields present on the record are deliberately not here. `actor` carries an end-user's id and
 * email, which is the one category the requirement excludes by default and defines no opt-in for.
 * `userAgent` identifies a device and answers no question about which endpoint is broken.
 * `occurrence.origin` — the code location parsed from the stack — is also omitted: it is not on the
 * permitted list, and widening what leaves the server is a decision to take deliberately rather than
 * in passing.
 *
 * Pure and synchronous by design. It runs on the way out of a fault, where anything that can throw
 * or await is a second failure waiting to happen.
 */
export function projectFault(
	occurrence: ErrorOccurrence,
	labels: EventLabels
): SentryFailureEvent {
	const record: ErrorRecord = occurrence.record;

	return {
		at: record.at,
		surface: occurrence.surface,
		/*
		 * Elysia's matched route *pattern*, which is what the capture sites already pass. Never the
		 * requested path: a concrete path is part of the request URL, which must not be sent, and it
		 * would fragment one fault into as many Sentry issues as there are ids that hit it.
		 */
		route: occurrence.route,
		method: occurrence.method,
		errorCode: occurrence.errorCode,
		status: occurrence.status,
		message: occurrence.message,
		fingerprint: occurrence.fingerprint,
		reference: record.reference,
		clientId: record.clientId,
		/*
		 * Passed through at whatever level the store already applied — omitted, anonymized, or full.
		 * Read from the record rather than re-derived so this cannot end up more revealing than what
		 * was kept locally.
		 */
		origin: record.origin,
		submittedFields: record.submittedFields,
		environment: labels.environment,
		instance: labels.instance,
		...(labels.release ? { release: labels.release } : {})
	};
}

/*
 * Whether an event is safe to send: its keys are exactly the permitted ones.
 *
 * Returns a verdict instead of throwing, because the caller's answer to "this event acquired a field
 * it should not have" is to drop it and say so — not to raise a second fault out of the code path
 * whose whole job is to not make things worse.
 *
 * A belt to the projection's braces. The projection cannot produce a forbidden key today; this holds
 * even if something later hands the queue an event from somewhere else.
 */
export function unpermittedKeys(event: SentryFailureEvent): string[] {
	const permitted = new Set<string>(PERMITTED_EVENT_KEYS);
	return Object.keys(event).filter((key) => !permitted.has(key));
}
