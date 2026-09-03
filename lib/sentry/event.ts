import type { ErrorOccurrence, ErrorRecord } from '../adapters/types.js';
import {
	PERMITTED_EVENT_KEYS,
	PERMITTED_LOCATION_KEYS,
	type SentryFailureEvent
} from './types.js';

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
 *
 * `occurrence.origin` — the code location — *is* here now, as `codeLocation`, and it was withheld
 * until it was worth widening the list for. The reason it can be sent at all is that the record never
 * keeps a stack: the location is parsed with the error message discarded, so the one field through
 * which a request value could plausibly arrive has already been thrown away upstream. A raw stack, an
 * error object, or a frame still carrying the message remains unsendable, and always will be.
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
		/*
		 * The occurrence's origin, not the record's — a different field that happens to share a name.
		 * Passed by reference rather than rebuilt: a copy assembled here could disagree with what was
		 * retained locally, and "no more revealing than the internal record" is only true if it is the
		 * same value. Already truncated by the parser; nothing re-truncates it.
		 */
		codeLocation: occurrence.origin,
		submittedFields: record.submittedFields,
		environment: labels.environment,
		instance: labels.instance,
		...(labels.release ? { release: labels.release } : {})
	};
}

/*
 * Whether an event is safe to send: its keys are exactly the permitted ones, at both levels.
 *
 * Returns a verdict instead of throwing, because the caller's answer to "this event acquired a field
 * it should not have" is to drop it and say so — not to raise a second fault out of the code path
 * whose whole job is to not make things worse.
 *
 * A belt to the projection's braces. The projection cannot produce a forbidden key today; this holds
 * even if something later hands the queue an event from somewhere else.
 *
 * Descends one level, and only into `codeLocation`. Not general recursion: `codeLocation` is the only
 * field on the event with an interior, so a generic deep walk would be machinery built for a case
 * that does not exist — and it would have to decide what to do about arrays and dates, which is
 * complexity on the one path that must never throw. When a second nested field appears, this grows a
 * second explicit branch, and that visibility is the point.
 *
 * Offenders come back as dotted paths so the line an operator reads names the place to look.
 */
export function unpermittedKeys(event: SentryFailureEvent): string[] {
	const permitted = new Set<string>(PERMITTED_EVENT_KEYS);
	const offenders = Object.keys(event).filter((key) => !permitted.has(key));

	const location: unknown = event.codeLocation;
	if (typeof location !== 'object' || location === null) {
		/*
		 * Absent counts as an offence rather than as nothing to check. A missing location means the
		 * event did not come from the projection, and an event of unknown provenance is precisely what
		 * this function exists to refuse.
		 */
		offenders.push('codeLocation');
		return offenders;
	}

	const permittedLocation = new Set<string>(PERMITTED_LOCATION_KEYS);
	for (const key of Object.keys(location)) {
		if (!permittedLocation.has(key)) {
			offenders.push(`codeLocation.${key}`);
		}
	}
	return offenders;
}
