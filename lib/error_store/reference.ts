import { randomBytes } from 'node:crypto';

/*
 * The identifier a caller can report back.
 *
 * Opaque and random, carrying nothing: not a record id, not a timestamp, not a counter. It is returned
 * in an error response, so anything encoded in it would be disclosed to whoever provoked the fault —
 * and a guessable one would let an outsider probe for other people's faults through the lookup an
 * operator uses.
 *
 * `err_` prefixed so an operator pasting one into the console can tell at a glance what they are
 * holding, and so a support thread quoting it is searchable.
 */
export function mintReference(): string {
	return `err_${randomBytes(12).toString('base64url')}`;
}

/*
 * Whether a string could be one of ours. Used to refuse a lookup before it reaches storage, so an
 * obviously malformed reference is answered as "no such record" rather than becoming a query.
 */
export function looksLikeReference(value: string): boolean {
	return /^err_[A-Za-z0-9_-]{16}$/.test(value);
}
