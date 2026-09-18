/*
 * A write refused because the datastore's own uniqueness constraint holds the value.
 *
 * Distinct from the friendly refusal an admin route produces after looking the value up, and both
 * exist on purpose. The lookup is what names the existing holder, which is what an operator needs. The
 * constraint is what makes the guarantee true, because two operators assigning one hostname at the same
 * moment both read "free" and both write — a read-then-write in a handler cannot promise uniqueness
 * however carefully it is written.
 *
 * A class rather than a message, so the route answers 409 instead of letting the race surface as an
 * internal fault. Nothing about it is backend-specific: each store raises it in its own terms — a
 * duplicate-key error, a unique-violation SQLSTATE, or a synchronous check — and callers see one type.
 */
export class UniqueValueTaken extends Error {
	constructor(
		readonly field: string,
		readonly value: string
	) {
		super(`${field} '${value}' is already taken`);
		this.name = 'UniqueValueTaken';
	}
}

export function isUniqueValueTaken(error: unknown): error is UniqueValueTaken {
	return error instanceof UniqueValueTaken;
}
