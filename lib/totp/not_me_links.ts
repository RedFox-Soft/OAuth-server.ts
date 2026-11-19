import { adapter } from '../adapters/index.js';
import { areaNamed } from '../consts/storage_inventory.js';

/*
 * The "This wasn't me" links of specs/126 and specs/138. Their area is unowned so that no revocation of the account
 * reaches them (lib/consts/storage_inventory.ts says why), which leaves two removals to be made by hand: with the
 * person, and with the project.
 */

/* The field comes from the area's declared indexes, as every enumerating read's does; a loud stop beats a scan. */
function indexed(field: 'accountId' | 'bucketId'): string {
	const declared = areaNamed('NotMeLink').indexes.some(
		(index) =>
			Object.keys(index.key).length === 1 &&
			Object.keys(index.key)[0] === `payload.${field}`
	);
	if (!declared) {
		throw new Error(`the NotMeLink area declares no index on ${field}`);
	}
	return field;
}

/* Every "This wasn't me" link mailed to this person; with the person themselves, never with their access. */
export function forgetNotMeLinksOf(accountId: string): Promise<number> {
	return adapter('NotMeLink').destroyByOwner(indexed('accountId'), accountId);
}

/* Every "This wasn't me" link of this project's people; with the project. */
export function forgetNotMeLinksIn(bucketId: string): Promise<number> {
	return adapter('NotMeLink').destroyByOwner(indexed('bucketId'), bucketId);
}
