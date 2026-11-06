import QuickLRU from 'quick-lru';

import { getUserStore } from '../adapters/index.js';
import type { ProtectedResource } from '../adapters/types.js';
import { groupIdsOfUser } from '../bucket_groups/service.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import { decideAccess, type AccessRefusal } from './conditions.js';
import { attributesOf } from './session.js';

/*
 * Who stands behind a token, for an API's access conditions (specs/124 FR-016, FR-017). An API has no session record
 * a lock or a sign-out removes, so whether the person may still sign in is read on every check; only their groups and
 * attributes — which change rarely and are read on every page asset — are kept, for a minute, as an app's standing is.
 */

const STANDING_MS = 60_000;

const standings = new QuickLRU<
	string,
	{ groupIds: string[]; attributes: Record<string, string> }
>({ maxSize: 10_000, maxAge: STANDING_MS });

export type AccessDecision = AccessRefusal | 'cannot_sign_in' | null;

export async function accessRefusal(
	api: Pick<ProtectedResource, 'bucketId' | 'tools'>,
	accountId: string | null,
	address: string | null
): Promise<AccessDecision> {
	const access = api.tools?.access;
	if (!access || access.conditions.length === 0) return null;
	const aboutPerson = access.conditions.some(
		(c) => c.kind === 'group' || c.kind === 'attribute'
	);
	let person: {
		groupIds: string[];
		attributes: Record<string, string>;
	} | null = null;
	if (aboutPerson && accountId) {
		/* The person is looked up only in the API's own project: a token never names someone of another. */
		const user = await getUserStore(api.bucketId).find(accountId);
		if (user) {
			if (!canSignIn(user)) return 'cannot_sign_in';
			const key = `${api.bucketId}:${accountId}`;
			person = standings.get(key) ?? null;
			if (!person) {
				person = {
					groupIds: [...(await groupIdsOfUser(api.bucketId, user._id))],
					attributes: attributesOf(user)
				};
				standings.set(key, person);
			}
		}
	}
	return decideAccess(access.conditions, {
		address,
		at: Date.now(),
		timeZone: access.timeZone ?? null,
		person,
		explain: false
	});
}

/* Test-only: forgets the kept groups and attributes, as a minute passing would. */
export function forgetApiStandings(): void {
	standings.clear();
}
