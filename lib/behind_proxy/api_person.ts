import QuickLRU from 'quick-lru';

import { getUserStore } from '../adapters/index.js';
import type { ProtectedResource } from '../adapters/types.js';
import { groupIdsOfUser } from '../bucket_groups/service.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import type { ApiPerson } from './api_decision.js';
import type { Condition } from './conditions.js';
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

/*
 * The person behind a token, for the conditions a request is judged on (specs/131 research R6): the API's own and the
 * named tool row's. Read only when one of them is about the person; null when the token names nobody of this project.
 */
export async function personFacts(
	api: Pick<ProtectedResource, 'bucketId'>,
	accountId: string | null,
	conditions: readonly Condition[]
): Promise<ApiPerson | null> {
	const aboutPerson = conditions.some(
		(c) => c.kind === 'group' || c.kind === 'attribute'
	);
	if (!aboutPerson || !accountId) return null;
	/* The person is looked up only in the API's own project: a token never names someone of another. */
	const user = await getUserStore(api.bucketId).find(accountId);
	if (!user) return null;
	if (!canSignIn(user)) {
		return { groupIds: [], attributes: {}, canSignIn: false };
	}
	const key = `${api.bucketId}:${accountId}`;
	let standing = standings.get(key);
	if (!standing) {
		standing = {
			groupIds: [...(await groupIdsOfUser(api.bucketId, user._id))],
			attributes: attributesOf(user)
		};
		standings.set(key, standing);
	}
	return { ...standing, canSignIn: true };
}

/* Test-only: forgets the kept groups and attributes, as a minute passing would. */
export function forgetApiStandings(): void {
	standings.clear();
}
