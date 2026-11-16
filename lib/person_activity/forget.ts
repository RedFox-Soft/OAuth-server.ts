import { getPersonActivityStore } from '../adapters/index.js';
import { PERSON_ACTIVITY_FLUSH_MS } from '../consts/person_activity.js';
import { dropPerson, dropProject } from './buffer.js';

/*
 * A person's activity goes with the person and with the project (specs/133 FR-014, FR-016), by hand: the area is
 * unowned, so no cascade reaches it, which is what lets it outlive a lock.
 *
 * Three steps close the window a write in flight leaves open (S6). This process drops what it holds for them; every
 * process's next write drops rows of people who no longer exist; and one more delete, two writes later, removes a
 * row another process wrote in the instant between its check and its write.
 */

function later(remove: () => Promise<number>): void {
	const timer = setTimeout(() => {
		remove().catch((error: unknown) => {
			console.error('activity of a deleted person not removed again', {
				error
			});
		});
	}, 2 * PERSON_ACTIVITY_FLUSH_MS);
	timer.unref();
}

export async function forgetPersonActivity(
	bucketId: string,
	accountId: string
): Promise<void> {
	dropPerson(bucketId, accountId);
	const store = getPersonActivityStore();
	await store.destroyPerson(bucketId, accountId);
	later(() => getPersonActivityStore().destroyPerson(bucketId, accountId));
}

export async function forgetProjectActivity(bucketId: string): Promise<void> {
	dropProject(bucketId);
	await getPersonActivityStore().destroyBucket(bucketId);
	later(() => getPersonActivityStore().destroyBucket(bucketId));
}
