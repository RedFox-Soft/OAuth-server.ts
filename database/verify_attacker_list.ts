import type { ModelAdapter } from '../lib/adapters/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/*
 * The attacker list's sign-in counters (specs/125) against a real datastore: one record per project, day and process,
 * read back by the declared bucket index. What the in-memory double cannot show is that the index exists and answers
 * the jsonb (or document) field, and that a record past its expiry is honoured as the reader expects. Shared by
 * verify_mongodb.ts and verify_postgres.ts.
 */
export async function verifyAttackerListCounts(
	tallies: ModelAdapter<Record<string, unknown>>,
	check: Check
): Promise<void> {
	const bucketId = `verify-guessing-${String(Date.now())}`;
	const other = `${bucketId}-other`;
	const exp = Math.floor(Date.now() / 1000) + 3600;
	const record = (bucket: string, process: string, attempts: number) => ({
		bucketId: bucket,
		day: '2026-11-09',
		attempts,
		rightPassword: 1,
		refused: 0,
		exp
	});
	await tallies.upsert(
		`${bucketId}:2026-11-09:a`,
		record(bucketId, 'a', 3),
		3600
	);
	await tallies.upsert(
		`${bucketId}:2026-11-09:b`,
		record(bucketId, 'b', 4),
		3600
	);
	await tallies.upsert(`${other}:2026-11-09:a`, record(other, 'a', 9), 3600);
	// A second flush of the same process rewrites its absolute totals rather than adding a record.
	await tallies.upsert(
		`${bucketId}:2026-11-09:b`,
		record(bucketId, 'b', 5),
		3600
	);

	const found = await tallies.findByIndexed('bucketId', bucketId);
	const attempts = found.map((r) => Number(r.attempts)).sort((a, b) => a - b);
	check(
		"a project's sign-in counter records are found by its index, one per process, rewritten in place",
		JSON.stringify(attempts) === '[3,5]',
		JSON.stringify(found)
	);
}
