import type { TelemetryStateStoreInstance } from '../lib/adapters/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/*
 * The usage-reporting state (specs/113) against a real datastore. What an in-memory double cannot show is
 * whether two processes racing to create the identifier end with one, whether two racing to claim a day
 * let exactly one send, and whether concurrent flushes of counts add up instead of overwriting. Shared by
 * verify_mongodb.ts and verify_postgres.ts so both backends answer the same questions in the same words.
 *
 * The state is a singleton, so a second run on the same database meets the first run's claimed day; the
 * days used here are derived from the run's time so each run claims days no earlier run has.
 */
export async function verifyTelemetry(
	makeStore: () => TelemetryStateStoreInstance,
	check: Check
): Promise<void> {
	const ids = await Promise.all(
		Array.from({ length: 8 }, () => makeStore().instanceId())
	);
	check(
		'eight processes creating the identifier at once end with one',
		new Set(ids).size === 1,
		ids.join(', ')
	);

	const day = `9${String(Date.now()).padStart(14, '0')}`;
	const claims = await Promise.all(
		Array.from({ length: 8 }, () => makeStore().claimDay(day))
	);
	check(
		'eight processes claiming one day at once give it to exactly one',
		claims.filter(Boolean).length === 1,
		JSON.stringify(claims)
	);
	check(
		'a day already claimed is not claimed again',
		!(await makeStore().claimDay(day))
	);

	const countDay = `${day}-c`;
	const older = `${day}-a`;
	await makeStore().addCounts(
		older,
		{ tokens: { refresh_token: 1 }, serverErrors: 0 },
		[older, countDay]
	);
	await Promise.all(
		Array.from({ length: 10 }, () =>
			makeStore().addCounts(
				countDay,
				{ tokens: { authorization_code: 2 }, serverErrors: 1 },
				[countDay]
			)
		)
	);
	const counts = (await makeStore().read())?.counts ?? {};
	const added = Object.hasOwn(counts, countDay) ? counts[countDay] : undefined;
	check(
		'ten concurrent flushes of counts add up',
		added?.tokens?.authorization_code === 20 && added.serverErrors === 10,
		JSON.stringify(added)
	);
	check('a day outside the kept window is dropped', !(older in counts));

	const report = JSON.stringify({ format: 1, note: 'verify', after: 'note' });
	const at = new Date();
	await makeStore().recordSend(report, at);
	const stored = await makeStore().read();
	check(
		'the last report reads back as the exact text sent, with its delivery time',
		stored?.lastReport === report &&
			stored.lastDeliveredAt === at.toISOString() &&
			stored.lastClaimedDay === day,
		JSON.stringify(stored)
	);

	// The hourly attack report (specs/114) shares the document and must leave the usage report's fields alone.
	const attack = JSON.stringify({ format: 1, addresses: [], verify: 'attack' });
	await makeStore().recordAttackSend(attack, at);
	const later = JSON.stringify({ format: 1, addresses: [], verify: 'later' });
	await makeStore().recordAttackSend(later, null);
	const both = await makeStore().read();
	check(
		'an attack report reads back as the text sent, keeping the usage report untouched',
		both?.lastAttackReport === later &&
			both.lastReport === report &&
			both.lastDeliveredAt === at.toISOString(),
		JSON.stringify(both)
	);
	check(
		'an undelivered attack report keeps the earlier delivery time',
		both?.lastAttackDeliveredAt === at.toISOString(),
		JSON.stringify(both)
	);
}
