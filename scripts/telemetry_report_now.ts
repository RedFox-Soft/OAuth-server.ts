/*
 * Sends today's usage report now, without waiting for this instance's slot (specs/113 quickstart).
 *
 * For checking reporting by hand: run it against the instance's own datastore and it claims today and
 * sends, exactly as the timer would. `--to <https URL>` sends to another receiver instead of FoxTrust —
 * an argument of this script, never server configuration, since the server's destination has no override.
 *
 *   bun scripts/telemetry_report_now.ts [--to https://receiver.example/usage]
 *
 * It refuses an instance without a datastore: such an instance never reports, and its identifier would be
 * a new one on every run.
 */
const toIndex = process.argv.indexOf('--to');
const to = toIndex === -1 ? undefined : process.argv[toIndex + 1];
if (to !== undefined && !/^https:\/\//.test(to)) {
	console.error('--to must be an https:// URL');
	process.exit(2);
}

const { selectBackend } = await import('../lib/adapters/selectBackend.ts');
if (selectBackend(process.env) === 'memory') {
	console.error(
		'no datastore is configured (MONGODB_URI or POSTGRES_URL): an instance without one never reports'
	);
	process.exit(2);
}

const { reportPass } = await import('../lib/telemetry/scheduler.ts');
const { sendReport } = await import('../lib/telemetry/send.ts');

const outcome = await reportPass(
	new Date(),
	(report) => sendReport(report, to),
	{ ignoreSlot: true }
);

const said: Record<typeof outcome, string> = {
	off: 'not sent: reporting is turned off in Settings',
	'before-slot': 'not sent: before the slot',
	'already-reported': 'not sent: already reported today',
	'no-report': 'not sent: the report could not be built',
	delivered: 'delivered',
	'not-delivered': 'not delivered'
};
console.log(said[outcome]);
if (
	to !== undefined &&
	(outcome === 'delivered' || outcome === 'not-delivered')
) {
	console.log(
		`today is now claimed, so FoxTrust gets no report from this instance today (sent to ${to})`
	);
}
process.exit(0);
