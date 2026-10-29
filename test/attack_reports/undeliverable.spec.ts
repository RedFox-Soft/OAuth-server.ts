import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	spyOn,
	type Mock
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	attackReceiver,
	attacker,
	closeHour,
	hangingAttackReceiver,
	inHour,
	nextHour,
	send
} from './helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import {
	ATTACK_DESTINATION,
	ATTACK_MAX_TRACKED_ADDRESSES
} from 'lib/consts/attack_report_fields.ts';
import { attackReportPass } from 'lib/attack_reports/scheduler.ts';
import { sendReport } from 'lib/telemetry/send.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

let undoClock: () => void = () => {};

const HOUR_MS = 60 * 60 * 1000;

async function recordedFaults(): Promise<number> {
	const user = await createAdministrator('super', `sa-${Math.random()}@x.io`);
	const cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
	// Recording is a microtask behind the capture; let it land before reading.
	await new Promise((resolve) => setTimeout(resolve, 20));
	const response = await elysia.handle(
		new Request(`${ISSUER}/admin/api/errors`, { headers: { cookie } })
	);
	return ((await response.json()) as { total: number }).total;
}

function consoleSpies(): Mock<(...args: unknown[]) => void>[] {
	return (['log', 'info', 'warn', 'error', 'debug'] as const).map((level) =>
		spyOn(console, level).mockImplementation(() => {})
	);
}

/* What an operator would notice after one undeliverable report: recorded faults and console lines. */
async function traceOfOneUndelivered(
	arrange: () => void,
	timeoutMs = 10_000
): Promise<{ faults: number; lines: number }> {
	const hour = nextHour();
	undoClock = inHour(hour);
	await send('/.env', attacker());
	arrange();
	const spies = consoleSpies();
	await closeHour(hour, (report) =>
		sendReport(report, ATTACK_DESTINATION, timeoutMs)
	);
	const lines = spies.reduce((sum, spy) => sum + spy.mock.calls.length, 0);
	for (const spy of spies) spy.mockRestore();
	return { faults: await recordedFaults(), lines };
}

/**
 * @proves An attack report that cannot be delivered leaves no trace for the operator, is abandoned within its
 * bound and is never sent again; a server process sends at most one report for a closed hour whatever its
 * clock does, and an address-rotation flood cannot make it remember more addresses than its bound.
 */
describe('an attack report that cannot be delivered', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	afterEach(() => {
		undoClock();
	});

	it('leaves no error-store record and no log line when the destination refuses it', async () => {
		expect(await traceOfOneUndelivered(() => attackReceiver(503))).toEqual({
			faults: 0,
			lines: 0
		});
	});

	it('leaves no error-store record and no log line when the destination redirects it', async () => {
		expect(await traceOfOneUndelivered(() => attackReceiver(302))).toEqual({
			faults: 0,
			lines: 0
		});
	});

	it('is abandoned within its bound, leaving no trace, when the destination never answers', async () => {
		const started = Date.now();

		const trace = await traceOfOneUndelivered(
			() => hangingAttackReceiver(),
			200
		);

		expect({ ...trace, abandoned: Date.now() - started < 3000 }).toEqual({
			faults: 0,
			lines: 0,
			abandoned: true
		});
	});

	it('sends only its own addresses in the hour after an undelivered report', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await send('/.env', attacker());
		await closeHour(hour, async () => false);
		const following = new Date(
			new Date(hour).getTime() + HOUR_MS
		).toISOString();
		undoClock();
		undoClock = inHour(following);
		const later = attacker();
		await send('/.env', later);

		const { report } = await closeHour(following);

		expect(report?.addresses.map((entry) => entry.address)).toEqual([later]);
	});

	it('sends one report for a closed hour however often it passes, a clock that jumps back included', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await send('/.env', attacker());
		const sent: unknown[] = [];
		const record = async (report: unknown) => {
			sent.push(report);
			return true;
		};
		const after = new Date(new Date(hour).getTime() + HOUR_MS + 5 * 60 * 1000);

		const outcomes = [
			await attackReportPass(after, record, { ignoreSlot: true }),
			await attackReportPass(new Date(after.getTime() + 60 * 1000), record, {
				ignoreSlot: true
			}),
			await attackReportPass(new Date(after.getTime() - 2 * HOUR_MS), record, {
				ignoreSlot: true
			})
		];

		expect({ outcomes, sent: sent.length }).toEqual({
			outcomes: ['delivered', 'already-handled', 'already-handled'],
			sent: 1
		});
	});

	it('stops remembering new addresses at its bound and keeps counting those it has', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const first = attacker();
		await send('/.env', first);
		for (let i = 1; i < ATTACK_MAX_TRACKED_ADDRESSES; i += 1) {
			await send('/.env', attacker());
		}
		// The heaviest caller of the hour if it were counted, so the report would have to carry it.
		const beyond = attacker();
		for (const path of ['/.env', '/.git', '/.env.local']) {
			await send(path, beyond);
		}
		await send('/.git', first);

		const { report } = await closeHour(hour);
		const addresses = new Set(report?.addresses.map((entry) => entry.address));

		expect({
			beyond: addresses.has(beyond),
			firstCounts: report?.addresses.find((entry) => entry.address === first)
				?.counts
		}).toEqual({ beyond: false, firstCounts: { probe: 2 } });
	}, 60_000);
});
