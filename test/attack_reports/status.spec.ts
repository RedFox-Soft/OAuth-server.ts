import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	attackReceiver,
	attacker,
	closeHour,
	inHour,
	nextHour,
	send
} from './helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { isPublicAddress } from 'lib/helpers/public_address.ts';
import { ATTACK_DESTINATION } from 'lib/consts/attack_report_fields.ts';
import { sendReport } from 'lib/telemetry/send.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

interface Status {
	enabled: boolean;
	offBecause?: string;
	setting: boolean;
	lastDeliveredAt: string | null;
	report: { addresses: { address: string }[] };
	reportIsPreview: boolean;
}

let undoClock: () => void = () => {};

async function cookieOf(kind: AdminKind): Promise<string> {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

function statusAs(cookie?: string): Promise<Response> {
	return elysia.handle(
		new Request(`${ISSUER}/admin/api/settings/attack-reports`, {
			headers: cookie ? { cookie } : {}
		})
	);
}

async function status(): Promise<Status> {
	return (await (await statusAs(await cookieOf('super'))).json()) as Status;
}

/* One hour with one scanner, reported through the real sender to a receiver answering `answer`. */
async function reportOneHour(answer: number): Promise<void> {
	const hour = nextHour();
	undoClock = inHour(hour);
	attackReceiver(answer);
	await send('/.env', attacker());
	await closeHour(hour, (report) => sendReport(report, ATTACK_DESTINATION));
	undoClock();
}

/**
 * @proves A super administrator, in the console or through an agent, sees whether attack reporting is on and
 * why not, when a report was last delivered and exactly what the last report said, or an example with no real
 * address before the first one; no other administrator can read it, because it names addresses.
 */
describe('the attack reporting status', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	afterEach(() => {
		undoClock();
		ApplicationConfig['attackReports.enabled'] = true;
	});

	it('shows an example with no real address before the first report', async () => {
		const shown = await status();

		expect({
			preview: shown.reportIsPreview,
			lastDeliveredAt: shown.lastDeliveredAt,
			realAddresses: shown.report.addresses.filter((entry) =>
				isPublicAddress(entry.address.replace(/\/64$/, '1'))
			)
		}).toEqual({ preview: true, lastDeliveredAt: null, realAddresses: [] });
	});

	it('shows the report exactly as the destination received it', async () => {
		const receiver = attackReceiver();
		const hour = nextHour();
		undoClock = inHour(hour);
		await send('/.env', attacker());
		await closeHour(hour, (report) => sendReport(report, ATTACK_DESTINATION));

		const shown = await status();

		expect({ report: shown.report, preview: shown.reportIsPreview }).toEqual({
			report: receiver.bodies[0] as Status['report'],
			preview: false
		});
	});

	it('keeps the last delivery time when a later report is not delivered', async () => {
		await reportOneHour(204);
		const delivered = (await status()).lastDeliveredAt;
		await reportOneHour(503);

		const shown = await status();

		expect({
			lastDeliveredAt: shown.lastDeliveredAt,
			hadDelivery: delivered !== null
		}).toEqual({ lastDeliveredAt: delivered, hadDelivery: true });
	});

	it('says reporting is off because of the setting when the setting is off', async () => {
		ApplicationConfig['attackReports.enabled'] = false;

		const shown = await status();

		expect([shown.enabled, shown.offBecause, shown.setting]).toEqual([
			false,
			'setting',
			false
		]);
	});

	it('says reporting is off because there is no datastore on the in-memory backend', async () => {
		const shown = await status();

		expect([shown.enabled, shown.offBecause, shown.setting]).toEqual([
			false,
			'no-datastore',
			true
		]);
	});

	it('refuses the status to an administrator who is not a super administrator', async () => {
		const response = await statusAs(await cookieOf('plain'));

		expect(response.status).toBe(403);
	});

	it('refuses the status without a session', async () => {
		const response = await statusAs();

		expect(response.status).toBe(401);
	});
});
