import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { attacker, closeHour, inHour, nextHour, send } from './helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { reportPass } from 'lib/telemetry/scheduler.ts';
import { saveSettings, superAdminCookie } from '../settings_apply/helpers.js';

let undoClock: () => void = () => {};
let cookie: string;

async function save(changes: Record<string, unknown>): Promise<void> {
	const response = await saveSettings(cookie, changes);
	if (!response.ok)
		throw new Error(`saving settings answered ${response.status}`);
}

/**
 * @proves An operator stops attack reporting at once, from the console, without a restart, and what was
 * counted is discarded rather than sent later; attack reporting and usage reporting are switched
 * independently.
 */
describe('turning attack reporting off', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		cookie = await superAdminCookie();
	});

	afterEach(async () => {
		undoClock();
		await save({ 'attackReports.enabled': true, 'telemetry.enabled': true });
	});

	it('sends nothing and keeps nothing once the setting is turned off', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await send('/.env', attacker());
		await save({ 'attackReports.enabled': false });
		const whileOff = await closeHour(hour);
		await save({ 'attackReports.enabled': true });

		const afterwards = await closeHour(hour);

		expect([whileOff, afterwards]).toEqual([
			{ outcome: 'off', report: null },
			{ outcome: 'no-report', report: null }
		]);
	});

	it('keeps sending usage reports while attack reporting is off', async () => {
		await save({ 'attackReports.enabled': false });

		const outcome = await reportPass(new Date(nextHour()), async () => true, {
			ignoreSlot: true
		});

		expect(outcome).toBe('delivered');
	});

	it('keeps sending attack reports while usage reporting is off', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await save({ 'telemetry.enabled': false });
		const scanner = attacker();
		await send('/.env', scanner);

		const { report } = await closeHour(hour);

		expect(report?.addresses.map((entry) => entry.address)).toEqual([scanner]);
	});
});
