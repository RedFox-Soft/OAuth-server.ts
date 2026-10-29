import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	attacker,
	closeHour,
	entryFor,
	inHour,
	nextHour,
	repeat,
	send,
	signInProject,
	wrongClientSecret,
	wrongPassword
} from './helper.ts';
import { reportPass } from 'lib/telemetry/scheduler.ts';

let undoClock: () => void = () => {};

/**
 * @proves An attack report carries the declared fields and nothing an attacker sent: no username, password,
 * client identifier, path, header or body. An hour in which nobody crossed a threshold sends nothing, a
 * report carries the server's usage-report identifier, and an hour with more attackers than a report holds
 * keeps the heaviest and says how many it left out.
 */
describe('what an attack report holds', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await signInProject();
	});

	afterEach(() => {
		undoClock();
	});

	it('sends nothing for an hour in which no address crossed a threshold', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await repeat(3, () => wrongPassword(attacker()));

		const { outcome, report } = await closeHour(hour);

		expect({ outcome, report }).toEqual({ outcome: 'no-report', report: null });
	});

	it('carries none of the usernames, passwords, client identifiers, paths, headers or bodies the attack sent', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		await repeat(10, () =>
			wrongPassword(address, 'zqmark-user@zqmark.example', 'zqmark-password')
		);
		await repeat(10, () => wrongClientSecret(address, 'zqmark-secret'));
		await send('/.env?zqmark-query=zqmark', address, {
			headers: { 'x-zqmark': 'zqmark-header', 'user-agent': 'zqmark-agent' }
		});
		await send('/wp-login.php', address, {
			method: 'POST',
			headers: { 'content-type': 'text/plain' },
			body: 'zqmark-body'
		});

		const { report } = await closeHour(hour);
		const text = JSON.stringify(report);

		expect({
			reported: entryFor(report, address) !== undefined,
			marks: text.match(/zqmark|attack-machine|attack-app|\/\.env|wp-login/g)
		}).toEqual({ reported: true, marks: null });
	});

	it('carries the identifier the usage report carries', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await send('/.git/config', attacker());
		let usage: unknown;
		await reportPass(
			new Date(hour),
			async (sent) => {
				usage = sent;
				return true;
			},
			{ ignoreSlot: true }
		);

		const { report } = await closeHour(hour);

		expect(report?.instanceId).toBe(
			(usage as { instanceId: string }).instanceId
		);
	});

	it('keeps the 500 addresses with the highest counts and states how many were left out', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const heavy: string[] = [];
		for (let i = 0; i < 520; i += 1) {
			const address = attacker();
			await send('/.env', address);
			if (i % 26 === 0) {
				heavy.push(address);
				await send('/.git', address);
			}
		}

		const { report } = await closeHour(hour);

		expect({
			carried: report?.addresses.length,
			omitted: report?.omitted,
			heavyAllCarried: heavy.every(
				(address) => entryFor(report, address) !== undefined
			)
		}).toEqual({ carried: 500, omitted: 20, heavyAllCarried: true });
	});
});
