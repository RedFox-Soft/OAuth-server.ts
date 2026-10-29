import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	attacker,
	closeHour,
	inHour,
	nextHour,
	repeat,
	resetRequest,
	scimWithoutCredential,
	send,
	signInProject,
	wrongClientSecret,
	wrongPassword
} from './helper.ts';
import { PROBE_PATHS } from 'lib/consts/attack_report_fields.ts';

let undoClock: () => void = () => {};

const HOUR_MS = 60 * 60 * 1000;

/**
 * @proves An honest visitor's mistakes never leave the server: activity under every threshold, requests that
 * present no credential, and requests for ordinary missing files are not reported, an address is reported
 * only for the hour it attacked in, and no path a scanner is reported for is one the server serves.
 */
describe('honest visitors', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await signInProject();
	});

	afterEach(() => {
		undoClock();
	});

	it('does not report an address whose activity stays under every threshold', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const visitor = attacker();
		await repeat(3, () => wrongPassword(visitor));
		await repeat(3, () => resetRequest(visitor));
		await repeat(4, () => wrongClientSecret(visitor));

		const { report } = await closeHour(hour);

		expect(report).toBeNull();
	});

	it('counts a request without any credential toward nothing', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const client = attacker();
		await repeat(20, () =>
			send('/mcp', client, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
			})
		);
		await repeat(20, () => scimWithoutCredential(client));
		await repeat(20, () =>
			send('/token', client, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: 'grant_type=client_credentials&client_id=no-such-client'
			})
		);

		const { report } = await closeHour(hour);

		expect(report).toBeNull();
	});

	it('counts an unserved path that is not a declared probe toward nothing', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const browser = attacker();
		for (const path of [
			'/favicon.ico',
			'/robots.txt.bak',
			'/admin.php',
			'/config.json'
		]) {
			await send(path, browser);
		}

		const { report } = await closeHour(hour);

		expect(report).toBeNull();
	});

	it('does not report an address in the quiet hour after the one it attacked in', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await send('/.env', attacker());
		await closeHour(hour);
		const following = new Date(
			new Date(hour).getTime() + HOUR_MS
		).toISOString();

		const { report } = await closeHour(following);

		expect(report).toBeNull();
	});

	it('answers not found for every declared probe path', async () => {
		const scanner = attacker();
		const paths = PROBE_PATHS.flatMap((probe) => [
			...probe.exact,
			...probe.prefixes.map(
				(prefix) => `${prefix}${prefix.endsWith('/') ? '' : '/'}index.php`
			)
		]);
		const served: string[] = [];
		for (const path of paths) {
			const response = await send(path, scanner);
			if (response.status !== 404) served.push(`${path} ${response.status}`);
		}

		expect(served).toEqual([]);
	});
});
