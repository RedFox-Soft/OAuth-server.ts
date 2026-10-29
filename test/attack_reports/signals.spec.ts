import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	attacker,
	badMcpToken,
	badScimToken,
	closeHour,
	entryFor,
	inHour,
	nextHour,
	repeat,
	resetRequest,
	send,
	signInProject,
	withRateLimit,
	wrongClientSecret,
	wrongPassword
} from './helper.ts';

let undoClock: () => void = () => {};

/**
 * @proves Every kind of attack the server refuses (password guessing, wrong client credentials, wrong SCIM or
 * MCP credentials, floods, mass mail requests and scanner paths) is reported to FoxTrust, under its own type,
 * once the attacking address crosses that type's threshold within an hour.
 */
describe('the attacks a report carries', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await signInProject();
	});

	afterEach(() => {
		undoClock();
	});

	it('reports an address failing the password past the threshold under sign-in failures', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		await repeat(10, () => wrongPassword(address));

		const { report } = await closeHour(hour);

		expect(entryFor(report, address)?.counts).toEqual({ signin_failures: 10 });
	});

	it('reports an address presenting wrong client credentials past the threshold under client authentication failures', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		await repeat(10, () => wrongClientSecret(address));

		const { report } = await closeHour(hour);

		expect(entryFor(report, address)?.counts).toEqual({
			client_auth_failures: 10
		});
	});

	it('reports an address requesting a declared probe path under probe with its label', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		await send('/.env', address);

		const { report } = await closeHour(hour);

		expect(entryFor(report, address)).toEqual({
			address,
			counts: { probe: 1 },
			probes: ['dotenv']
		});
	});

	it('reports an address refused by the rate limit past the threshold under flood', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		const undoLimit = withRateLimit(1);
		try {
			await repeat(21, () =>
				send('/.well-known/openid-configuration', address)
			);
		} finally {
			undoLimit();
		}

		const { report } = await closeHour(hour);

		expect(entryFor(report, address)?.counts).toEqual({ flood: 20 });
	});

	it('reports an address presenting invalid SCIM and MCP credentials past the threshold under administrative credential failures', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		await repeat(3, () => badScimToken(address));
		await repeat(2, () => badMcpToken(address));

		const { report } = await closeHour(hour);

		expect(entryFor(report, address)?.counts).toEqual({
			admin_credential_failures: 5
		});
	});

	it('reports an address making mail requests past the threshold under mail requests, refused ones included', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		await repeat(10, (i) => resetRequest(address, `victim-${i}@x.io`));

		const { report } = await closeHour(hour);

		expect(entryFor(report, address)?.counts).toEqual({ mail_requests: 10 });
	});
});
