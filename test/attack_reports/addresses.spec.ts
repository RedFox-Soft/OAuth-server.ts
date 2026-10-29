import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	attacker,
	attacker6,
	closeHour,
	entryFor,
	inHour,
	nextHour,
	repeat,
	send,
	signInProject,
	wrongClientSecret
} from './helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';

let undoClock: () => void = () => {};

/* One representative of every class of address that is not the public internet. */
const NOT_PUBLIC = {
	'private 10/8': '10.1.2.3',
	'private 172.16/12': '172.16.0.9',
	'private 192.168/16': '192.168.1.9',
	'loopback IPv4': '127.0.0.1',
	'loopback IPv6': '::1',
	'link-local IPv4': '169.254.1.9',
	'link-local IPv6': 'fe80::9',
	'unique-local IPv6': 'fd00::9',
	'shared address space': '100.64.0.9',
	'documentation IPv4': '192.0.2.9',
	'documentation IPv6': '2001:db8::9',
	benchmarking: '198.18.0.9',
	'multicast IPv4': '224.0.0.9',
	'multicast IPv6': 'ff02::9',
	'unspecified IPv4': '0.0.0.0',
	'unspecified IPv6': '::',
	'reserved IPv4': '240.0.0.9'
};

/* Past two thresholds at once: a scanner path and ten wrong client secrets. */
async function attackFrom(peer: string, headers: Record<string, string> = {}) {
	await send('/.env', peer, { headers });
	await repeat(10, () => wrongClientSecret(peer));
}

/**
 * @proves Only a caller on the public internet is ever reported: no private, loopback, link-local,
 * unique-local, shared, documentation, benchmarking, multicast, unspecified or reserved address, no forwarded
 * value that is not an address and no caller whose address is unknown; an IPv6 caller leaves only as its /64
 * network, and an IPv4 caller seen in IPv4-mapped form as its IPv4 address.
 */
describe('which addresses may leave the server', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await signInProject();
	});

	afterEach(() => {
		undoClock();
	});

	it('reports no address of any class that is not the public internet, past every threshold', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		for (const peer of Object.values(NOT_PUBLIC)) await attackFrom(peer);

		const { report } = await closeHour(hour);

		expect(report).toBeNull();
	});

	it('never reports a forwarded value that is not an address', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		await attackFrom('10.0.0.5', { 'x-forwarded-for': 'not-an-address' });

		const { report } = await closeHour(hour);

		expect(report).toBeNull();
	});

	it('reports an IPv6 attacker as its /64 network only', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const first = attacker6();
		const second = first.replace(/::7$/, '::8');
		await send('/.env', first);
		await send('/.git/config', second);

		const { report } = await closeHour(hour);
		const network = `${first.split(':').slice(0, 4).join(':')}::/64`;

		expect({
			entry: entryFor(report, network),
			fullAddresses: JSON.stringify(report).match(/::7|::8/g)
		}).toEqual({
			entry: {
				address: network,
				counts: { probe: 2 },
				probes: ['dotenv', 'git']
			},
			fullAddresses: null
		});
	});

	it('reports an IPv4 attacker seen in IPv4-mapped form as its IPv4 address', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		const address = attacker();
		await send('/.env', `::ffff:${address}`);

		const { report } = await closeHour(hour);

		expect(report?.addresses.map((entry) => entry.address)).toEqual([address]);
	});

	it('never reports a caller whose address cannot be determined', async () => {
		const hour = nextHour();
		undoClock = inHour(hour);
		setPeerResolverForTests(null);
		await elysia.handle(new Request(`${ISSUER}/.env`));
		await repeat(10, () =>
			elysia.handle(
				new Request(`${ISSUER}/token`, {
					method: 'POST',
					headers: {
						'content-type': 'application/x-www-form-urlencoded',
						authorization: `Basic ${btoa('attack-machine:wrong')}`
					},
					body: 'grant_type=client_credentials'
				})
			)
		);

		const { report } = await closeHour(hour);

		expect(report).toBeNull();
	});
});
