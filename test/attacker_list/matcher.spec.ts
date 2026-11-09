import { describe, it, expect } from 'bun:test';
import { BlockList } from 'node:net';

import { parseAddress } from 'lib/behind_proxy/net.ts';
import { buildMatcher } from 'lib/attacker_list/matcher.ts';
import { parseEntry } from 'lib/attacker_list/parse.ts';

/*
 * A deterministic generator, so a failure names the case that produced it and a rerun reproduces it.
 */
function generator(seed: number) {
	let state = seed >>> 0;
	return () => {
		state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
		return state;
	};
}

function ipv4(next: () => number, near?: number): string {
	const value = near === undefined ? next() : (near + (next() % 512)) >>> 0;
	return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
}

function ipv6Prefix(next: () => number): string {
	const groups = Array.from({ length: 4 }, () =>
		((next() % 6) + 0x2a00 * (next() % 2)).toString(16)
	);
	return `2001:db8:${groups[2]}:${groups[3]}`;
}

function ipv6In(prefix: string, next: () => number): string {
	return `${prefix}:${(next() % 0xffff).toString(16)}:0:0:${(next() % 0xffff).toString(16)}`;
}

/**
 * @proves An address is found on the attacker list exactly when the list covers it: an IPv4 address by itself, an
 * IPv6 address by its /64, and an IPv4-mapped IPv6 address as the IPv4 address it carries.
 */
describe('finding an address on the attacker list', () => {
	it('answers as an independent reference for generated lists and addresses', () => {
		for (let seed = 1; seed <= 20; seed += 1) {
			const next = generator(seed);
			const anchor = next();
			const v4 = Array.from({ length: 200 }, () => ipv4(next, anchor));
			const prefixes = Array.from({ length: 50 }, () => ipv6Prefix(next));
			const lines = [
				...v4.map((address) => `${address}\tlogin_bruteforce\t3600\tweak\t0`),
				...prefixes.map(
					(prefix) => `${prefix}::/64\tlogin_bruteforce\t3600\tweak\t0`
				)
			];
			const matcher = buildMatcher(
				lines.map((line) => parseEntry(line)).filter((entry) => entry !== null)
			);
			const reference = new BlockList();
			for (const address of v4) reference.addAddress(address, 'ipv4');
			for (const prefix of prefixes) {
				reference.addSubnet(`${prefix}::`, 64, 'ipv6');
			}

			const probes = [
				...Array.from({ length: 400 }, () => ipv4(next, anchor)),
				...Array.from({ length: 200 }, () =>
					ipv6In(prefixes[next() % prefixes.length], next)
				),
				...Array.from({ length: 200 }, () => ipv6In(ipv6Prefix(next), next))
			];
			for (const probe of probes) {
				const parsed = parseAddress(probe);
				if (!parsed) throw new Error(`generated a bad address: ${probe}`);
				const family = probe.includes(':') ? 'ipv6' : 'ipv4';
				expect({ probe, found: matcher.lookup(parsed) !== null }).toEqual({
					probe,
					found: reference.check(probe, family)
				});
			}
		}
	});

	it('finds an IPv4-mapped IPv6 address as the IPv4 address it carries', () => {
		const matcher = buildMatcher(
			[parseEntry('11.0.0.7\tlogin_bruteforce\t3600\tweak\t0')].filter(
				(entry) => entry !== null
			)
		);
		const mapped = parseAddress('::ffff:11.0.0.7');
		if (!mapped) throw new Error('mapped address did not parse');

		expect(matcher.lookup(mapped)).not.toBeNull();
	});

	it('skips a line naming a code this release does not know', () => {
		expect(parseEntry('11.0.0.8\tmail_flood\t3600\tweak\t0')).toBeNull();
	});

	it('skips an IPv4 line wider than one address', () => {
		expect(
			parseEntry('11.0.0.0/24\tlogin_bruteforce\t3600\tweak\t0')
		).toBeNull();
	});

	it('skips an IPv6 line other than a /64', () => {
		expect(
			parseEntry('2001:db8::/48\tlogin_bruteforce\t3600\tweak\t0')
		).toBeNull();
	});
});
