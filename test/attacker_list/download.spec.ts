import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { parseAddress } from 'lib/behind_proxy/net.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { ATTACKER_LIST_MAX_BYTES } from 'lib/consts/attacker_list.ts';
import {
	listInEffect,
	listStatus,
	resetAttackerListForTests
} from 'lib/attacker_list/state.ts';
import {
	clockAt,
	iso,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer,
	at,
	type Publication,
	type Signer
} from './helper.ts';

await bootstrap(import.meta.url);

function holds(address: string, hours: number): boolean {
	const parsed = parseAddress(address);
	if (!parsed) throw new Error(`not an address: ${address}`);
	return (
		(listInEffect(at(hours).getTime())?.matcher.lookup(parsed) ?? null) !== null
	);
}

/**
 * @proves A list is applied only when it verifies with a pinned key, matches the manifest, is newer than the one
 * held (also after a restart) and still valid; anything else keeps the previous list, and a stale list applies to
 * nobody.
 */
describe("FoxTrust's attacker list, as a server process takes it", () => {
	let foxtrust: Signer;
	let stranger: Signer;
	let published: Publication;
	let undoClock: () => void;

	beforeEach(async () => {
		resetAttackerList();
		foxtrust = await signer('foxtrust');
		stranger = await signer('stranger');
		published = publication();
		undoClock = clockAt(0.1);
	});

	afterEach(() => {
		undoClock();
	});

	it('applies the addresses of a list FoxTrust signed', async () => {
		const address = listedAddress();
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: address, lastSeen: seconds(-1) }],
			by: foxtrust
		});

		expect(await pass(foxtrust)).toBe('accepted');
		expect(holds(address, 0.1)).toBe(true);
	});

	it('keeps the list it holds when a newer file is signed by another key', async () => {
		const kept = listedAddress();
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: kept, lastSeen: seconds(-1) }],
			by: foxtrust
		});
		await pass(foxtrust);
		await published.publish({
			version: 'a2',
			builtAt: iso(1),
			validUntil: iso(4),
			lines: [],
			by: foxtrust,
			fileSignedBy: stranger
		});

		expect(await pass(foxtrust)).toBe('signature');
		expect(holds(kept, 0.1)).toBe(true);
	});

	it('refuses a manifest signed by another key', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: listedAddress(), lastSeen: seconds(-1) }],
			by: stranger
		});

		expect(await pass(foxtrust)).toBe('signature');
		expect(listInEffect(at(0.1).getTime())).toBeNull();
	});

	it('refuses a file whose size differs from what the manifest states', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: listedAddress(), lastSeen: seconds(-1) }],
			by: foxtrust,
			manifestSize: 1
		});

		expect(await pass(foxtrust)).toBe('size');
		expect(listInEffect(at(0.1).getTime())).toBeNull();
	});

	it('refuses a file whose digest differs from what the manifest states', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: listedAddress(), lastSeen: seconds(-1) }],
			by: foxtrust,
			manifestSha256: '0'.repeat(64)
		});

		expect(await pass(foxtrust)).toBe('digest');
		expect(listInEffect(at(0.1).getTime())).toBeNull();
	});

	it('refuses a file larger than the cap without reading it whole', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: foxtrust,
			file: new Uint8Array(ATTACKER_LIST_MAX_BYTES + 1).fill(97)
		});

		expect(await pass(foxtrust)).toBe('size');
	});

	it('refuses a list built no later than the one it holds', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: foxtrust
		});
		await pass(foxtrust);
		await published.publish({
			version: 'a0',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: listedAddress(), lastSeen: seconds(-1) }],
			by: foxtrust
		});

		expect(await pass(foxtrust)).toBe('older');
	});

	it('refuses an older list after a restart', async () => {
		await published.publish({
			version: 'a2',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: foxtrust
		});
		await pass(foxtrust);
		// A new process: nothing held in memory, the instance's record of what it accepted still there.
		resetAttackerListForTests();
		await published.publish({
			version: 'a1',
			builtAt: iso(-0.5),
			validUntil: iso(2.5),
			lines: [{ network: listedAddress(), lastSeen: seconds(-1) }],
			by: foxtrust
		});

		expect(await pass(foxtrust)).toBe('older');
	});

	it('applies the list to nobody once its validity has passed', async () => {
		const address = listedAddress();
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: address, lastSeen: seconds(-1) }],
			by: foxtrust
		});
		await pass(foxtrust);

		expect(holds(address, 3)).toBe(false);
		expect(listStatus(at(3).getTime()).state).toBe('out-of-date');
	});

	it('refuses a list already past its validity', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(-4),
			validUntil: iso(-1),
			lines: [{ network: listedAddress(), lastSeen: seconds(-5) }],
			by: foxtrust
		});

		expect(await pass(foxtrust)).toBe('expired');
	});

	it('asks for an update of FoxAuth when FoxTrust lists only a format it cannot read', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: foxtrust,
			format: '2'
		});
		await pass(foxtrust);

		expect(listStatus(at(0.1).getTime()).state).toBe('unknown-format');
	});

	it('shows no rejection after a single signature mismatch', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: stranger
		});
		await pass(foxtrust);

		expect(listStatus(at(0.1).getTime()).lastProblem).toBeNull();
	});

	it('shows a rejection once a signature mismatch repeats', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: stranger
		});
		await pass(foxtrust);
		await pass(foxtrust);

		expect(listStatus(at(0.1).getTime()).lastProblem?.kind).toBe('signature');
	});

	it('names the FoxAuth version while usage reports are on', async () => {
		await published.publish({
			version: 'a1',
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [],
			by: foxtrust
		});
		await pass(foxtrust);

		for (const request of published.requests) {
			expect(request.headers.get('user-agent')).toMatch(/^FoxAuth\/\d/);
		}
	});

	it('sends no version, and nothing else about the server, while usage reports are off', async () => {
		ApplicationConfig['telemetry.enabled'] = false;
		try {
			await published.publish({
				version: 'a1',
				builtAt: iso(0),
				validUntil: iso(3),
				lines: [],
				by: foxtrust
			});
			await pass(foxtrust);
		} finally {
			ApplicationConfig['telemetry.enabled'] = true;
		}

		for (const request of published.requests) {
			expect(request.headers.get('user-agent')).toBe('FoxAuth');
			expect([...request.headers.keys()].sort()).toEqual(
				[...request.headers.keys()]
					.filter((name) => name === 'user-agent' || name === 'if-none-match')
					.sort()
			);
		}
	});
});
