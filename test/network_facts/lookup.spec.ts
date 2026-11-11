import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { decide } from 'lib/behind_proxy/decide.ts';
import type { NetworkFacts } from 'lib/behind_proxy/conditions.ts';
import { factsForBelieved } from 'lib/network_facts/lookup.ts';
import { agent, call, cookieOf, rpc, tool } from './agents.ts';
import {
	ADDRESSES,
	clockAt,
	fullVersion,
	loadStandard,
	publication,
	resetNetworkFacts,
	signer
} from './publication.ts';

let undoClock: () => void = () => {};

async function lookUp(address: string, cookie?: string) {
	const answer = await call(
		'POST',
		'/admin/api/network-facts/lookup',
		cookie ?? (await cookieOf('plain')),
		{ address }
	);
	return {
		status: answer.status,
		body: (await answer.json()) as Record<string, unknown>
	};
}

/**
 * @proves Any administrator learns what this server's snapshot says about an address, with its age, without the
 * address going anywhere or into the audit trail; and "Check access" given that answer decides as the proxy does.
 */
describe('Looking up an address in network facts', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	beforeEach(async () => {
		resetNetworkFacts();
		undoClock = clockAt(0.2);
		ApplicationConfig['mcp.enabled'] = true;
		await loadStandard(publication(), await signer());
	});

	afterEach(() => {
		undoClock();
		ApplicationConfig['networkFacts.enabled'] = true;
	});

	it("answers an administrator an address's categories and country, with the snapshot's age", async () => {
		const { status, body } = await lookUp(ADDRESSES.tor);
		expect(status).toBe(200);
		expect(body).toMatchObject({
			facts: { known: true, categories: ['tor'], country: 'DE' },
			state: 'current',
			fullVersion: fullVersion(),
			ageSeconds: 720
		});
	});

	it('answers nothing known for an address the snapshot does not hold', async () => {
		const { body } = await lookUp(ADDRESSES.unlisted);
		expect(body.facts).toEqual({ known: true, categories: [], country: null });
	});

	it('answers unknown once the snapshot is more than 26 hours old', async () => {
		undoClock();
		undoClock = clockAt(27);
		const { body } = await lookUp(ADDRESSES.tor);
		expect([body.facts, body.state]).toEqual([{ known: false }, 'stale']);
	});

	it('refuses text that is no address', async () => {
		const { status, body } = await lookUp('not-an-address');
		expect([status, body.code]).toEqual([400, 'invalid_address']);
	});

	it('records the lookup in the audit trail without the address', async () => {
		const cookie = await cookieOf('plain');
		const before = (
			await adminAuditStore.list({ action: 'networkfacts.lookup' })
		).entries.length;
		await lookUp('45.10.20.30', cookie);
		const { entries } = await adminAuditStore.list({
			action: 'networkfacts.lookup'
		});
		expect(entries.length).toBe(before + 1);
		expect(JSON.stringify(entries)).not.toContain('45.10.20.30');
	});

	it('writes the address to no log line', async () => {
		const lines: string[] = [];
		const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
			(level) =>
				spyOn(console, level).mockImplementation((...args: unknown[]) => {
					lines.push(args.map(String).join(' '));
				})
		);
		try {
			await lookUp('45.10.20.31');
		} finally {
			for (const spy of spies) spy.mockRestore();
		}
		expect(lines.join('\n')).not.toContain('45.10.20.31');
	});

	it('lets an agent look an address up', async () => {
		const { payload } = await rpc(
			tool('network_facts_lookup', { address: ADDRESSES.hosting }),
			await agent('plain')
		);
		expect(payload.result?.isError).not.toBe(true);
		expect(payload.result?.structuredContent?.result).toMatchObject({
			facts: { known: true, categories: ['hosting'], country: 'NL' }
		});
	});

	it('gives "Check access" the decision the proxy reaches, for every address of the snapshot', async () => {
		const rules = [
			{
				path: '/',
				who: {
					kind: 'conditional' as const,
					who: { kind: 'project' as const },
					conditions: [
						{
							kind: 'network' as const,
							only: [],
							not: [],
							facts: {
								categories: ['tor' as const, 'hosting' as const],
								countries: { mode: 'not' as const, codes: ['FR'] },
								outcome: { kind: 'refuse' as const }
							}
						}
					]
				}
			}
		];
		const cookie = await cookieOf('plain');
		for (const address of Object.values(ADDRESSES)) {
			const { body } = await lookUp(address, cookie);
			const input = {
				rules,
				method: 'GET',
				rawPath: '/',
				person: { canSignIn: true, groupIds: [] },
				address,
				at: Date.now()
			};
			/* The console hands the route's answer to decide() as it came; the response schema is NetworkFacts'. */
			const inConsole = decide({
				...input,
				network: body.facts as NetworkFacts
			});
			const proxy = decide({
				...input,
				network: factsForBelieved(address, rules[0].who.conditions)
			});
			expect([address, inConsole.reason]).toEqual([address, proxy.reason]);
		}
	});
});
