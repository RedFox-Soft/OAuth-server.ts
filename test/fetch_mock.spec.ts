import { describe, it, expect, afterEach, mock as bunMock } from 'bun:test';

import { mock } from './fetch_mock.ts';

/*
 * The helper's own state is module state, so it outlives a spec file while the `globalThis.fetch`
 * patch does not: Bun puts the real `fetch` back at the file boundary. A spec that registers an
 * interceptor and ends without calling `mock.restore()` therefore hands the next file a helper that
 * believes it is installed when it is not — and the next file's requests leave the machine.
 *
 * That is not hypothetical: it made test/mcp/secrecy.spec.ts fail on Linux CI (where the file order
 * put such a spec first) while passing on Windows, and the failure looked like an unreachable
 * upstream rather than a harness bug, because the request really was reaching the network.
 */
describe('the outbound fetch mock', () => {
	afterEach(() => {
		mock.restore();
	});

	it('intercepts a mocked origin', async () => {
		mock('https://intercepted.test')
			.intercept({ path: '/probe' })
			.reply(200, '{"ok":true}', {
				headers: { 'content-type': 'application/json' }
			});

		const response = await fetch('https://intercepted.test/probe');

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
	});

	it('reinstalls itself when the patch was dropped but its own state was not', async () => {
		// Register once so the helper's internal spy handle is set.
		mock('https://first.test').intercept({ path: '/a' }).reply(200, 'a');

		/*
		 * Bun's global restore is what a spec-file boundary does to the patch: `globalThis.fetch` is
		 * the real one again, while the helper's module-level handle still refers to the spy it made.
		 * The helper must notice that and patch again rather than trust its own bookkeeping.
		 */
		bunMock.restore();

		mock('https://second.test')
			.intercept({ path: '/b' })
			.reply(200, '{"ok":true}', {
				headers: { 'content-type': 'application/json' }
			});

		// Without the fix this escapes to the network and rejects (DNS) instead of being intercepted.
		const response = await fetch('https://second.test/b');

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
	});

	it('still refuses an unmatched path on a mocked origin', async () => {
		mock('https://strict.test').intercept({ path: '/known' }).reply(200, 'k');

		let threw: unknown;
		try {
			await fetch('https://strict.test/unknown');
		} catch (error) {
			threw = error;
		}

		expect(String(threw)).toInclude('No mock interceptor');
	});
});
