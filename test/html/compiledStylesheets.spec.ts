import { describe, it, expect } from 'bun:test';

/*
 * The hydrated pages link antd's precompiled stylesheet instead of generating their CSS in the
 * browser. That file ships inside the antd package, so an antd upgrade that moved or dropped it would
 * otherwise present as every hydrated page rendering unstyled — with a 404 in the network tab and
 * nothing in the suite.
 */
describe('antd ships the stylesheets zeroRuntime mode requires', () => {
	it('has a compiled component stylesheet', async () => {
		const css = Bun.file('node_modules/antd/dist/antd.css');
		expect(await css.exists()).toBe(true);
		// A truncated or placeholder file is the failure this guards; the real one is ~1 MB.
		expect(css.size).toBeGreaterThan(500_000);
	});

	it('has a reset stylesheet', async () => {
		const reset = Bun.file('node_modules/antd/dist/reset.css');
		expect(await reset.exists()).toBe(true);
		expect(reset.size).toBeGreaterThan(1_000);
	});
});
