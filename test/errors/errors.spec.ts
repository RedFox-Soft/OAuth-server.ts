import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';

const browserAccept =
	'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';

describe('default error behavior', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('responds with json when no Accept header', async () => {
		const { response } = await agent.userinfo.post({});
		expect(response.headers.get('content-type')).toMatch(/json/);
	});

	it('responds with json when */* header', async () => {
		const { response } = await agent.userinfo.post(
			{},
			{ headers: { accept: '*/*' } }
		);
		expect(response.headers.get('content-type')).toMatch(/json/);
	});

	it('responds with html when browser like header', async () => {
		const { response } = await agent.userinfo.post(
			{},
			{ headers: { accept: browserAccept } }
		);
		expect(response.headers.get('content-type')).toMatch(/html/);
	});
});
