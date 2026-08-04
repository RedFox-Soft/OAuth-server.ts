import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { getErrorHtmlResponse } from 'lib/html/error.tsx';
import { send, UNSERVED_PATH } from '../feature_gate/helpers.ts';

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

/*
 * The illustration used to be `status === 500 ? '500' : '403'`, so a not-found was drawn as an access
 * refusal — an operator chasing a permissions problem that did not exist. The status *code* half of
 * this defect (every rendered error answering 200) was fixed with the feature-gate work; this is the
 * remaining half.
 *
 * `ant-result-{status}` is the component's own root class, so it names the chosen illustration
 * directly rather than fingerprinting the artwork.
 */
describe('rendered error page illustration', () => {
	async function render(status: number) {
		const res = getErrorHtmlResponse(status, 'an_error', 'a description');
		return { status: res.status, html: await res.text() };
	}

	it('draws a not-found as a not-found', async () => {
		const { html } = await render(404);
		expect(html).toContain('ant-result-404');
	});

	it('draws an access refusal as a refusal', async () => {
		const { html } = await render(403);
		expect(html).toContain('ant-result-403');
	});

	it('draws a server fault as a server fault', async () => {
		for (const status of [500, 503]) {
			const { html } = await render(status);
			expect(html).toContain('ant-result-500');
		}
	});

	// The point of the batch: a 400 or a 401 gets a general error illustration, never one naming a
	// cause that did not occur.
	it('draws every other client error generically', async () => {
		for (const status of [400, 401, 429]) {
			const { html } = await render(status);
			expect(html).toContain('ant-result-error');
			expect(html).not.toContain('ant-result-403');
			expect(html).not.toContain('ant-result-404');
		}
	});

	it('keeps the displayed title equal to the response status', async () => {
		for (const status of [400, 403, 404, 500]) {
			const { status: responseStatus, html } = await render(status);
			expect(responseStatus).toBe(status);
			expect(html).toContain(`>${status}</div>`);
		}
	});
});

describe('an unserved path rendered for a browser', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	// The end-to-end form of the case above: the status and the illustration have to agree on the
	// one path a real browser reaches by accident.
	it('answers 404 and draws a not-found', async () => {
		const res = await send(UNSERVED_PATH, {
			method: 'GET',
			headers: { accept: browserAccept }
		});
		expect(res.status).toBe(404);
		expect(await res.text()).toContain('ant-result-404');
	});
});
