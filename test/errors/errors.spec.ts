import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { getErrorHtmlResponse } from 'lib/html/error.tsx';
import getWWWAuthenticate from 'lib/shared/authorization_error_handler.js';
import { send, UNSERVED_PATH } from '../feature_gate/helpers.ts';

const browserAccept =
	'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';

/**
 * @proves An error reaches a machine as JSON and a person as a readable page whose title matches
 * its status, and neither can carry an unescapable character into a header or a page.
 */
describe('default error behavior', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	/*
	 * The trigger is a credential that is present and unusable, not an absent one. A request carrying
	 * no credentials at all is the one error this pipeline deliberately does not negotiate: RFC 6750
	 * §3.1 has it answered with a challenge and no error information whatever the caller accepts, so
	 * it cannot demonstrate the choice these cases are about.
	 */
	const unusable = { authorization: 'Bearer not-a-token' };

	it('responds with json when no Accept header', async () => {
		const { response } = await agent.userinfo.post({}, { headers: unusable });
		expect(response.headers.get('content-type')).toMatch(/json/);
	});

	it('responds with json when */* header', async () => {
		const { response } = await agent.userinfo.post(
			{},
			{ headers: { ...unusable, accept: '*/*' } }
		);
		expect(response.headers.get('content-type')).toMatch(/json/);
	});

	it('responds with html when browser like header', async () => {
		const { response } = await agent.userinfo.post(
			{},
			{ headers: { ...unusable, accept: browserAccept } }
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

/*
 * RFC 6750 §3 limits `error_description` to NQCHAR, a grammar that holds neither a quote nor a
 * backslash. The challenge used to escape the quote and leave the backslash alone, which is the one
 * combination that fails: a value ending in a backslash closed the quoted string a character early,
 * and everything after it became further auth-params. Escaping only moved the problem — a quoted-pair
 * is exactly what makes an early terminator expressible. Stripping is what the grammar asks for.
 *
 * Nothing dynamic reaches a 401 description today, so this is the guard that has to fail first: the
 * defect arms itself the moment one does.
 */
describe('the WWW-Authenticate challenge', () => {
	it('carries no character the quoted-string grammar cannot hold', () => {
		const header = getWWWAuthenticate('bearer', false, {
			error: 'invalid_token',
			error_description: 'ends with a backslash\\'
		});

		expect(header).not.toContain('\\');
		expect(header).toMatch(/error_description="ends with a backslash"$/);
	});

	it('cannot be talked out of its quoted string into another auth-param', () => {
		const header = getWWWAuthenticate('bearer', false, {
			error: 'invalid_token',
			error_description: 'nudge\\", scope="write'
		});

		// No backslash means no quoted-pair, so every quote left in the header is a real delimiter.
		expect(header).not.toContain('\\');
		expect(header).toMatch(/error_description="nudge, scope=write"$/);
	});
});

/*
 * The document title is the one thing on this page interpolated raw rather than through React, and
 * lib/interactions/plainPage.tsx already escapes the same position — so the inconsistency, not the
 * reachability, is the finding. The error code is drawn from a fixed set today; the page should not
 * be the reason that stays true.
 */
describe('the rendered error page title', () => {
	it('escapes the error code rather than interpolating it as markup', async () => {
		const html = await getErrorHtmlResponse(
			400,
			'<script>alert(1)</script>',
			'a description'
		).text();

		expect(html).not.toContain('<script>alert(1)</script>');
		expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
	});
});
