import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { CONSENT_TEXTS as T } from 'lib/interactions/consentTexts.js';
import { serveDocument, mock } from './document_host.js';
import { openConsent } from '../consent_page/flow.ts';

/*
 * What the End-User is shown about a client that identified itself with a document it hosts.
 *
 * The name on the screen is whatever that document claims, so on its own it proves nothing — which is
 * why the draft's §8.5 and the MCP security considerations both require the hostnames beside it: the
 * domain is the part that was actually proved. The loopback warning is a stated SHOULD, because such a
 * document cannot establish which local process will receive the authorization code.
 */

const publicAddress = '93.184.216.34';

/**
 * @proves A user asked to authorize a document-identified client is shown who it actually is,
 * including when its redirect leaves the identifier host or offers only loopback.
 */
describe('the consent page for a document-identified client', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'cimd' });
		cookie = await setup.login({ scope: 'openid' });
	});

	beforeEach(() => {
		clearDocumentCache();
		resolver.lookup = async () => [publicAddress];
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
	});

	it('shows where the answer goes and that the server has not checked the app', async () => {
		const { identifier } = serveDocument();

		const page = await openConsent(
			{
				client_id: identifier,
				scope: 'openid',
				redirect_uri: 'https://app.example.com/callback'
			},
			cookie
		);

		expect(page.view.client.tier).toBe('self-registered');
		expect(page.text).toContain(`${T.host.label} app.example.com`);
		expect(page.text).toContain(T.host.notChecked(page.view.service.host));
		// The document's host is the redirect's host, so it is not shown a second time.
		expect(page.view.redirect.documentHost).toBeUndefined();
	});

	it('shows both hosts and warns when the redirect leaves the identifier host', async () => {
		const { identifier } = serveDocument({
			overrides: { redirect_uris: ['https://cdn.elsewhere.example/cb'] }
		});

		const page = await openConsent(
			{
				client_id: identifier,
				scope: 'openid',
				redirect_uri: 'https://cdn.elsewhere.example/cb'
			},
			cookie
		);

		expect(page.view.redirect).toMatchObject({
			host: 'cdn.elsewhere.example',
			documentHost: 'app.example.com'
		});
		expect(page.text).toContain(`${T.host.documentLabel} app.example.com`);
		expect(page.text).toContain(T.warning.hostMismatch);
	});

	it('warns when every offered redirect target is loopback', async () => {
		const { identifier } = serveDocument({
			overrides: { redirect_uris: ['http://127.0.0.1:33418/callback'] }
		});

		const page = await openConsent(
			{
				client_id: identifier,
				scope: 'openid',
				redirect_uri: 'http://127.0.0.1:33418/callback'
			},
			cookie
		);

		expect(page.view.warning).toEqual({ kind: 'loopback' });
	});

	/*
	 * A document offering a real HTTPS target as well is not in the same position: the domain it proved
	 * is somewhere the code can actually be sent, so the warning would be noise.
	 */
	it('does not warn about loopback when a web target is also offered', async () => {
		const { identifier } = serveDocument({
			overrides: {
				redirect_uris: [
					'http://127.0.0.1:1/cb',
					'https://app.example.com/callback'
				]
			}
		});

		const page = await openConsent(
			{
				client_id: identifier,
				scope: 'openid',
				redirect_uri: 'http://127.0.0.1:1/cb'
			},
			cookie
		);

		expect(page.view.warning?.kind).not.toBe('loopback');
		expect(page.text).toContain(T.next.loopback);
	});

	/*
	 * An ordinary registered client gets none of this: the operator who made it is the instance's own, so
	 * there is no unchecked app to warn about — only the address it sends the answer to.
	 */
	it('says nothing of an unchecked app for an ordinary registered client', async () => {
		const page = await openConsent(
			{ client_id: 'client', scope: 'openid email', prompt: 'consent' },
			cookie
		);

		expect(page.view.client.tier).toBe('this-organization');
		expect(page.text).not.toContain(T.host.notChecked(page.view.service.host));
		expect(page.text).toContain('client.example.com');
	});
});
