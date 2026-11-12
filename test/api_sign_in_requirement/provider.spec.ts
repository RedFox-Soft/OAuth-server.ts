import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { idpStub } from '../federation/idp_stub.ts';
import { get, provider, seedBucket, walk } from '../federation/harness.ts';
import { present } from '../shape.ts';
import { propsOf, textOf } from '../require_code/helpers.ts';
import { AGENT, apis, FILES } from './helpers.ts';

let bucketId = '';
let idp: Awaited<ReturnType<typeof idpStub>>;

/* The agent's sign-in for Files, as an MCP client starts it, up to the interaction it opens. */
async function startForFiles(): Promise<{ uid: string; cookie: string }> {
	const auth = new AuthorizationRequest({
		client_id: AGENT,
		scope: 'openid files:read',
		resource: [FILES]
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = present(response.headers.get('location'), 'a redirect');
	const cookie = present(response.headers.get('set-cookie'), 'a cookie');
	return { uid: location.split('/')[2], cookie };
}

/**
 * @proves A person who signs in through a provider is never waved through an API's requirement: when the API asks for a
 * recent sign-in the provider is asked for a fresh one no older than the API allows, and when the API asks for a code,
 * which a provider sign-in cannot give here, the person is told so on a page that names the API and offers no set-up.
 */
describe('a provider sign-in for an API that requires a code or a recent sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'api_sign_in_requirement' });
		idp = await idpStub('https://idp-api-requirement.test');
		bucketId = await seedBucket(AGENT, {
			federation: [provider(idp.origin)],
			passwordLogin: true
		});
	});

	beforeEach(() => {
		idp.expectDiscovery();
	});

	it('asks the provider for a fresh sign-in no older than the API allows', async () => {
		await apis({ signInEveryMinutes: 1440 }, 'jwt', bucketId);
		const { uid, cookie } = await startForFiles();

		const start = await get(`/ui/${uid}/federation/acme-sso/start`, cookie);
		const authorize = new URL(start.location);

		expect(authorize.searchParams.get('prompt')).toBe('login');
		expect(authorize.searchParams.get('max_age')).toBe('86400');
	});

	it('tells a person signed in through a provider that the API asks for a code, with no set-up offered', async () => {
		await apis({ requireCode: true }, 'jwt', bucketId);
		const email = `linked-${Math.random().toString(36).slice(2)}@acme.test`;
		const sub = `upstream-${Math.random().toString(36).slice(2)}`;
		const store = getUserStore(bucketId);
		const account = await store.create(email, 'irrelevant-hash', true);
		await store.update(account._id, {
			federated: [{ providerId: 'acme-sso', sub, linkedAt: new Date() }],
			passwordSet: false
		});
		const { uid, cookie } = await startForFiles();

		const { complete } = await walk(uid, cookie, {
			idp,
			claims: { email, sub }
		});
		const location = present(complete?.location, 'where the sign-in went');
		const cookies = (complete?.setCookies ?? [])
			.filter((raw) => !/max-age=0/i.test(raw) && !raw.includes('1970'))
			.map((raw) => raw.split(';')[0])
			.join('; ');
		const page = await get(location, cookies);

		expect(location).toMatch(/\/ui\/[^/]+\/code-required$/);
		expect(propsOf(page.text).variant).toBe('providerAsk');
		expect(textOf(page.text)).toContain(
			'Files asks for a code from an authenticator app'
		);
		expect(page.text).not.toContain('/totp/enroll');
	});
});
