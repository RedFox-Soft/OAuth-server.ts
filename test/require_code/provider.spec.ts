import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { idpStub } from '../federation/idp_stub.ts';
import {
	get,
	provider,
	seedBucket,
	startInteraction,
	walk
} from '../federation/harness.ts';
import { present } from '../shape.ts';
import { CODE_APP, propsOf, textOf } from './helpers.ts';

let bucketId = '';
let idp: Awaited<ReturnType<typeof idpStub>>;

/* A person linked to the provider, with or without a password of their own here. */
async function linkedPerson(withPassword: boolean): Promise<{
	email: string;
	sub: string;
}> {
	const email = `linked-${Math.random().toString(36).slice(2)}@acme.test`;
	const sub = `upstream-${Math.random().toString(36).slice(2)}`;
	const store = getUserStore(bucketId);
	const account = await store.create(email, 'irrelevant-hash', true);
	await store.update(account._id, {
		federated: [{ providerId: 'acme-sso', sub, linkedAt: new Date() }],
		...(withPassword ? {} : { passwordSet: false })
	});
	return { email, sub };
}

/* Signs in through the provider and follows the sign-in to the page it stops at, with the cookies it set. */
async function throughProvider(email: string, sub: string) {
	idp.expectDiscovery();
	const { uid, cookie } = await startInteraction(CODE_APP);
	const { complete } = await walk(uid, cookie, {
		idp,
		claims: { email, sub }
	});
	const location = present(complete?.location, 'where the sign-in went');
	// What the browser holds now: the session the sign-in wrote and the cookie of the interaction it opened.
	const cookies = (complete?.setCookies ?? [])
		.filter((raw) => !/max-age=0/i.test(raw) && !raw.includes('1970'))
		.map((raw) => raw.split(';')[0])
		.join('; ');
	return { location, page: await get(location, cookies) };
}

/**
 * @proves A person who signed in through a provider to an application that requires a code is never sent to set one
 * up, which would not help them — a provider sign-in is not asked for this server's code. They are told so, with the
 * provider named as on its button, and offered a password only when their account has one and password sign-in is open.
 */
describe('a provider sign-in to an application that requires a code', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'require_code' });
		idp = await idpStub('https://idp-require-code.test');
		bucketId = await seedBucket(CODE_APP, {
			federation: [provider(idp.origin)],
			passwordLogin: true
		});
	});

	it('names the provider and offers no setting up when the account has no password', async () => {
		const { email, sub } = await linkedPerson(false);

		const { location, page } = await throughProvider(email, sub);

		expect(location).toMatch(/\/ui\/[^/]+\/code-required$/);
		const props = propsOf(page.text);
		expect(props.variant).toBe('providerAsk');
		expect(props.provider).toBe('Acme SSO');
		expect(page.text).not.toContain('/totp/enroll');
		expect(textOf(page.text)).toContain('Acme SSO');
	});

	it('offers a password instead when the account has one', async () => {
		const { email, sub } = await linkedPerson(true);

		const { location, page } = await throughProvider(email, sub);

		expect(propsOf(page.text).variant).toBe('provider');
		const uid = present(/\/ui\/([^/]+)\//.exec(location)?.[1], 'the uid');
		expect(page.text).toContain(`/ui/${uid}/login`);
		expect(page.text).not.toContain('/totp/enroll');
	});
});
