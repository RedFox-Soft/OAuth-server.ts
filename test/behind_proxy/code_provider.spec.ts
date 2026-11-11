import { beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import {
	getBucketGroupStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { idpStub } from '../federation/idp_stub.ts';
import { get, provider, walk } from '../federation/harness.ts';
import { admin } from '../provisioning/helpers.ts';
import { Browser } from '../connected_apps/helpers.ts';
import { propsOf, textOf, uidIn } from '../require_code/helpers.ts';
import { present, shaped } from '../shape.ts';
import {
	AppJar,
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	world,
	type AppView,
	type World
} from './helpers.ts';

const Preview = Type.Object({
	expect: Type.Object({
		withoutAuthenticator: Type.Number(),
		providerOnly: Type.Number()
	})
});

let w: World;
let app: AppView;
let idp: Awaited<ReturnType<typeof idpStub>>;

/* A person of Staff linked to the project's provider, with or without a password of their own here. */
async function linkedPerson(withPassword: boolean) {
	const email = `linked-${nanoid().slice(0, 8)}@acme.test`;
	const sub = `upstream-${nanoid().slice(0, 8)}`;
	const store = getUserStore(w.acme.id);
	const account = await store.create(email, 'irrelevant-hash', true);
	await store.update(account._id, {
		federated: [{ providerId: 'acme-sso', sub, linkedAt: new Date() }],
		...(withPassword ? {} : { passwordSet: false })
	});
	await getBucketGroupStore().change(w.acme.staff, {
		add: [account._id],
		remove: []
	});
	return { email, sub };
}

/* Opens /admin and signs in through the provider; answers the page the sign-in stopped at. */
async function throughProvider(email: string, sub: string) {
	const jar = new AppJar();
	const browser = new Browser();
	const sent = jar.absorb(
		await checkApp({ slug: w.acme.slug, app }, { uri: '/admin' })
	);
	const login = await browser.open(
		present(sent.headers.get('location'), 'a sign-in')
	);
	idp.expectDiscovery();
	const { complete } = await walk(uidIn(login.url), browser.cookie, {
		idp,
		claims: { email, sub }
	});
	const location = present(complete?.location, 'where the sign-in went');
	const cookies = (complete?.setCookies ?? [])
		.filter((raw) => !/max-age=0/i.test(raw) && !raw.includes('1970'))
		.map((raw) => raw.split(';')[0])
		.join('; ');
	return { location, page: await get(location, cookies) };
}

/**
 * @proves A person who signs in through a provider to a path behind the proxy that asks for a code is never sent to set
 * one up: they are told this way of signing in cannot open it, with the app named by its host, and offered a password
 * only when their account has one.
 */
describe('a provider sign-in to a path behind the proxy that asks for a code', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'code_provider' });
		w = await world();
		idp = await idpStub('https://idp-proxy-code.test');
		await getBucketStore().update(w.acme.id, {
			federation: [provider(idp.origin)]
		});
		forgetBucketAddresses();
		app = await createApp(w.cookie, w.acme.id, { rootGroups: [w.acme.staff] });
		const rules = [
			{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
			{
				path: '/admin',
				who: { kind: 'groups', groups: [w.acme.staff] },
				conditions: [{ kind: 'fresh', maxAgeMinutes: 15, withCode: true }]
			}
		];
		const path = behindProxyPath(w.acme.id, app.id);
		const asked = await admin('PATCH', path, w.cookie, { rules });
		const applied = await admin('PATCH', path, w.cookie, {
			rules,
			confirm: true,
			expect: shaped(Preview, asked.body).expect
		});
		expectStatus(applied, 200, 'asking for a code on /admin');
	});

	it('names the provider and the host, and offers no setting up, when the account has no password', async () => {
		const { email, sub } = await linkedPerson(false);

		const { location, page } = await throughProvider(email, sub);

		expect(location).toMatch(/\/ui\/[^/]+\/code-required$/);
		const props = propsOf(page.text);
		expect(props.variant).toBe('providerAsk');
		expect(props.provider).toBe('Acme SSO');
		expect(page.text).not.toContain('/totp/enroll');
		expect(textOf(page.text)).toContain(
			`${new URL(app.address).host} asks for a code from an authenticator app`
		);
	});

	it('offers a password instead when the account has one', async () => {
		const { email, sub } = await linkedPerson(true);

		const { page } = await throughProvider(email, sub);

		expect(propsOf(page.text).variant).toBe('provider');
		expect(textOf(page.text)).toContain('Sign in with a password instead');
	});
});
