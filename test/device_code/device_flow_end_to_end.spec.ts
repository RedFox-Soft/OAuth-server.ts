import { describe, it, expect, beforeAll, afterEach } from 'bun:test';
import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import {
	errorStore,
	getProjectStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { addons } from 'lib/addon/registry.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.js';
import { AUDIENCE, MFA } from './device_flow_end_to_end.config.js';

const PASSWORD = 'correct horse battery';
const form = { 'content-type': 'application/x-www-form-urlencoded' };

/* A browser: it keeps the cookies it is given and sends them all back. */
class Browser {
	#jar = new Map<string, string>();

	async request(path: string, init: RequestInit = {}) {
		const response = await elysia.handle(
			new Request(`http://e.ly${path}`, {
				redirect: 'manual',
				...init,
				headers: { ...(init.headers ?? {}), cookie: this.cookie }
			})
		);
		for (const set of response.headers.getSetCookie()) {
			const [pair] = set.split(';');
			const at = pair.indexOf('=');
			this.#jar.set(pair.slice(0, at), pair.slice(at + 1));
		}
		return response;
	}

	post(path: string, fields: Record<string, string>) {
		return this.request(path, {
			method: 'POST',
			headers: form,
			body: new URLSearchParams(fields)
		});
	}

	get cookie() {
		return [...this.#jar].map(([k, v]) => `${k}=${v}`).join('; ');
	}
}

async function deviceAuthorization(fields: Record<string, string> = {}) {
	const response = await elysia.handle(
		new Request('http://e.ly/device/auth', {
			method: 'POST',
			headers: form,
			body: new URLSearchParams({ client_id: 'tv', scope: 'openid', ...fields })
		})
	);
	return (await response.json()) as { device_code: string; user_code: string };
}

/* Enter the code on the verification page and confirm it; answers the interaction's uid. */
async function enterCode(browser: Browser, userCode: string) {
	const page = await browser.request('/device');
	const xsrf = /name="xsrf" value="([0-9a-f]+)"/.exec(await page.text())?.[1];
	const confirmed = await browser.post('/device', {
		xsrf: xsrf ?? '',
		user_code: userCode,
		confirm: 'yes'
	});
	return confirmed.headers.get('location');
}

function uidOf(location: string | null) {
	const uid = location?.split('/')[2];
	if (!uid) throw new Error(`expected an interaction, got ${location}`);
	return uid;
}

async function signIn(
	browser: Browser,
	location: string | null,
	email: string
) {
	return browser.post(`/ui/${uidOf(location)}/login`, {
		username: email,
		password: PASSWORD
	});
}

async function poll(deviceCode: string) {
	const response = await elysia.handle(
		new Request('http://e.ly/token', {
			method: 'POST',
			headers: form,
			body: new URLSearchParams({
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code: deviceCode,
				client_id: 'tv'
			})
		})
	);
	return (await response.json()) as Record<string, unknown>;
}

async function newUser() {
	const email = `tv-${Math.random()}@x.io`;
	await getUserStore().create(
		email,
		await Bun.password.hash(PASSWORD),
		[],
		true
	);
	return email;
}

/* Sign in from a fresh browser and arrive at consent; answers the browser and the consent uid. */
async function atConsent(fields: Record<string, string> = {}) {
	const browser = new Browser();
	const { device_code, user_code } = await deviceAuthorization(fields);
	const signedIn = await signIn(
		browser,
		await enterCode(browser, user_code),
		await newUser()
	);
	return { browser, device_code, consentAt: signedIn.headers.get('location') };
}

/**
 * @proves A person with no session can approve a device, and whatever ends the request on the
 * verification step reaches the polling device on its next poll — while a request that cannot prove
 * it belongs to that sign-in changes nothing.
 */
describe('a device sign-in from a browser with no session', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'device_flow_end_to_end' });
	});

	afterEach(() => {
		resetQueue();
	});

	it('signs the device in when the person enters the code, signs in and approves', async () => {
		const { browser, device_code, consentAt } = await atConsent();

		const approved = await browser.post(`/ui/${uidOf(consentAt)}/consent`, {
			action: 'allow'
		});

		expect(approved.status).toBe(200);
		expect(await poll(device_code)).toHaveProperty('access_token');
	});

	it('tells the device access_denied when the person declines', async () => {
		const { browser, device_code, consentAt } = await atConsent();

		await browser.post(`/ui/${uidOf(consentAt)}/consent`, { action: 'cancel' });

		expect((await poll(device_code)).error).toBe('access_denied');
	});

	it('tells the device unmet_authentication_requirements when the sign-in cannot meet a required context', async () => {
		const browser = new Browser();
		const { device_code, user_code } = await deviceAuthorization({
			claims: JSON.stringify({
				id_token: { acr: { essential: true, value: MFA } }
			})
		});

		const signedIn = await signIn(
			browser,
			await enterCode(browser, user_code),
			await newUser()
		);

		expect(signedIn.headers.get('location')).toBeNull();
		expect((await poll(device_code)).error).toBe(
			'unmet_authentication_requirements'
		);
	});

	it('tells the device invalid_target when the requested resource is withdrawn before approval', async () => {
		const project = await getProjectStore().create({
			name: 'TV',
			slug: `tv-${Math.random()}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: AUDIENCE,
			projectId: project._id,
			name: 'TV API',
			scopes: []
		});
		const { browser, device_code, consentAt } = await atConsent({
			resource: AUDIENCE
		});
		await getProtectedResourceStore().destroy(ROOT_NAMESPACE, AUDIENCE);

		await browser.post(`/ui/${uidOf(consentAt)}/consent`, { action: 'allow' });

		expect((await poll(device_code)).error).toBe('invalid_target');
	});

	it('tells the device server_error and records the fault once when the server faults while completing', async () => {
		const { browser, device_code, consentAt } = await atConsent();
		addons.override({
			loadExistingGrant: () => {
				throw new Error('fault while completing a device sign-in');
			}
		});

		await browser.post(`/ui/${uidOf(consentAt)}/consent`, { action: 'allow' });
		const answer = await poll(device_code);
		await flushForTest();
		const groups = (await errorStore.list({ route: '/ui/:uid/consent' }))
			.groups;

		expect(answer.error).toBe('server_error');
		expect(groups).toHaveLength(1);
		expect(groups[0].occurrences).toBe(1);
	});

	it('leaves the device pending when the completion is reached from another session', async () => {
		const { browser, device_code, consentAt } = await atConsent();
		const stranger = new Browser();
		await stranger.request('/device');
		const interaction = browser.cookie
			.split('; ')
			.find((c) => c.startsWith('_interaction='));

		await elysia.handle(
			new Request(`http://e.ly/ui/${uidOf(consentAt)}/device_resume`, {
				headers: { cookie: [interaction, stranger.cookie].join('; ') }
			})
		);

		expect((await poll(device_code)).error).toBe('authorization_pending');
	});

	it('keeps the first outcome when a code that already has one is completed', async () => {
		const { browser, device_code, consentAt } = await atConsent();
		const code = await DeviceCode.find(device_code, {
			ignoreExpiration: true
		});
		Object.assign(code.payload, {
			error: 'access_denied',
			errorDescription: 'aborted elsewhere'
		});
		await code.save();

		await browser.post(`/ui/${uidOf(consentAt)}/consent`, { action: 'allow' });

		expect(await poll(device_code)).toMatchObject({
			error: 'access_denied',
			error_description: 'aborted elsewhere'
		});
	});
});
