/*
 * The consent page in Russian: whole sentences around the application's name, Russian plural forms and a
 * Russian date — the parts of a page that a word-for-word string swap gets wrong.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { visible } from '../page_text.js';
import { elysia } from 'lib/index.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { DeviceCode } from 'lib/models/device_code.js';
import epochTime from 'lib/helpers/epoch_time.ts';
import { text as fill } from 'lib/i18n/message.tsx';
import { CONSENT_TEXTS } from 'lib/i18n/texts/consent/index.ts';

const PASSWORD = 'correct horse battery';
const form = { 'content-type': 'application/x-www-form-urlencoded' };
const RU = CONSENT_TEXTS.ru;

/* A Russian-speaking browser: it keeps its cookies and always asks for Russian. */
class Browser {
	#jar = new Map<string, string>();

	async request(path: string, init: RequestInit = {}) {
		const headers = new Headers(init.headers);
		headers.set('accept-language', 'ru-RU,ru;q=0.9');
		if (this.cookie) headers.set('cookie', this.cookie);
		const response = await elysia.handle(
			new Request(`http://e.ly${path}`, { ...init, headers })
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

/* Starts a device sign-in, approves the code and signs in; answers the consent page's path and the code. */
async function deviceConsent() {
	const authorized = await elysia.handle(
		new Request('http://e.ly/device/auth', {
			method: 'POST',
			headers: form,
			body: new URLSearchParams({ client_id: 'tv', scope: 'openid' })
		})
	);
	const { device_code, user_code } = (await authorized.json()) as {
		device_code: string;
		user_code: string;
	};
	const browser = new Browser();
	const entry = await browser.request('/device');
	const xsrf = /name="xsrf" value="([0-9a-f]+)"/.exec(await entry.text())?.[1];
	const confirmed = await browser.post('/device', {
		xsrf: xsrf ?? '',
		user_code,
		confirm: 'yes'
	});
	const login = confirmed.headers.get('location') ?? '';
	const email = `ru-${Math.random()}@x.io`;
	await getUserStore().create(email, await Bun.password.hash(PASSWORD), true);
	const signedIn = await browser.post(
		`${login.replace(/\/login$/, '')}/login`,
		{
			username: email,
			password: PASSWORD
		}
	);
	return {
		browser,
		consentAt: signedIn.headers.get('location') ?? '',
		deviceCode: device_code
	};
}

async function requestedMinutesAgo(deviceCode: string, minutes: number) {
	const code = await DeviceCode.find(deviceCode);
	code.payload.iat = epochTime() - minutes * 60 - 5;
	await code.save();
}

/**
 * @proves A Russian-speaking end user reads the consent page as Russian: the application's name sits inside
 * whole Russian sentences, counts take the Russian form for their number, and an application's name cannot
 * change the sentence it is placed in.
 */
describe('the consent page in Russian', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('names the device application inside the Russian heading and repeats the warning in Russian', async () => {
		const { browser, consentAt } = await deviceConsent();

		const html = await (await browser.request(consentAt)).text();

		expect(html).toContain('<html lang="ru">');
		expect(visible(html)).toContain(RU.headline.device);
		expect(visible(html)).toContain(RU.warning.deviceSent);
	});

	for (const [minutes, ago] of [
		[1, '1 минуту назад'],
		[3, '3 минуты назад'],
		[5, '5 минут назад'],
		[21, '21 минуту назад']
	] as const) {
		it(`says the code was requested “${ago}” when it was requested ${minutes} minutes ago`, async () => {
			const { browser, consentAt, deviceCode } = await deviceConsent();
			await requestedMinutesAgo(deviceCode, minutes);

			const html = await (await browser.request(consentAt)).text();

			expect(visible(html)).toContain(
				fill(RU.warning.deviceRequested, { ago })
			);
		});
	}
});
