import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig, configuration } from 'lib/configs/application.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { setSystemTime } from 'bun:test';
import { present } from '../shape.ts';
import { typePassword } from '../require_code/helpers.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { activityOf } from '../person_activity/helpers.ts';
import {
	apis,
	Browser,
	connect,
	FILES,
	mailOn,
	payloadOf,
	person,
	project,
	SECRET,
	setUpAndContinue,
	signIn,
	textOf,
	tokensFrom,
	typeCode,
	uidIn
} from './helpers.ts';

async function withFactor(): Promise<{ email: string; accountId: string }> {
	const found = await person();
	await getUserStore(DEFAULT_BUCKET_ID).update(found.accountId, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
	});
	return found;
}

/**
 * @proves A sign-in for a token for an API that requires a code asks for the code, whatever the client asked for,
 * and says why by the API's declared name, never the client's; a person without one is offered to set one up inside
 * the same sign-in with spec 127's proofs; a person signed in through a provider is told the truth; and an API that
 * asks for a sign-in every so often asks for a new one once the session is older, even when the client did not.
 */
describe('a sign-in for an API that requires a code or a recent sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project({ totpSelfService: true });
	});

	afterEach(() => {
		setSystemTime();
	});

	it('asks a person with an authenticator for the code, and the token for the API says so', async () => {
		await apis({ requireCode: true });
		const { email } = await withFactor();
		const browser = new Browser();

		const opened = await connect(browser);
		const login = await browser.request(opened.url);
		const html = await login.text();
		const landed = await typePassword(browser, opened.url, email);
		const finished = await typeCode(browser, landed.url);
		const tokens = await tokensFrom(opened.auth, finished.url);

		expect(textOf(html)).toContain(
			'Files asks for a code from an authenticator app to connect.'
		);
		expect(payloadOf(tokens.access_token)).toMatchObject({
			aud: FILES,
			acr: configuration.acrMap.multi_factor
		});
	});

	it('asks again for the password and code when the session was signed in with a password only', async () => {
		await apis();
		const { email, accountId } = await person();
		const browser = new Browser();
		const first = await signIn(browser, email, false);
		await tokensFrom(first.auth, first.url);
		await apis({ requireCode: true });
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
		});

		const again = await connect(browser);

		expect(again.url).toMatch(/\/ui\/[^/]+\/login$/);
	});

	it('offers a person without an authenticator to set one up in the same sign-in, naming the API', async () => {
		await apis({ requireCode: true });
		const { email } = await person();
		const browser = new Browser();

		const reached = await signIn(browser, email, false);
		const page = textOf(await reached.response.text());
		const continued = await setUpAndContinue(browser, reached.url, email);
		const tokens = await tokensFrom(reached.auth, continued.url);

		expect(reached.url).toMatch(/\/ui\/[^/]+\/code-required$/);
		expect(page).toContain('Files asks for two-step sign-in');
		expect(page).toContain('Return to the app without signing in');
		expect(payloadOf(tokens.access_token)).toMatchObject({
			acr: configuration.acrMap.multi_factor
		});
	});

	it('keeps in the person’s activity that the API asked for the code, by the API’s name', async () => {
		await apis({ requireCode: true });
		const { email, accountId } = await person();

		await signIn(new Browser(), email, false);
		const { rows } = await activityOf(
			await adminCookie(),
			DEFAULT_BUCKET_ID,
			accountId
		);
		const stopped = rows.find((row) => row.outcome === 'refused');

		expect(stopped?.words.reason).toEndWith(
			'without a code; Files asks for one'
		);
		expect(stopped?.words.sawText).toBe('Files asks for two-step sign-in');
	});

	it('sends a person who goes back without a code back to the app with the standard error', async () => {
		await apis({ requireCode: true });
		const { email } = await person();
		const browser = new Browser();
		const reached = await signIn(browser, email, false);

		const back = await browser.post(`/ui/${uidIn(reached.url)}/code-required`, {
			action: 'return'
		});
		const location = present(back.headers.get('location'), 'a redirect');
		const delivered = await browser.open(
			new URL(location, reached.url).toString()
		);

		const url = new URL(delivered.url);
		expect(url.searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
		expect(url.searchParams.get('error_description')).toBe(
			'the API requires two-step sign-in'
		);
	});

	it('holds with the IPSIE SL1 profile on, which neither weakens it nor is weakened by it', async () => {
		const before = ApplicationConfig['ipsieSl1.enabled'];
		ApplicationConfig['ipsieSl1.enabled'] = true;
		try {
			await apis({ requireCode: true });
			const holder = await withFactor();
			const lacking = await person();

			/* Asked for the code at its step, then handed back to the app (SL1 then wants DPoP at the token endpoint). */
			const withCode = await signIn(new Browser(), holder.email, true);
			const refused = await signIn(new Browser(), lacking.email, false);

			expect(new URL(withCode.url).searchParams.get('code')).toBeString();
			expect(refused.url).toMatch(/\/ui\/[^/]+\/code-required$/);
		} finally {
			ApplicationConfig['ipsieSl1.enabled'] = before;
		}
	});

	it('changes nothing for an API without a requirement when the client asks for a code on its own', async () => {
		await apis();
		const { email } = await person();
		const browser = new Browser();

		const reached = await signIn(browser, email, false, {
			acr_values: configuration.acrMap.multi_factor
		});
		const tokens = await tokensFrom(reached.auth, reached.url);

		expect(payloadOf(tokens.access_token).acr).toBe(
			configuration.acrMap.password
		);
	});

	it('asks for a new sign-in once the session is older than the API allows, saying how often', async () => {
		await apis({ signInEveryMinutes: 1440 });
		const { email } = await person();
		const browser = new Browser();
		const first = await signIn(browser, email, false);
		await tokensFrom(first.auth, first.url);
		setSystemTime(Date.now() + 2 * 86_400_000);

		const again = await connect(browser);
		const html = textOf(await (await browser.request(again.url)).text());

		expect(again.url).toMatch(/\/ui\/[^/]+\/login$/);
		expect(html).toContain(
			'Files asks you to sign in again every day to stay connected.'
		);
	});

	it('does not ask again while the session is within the interval', async () => {
		await apis({ signInEveryMinutes: 1440 });
		const { email } = await person();
		const browser = new Browser();
		const first = await signIn(browser, email, false);
		await tokensFrom(first.auth, first.url);
		setSystemTime(Date.now() + 3_600_000);

		const again = await connect(browser);

		expect(again.url).toContain('https://agent.acme.test/cb');
	});

	it('the reason line reads in the person’s language', async () => {
		await apis({ signInEveryMinutes: 10080 });
		const browser = new Browser();

		const opened = await connect(browser, { ui_locales: 'ru' });
		const html = textOf(await (await browser.request(opened.url)).text());

		expect(html).toContain(
			'Files просит входить заново раз в 7 дней, чтобы подключение продолжало работать.'
		);
	});
});
