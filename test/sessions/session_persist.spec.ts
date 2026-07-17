import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap from '../test_helper.js';
import sessionHandler from 'lib/shared/session.ts';
import { Session } from 'lib/models/session.ts';
import { cookieNames } from 'lib/consts/param_list.ts';

// Minimal cookie jar matching the shape session.ts reads/writes: a per-name
// entry exposing `.value` and `.set({ value })`.
function makeCookieJar(sessionValue?: string) {
	const entry = {
		value: sessionValue as string | undefined,
		set(o: { value: string }) {
			this.value = o.value;
		},
		remove() {
			this.value = undefined;
		}
	};
	return { [cookieNames.session]: entry } as Record<string, typeof entry>;
}

describe('session persistence (setCookies)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('persists a freshly authenticated session (no prior cookie) and issues the cookie', async () => {
		// Regression: setCookies() used to save only when a `_session` cookie
		// already existed, so a first-time login was never persisted and its
		// session-bound authorization code failed at the token endpoint
		// (Session.findByUid returned nothing).
		const oidc = { cookie: makeCookieJar() } as unknown as {
			cookie: ReturnType<typeof makeCookieJar>;
			session: Session;
		};
		const setCookies = await sessionHandler(oidc);
		oidc.session.loginAccount({ accountId: 'acc-persist-1' });

		await setCookies();

		expect(oidc.cookie[cookieNames.session].value).toBe(oidc.session.id);
		const found = await Session.findByUid(oidc.session.payload.uid);
		expect(found?.payload.accountId).toBe('acc-persist-1');
	});

	it('does not persist an anonymous session with no prior cookie', async () => {
		const oidc = { cookie: makeCookieJar() } as unknown as {
			cookie: ReturnType<typeof makeCookieJar>;
			session: Session;
		};
		const setCookies = await sessionHandler(oidc);
		const uid = oidc.session.payload.uid;

		await setCookies();

		expect(oidc.cookie[cookieNames.session].value).toBeUndefined();
		expect(await Session.findByUid(uid)).toBeUndefined();
	});
});
