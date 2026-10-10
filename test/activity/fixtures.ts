import { agent } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { refreshTokenOf } from '../acr/response.ts';
import { Browser, signIn, uidOf, PASSWORD, codeOf } from '../amr/flow.ts';
import { setClockForTests } from 'lib/activity/clock.ts';
import { getActivityStore, resetActivityStore } from 'lib/adapters/index.ts';
import { resetActivityCacheForTests, whenRecorded } from 'lib/activity/note.ts';
import { readPeriod, type PeriodFigure } from 'lib/activity/read.ts';
import { monthOf, dayOf } from 'lib/activity/periods.ts';
import { present } from 'test/shape.ts';

export { Browser, signIn, uidOf, PASSWORD, codeOf };
export { seedBucket, seedUser, codeFor } from '../amr/flow.ts';

/* A full code flow for `email` through `clientId`, from `browser`'s session; answers the token response. */
export async function signInAndRedeem(
	clientId: string,
	email: string,
	{
		browser = new Browser(),
		offline = false,
		second = false
	}: { browser?: Browser; offline?: boolean; second?: boolean } = {}
) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: offline ? 'openid offline_access' : 'openid',
		...(offline ? { prompt: 'consent' } : {})
	});
	const code = await signIn(browser, auth, email, { second });
	return auth.getToken(code);
}

export function refresh(clientId: string, refreshToken: string) {
	return agent.token.post({
		client_id: clientId,
		grant_type: 'refresh_token',
		refresh_token: refreshToken
	});
}

export { refreshTokenOf };

/* `prompt=none` on the session `browser` already holds, then the code exchange. No sign-in happens. */
export async function silentReauth(browser: Browser, clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		prompt: 'none'
	});
	const res = await browser.authorize(auth);
	return auth.getToken(codeOf(res.headers.get('location')));
}

/*
 * A fresh activity store that has been counting since the epoch, so a suite reads only its own activity and
 * no period it uses is "before counting began" — that rule has its own cases.
 */
export async function startCounting(since = new Date(0)): Promise<void> {
	resetActivityStore();
	resetActivityCacheForTests();
	await getActivityStore().countingSince(since);
}

/* Sets the activity clock to `iso` until the returned function is called. */
export function atDay(iso: string): () => void {
	const at = new Date(iso);
	return setClockForTests(() => at);
}

export const thisMonth = () => monthOf(new Date());
export const today = () => dayOf(new Date());

/*
 * What a period of a bucket reads as. Read through the store rather than the admin route on purpose: the
 * route is the reading story's deliverable, and the trigger of every counting case is an end user's
 * action, never a function call — this is only where its outcome is observed.
 *
 * Recording is fire-and-forget, so a read right after a token response may run ahead of the write it is
 * meant to observe; it waits for the writes already started first.
 */
export async function figureOf(
	bucketId: string,
	period: string,
	at?: Date
): Promise<PeriodFigure> {
	await settled();
	return present(
		await readPeriod(bucketId, period, at),
		`a figure for ${period}`
	);
}

export async function settled(): Promise<void> {
	await whenRecorded();
}
