import {
	getBucketStore,
	getPersonActivityStore,
	getUserStore
} from '../adapters/index.js';
import type { PersonActivityRow, User, UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { shownNameOf } from '../configs/issuer.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import type { Language } from '../i18n/languages.js';
import { text } from '../i18n/message.js';
import { emailLanguage } from '../i18n/resolve.js';
import { ACCOUNT_TEXTS } from '../i18n/texts/account/index.js';
import { deliver, mailDeliveryConfigured } from '../mail/mailer.js';
import { newSignInEmail } from '../mail/templates/new_sign_in.js';
import { Names } from '../person_activity/read.js';
import {
	BROWSER_NAMES,
	SYSTEM_NAMES,
	countryWords
} from '../person_activity/sign_in_words.js';
import { claim } from './claim.js';
import {
	browserKey,
	isSignedIn,
	judge,
	networkKey,
	type Newness
} from './judge.js';
import { issueNotMeLink } from './link.js';
import { alertsOn } from './setting.js';

/*
 * Emails about a sign-in from a new network or browser (specs/138 research R1). Decided in the activity flush, after
 * the network owner is looked up and before the rows are written, so the decision rides on the row it describes and no
 * request ever waits on it; sent once the write has succeeded, so no email describes a sign-in the log does not hold.
 */

export interface Alert {
	row: PersonActivityRow;
	user: User;
	bucket: UserBucket;
	why: Newness;
}

/* Successful sign-ins of the last 90 days: at most a few hundred for one account, the bound "New address" reads. */
const HISTORY_LIMIT = 500;

function eligible(user: User | undefined): user is User & { email: string } {
	return user !== undefined && canSignIn(user) && user.verified && !!user.email;
}

async function forProject(
	bucketId: string,
	rows: readonly PersonActivityRow[],
	now: Date
): Promise<Alert[]> {
	const bucket = await getBucketStore().find(bucketId);
	if (!bucket || !alertsOn(bucket)) return [];
	const accountIds = [...new Set(rows.map((row) => row.accountId))];
	const users = new Map(
		(await getUserStore(bucketId).findMany(accountIds)).map((user) => [
			user._id,
			user
		])
	);
	const alerts: Alert[] = [];
	for (const accountId of accountIds) {
		const user = users.get(accountId);
		if (!eligible(user)) continue;
		const mine = rows.filter((row) => row.accountId === accountId);
		const { rows: kept } = await getPersonActivityStore().listForPerson(
			bucketId,
			accountId,
			{ kind: 'signIn', outcome: 'let_in', limit: HISTORY_LIMIT, now }
		);
		/* This flush's earlier sign-ins count too: two from one new place in a minute are one email. */
		const history = [...kept, ...mine];
		for (const row of mine) {
			const why = judge(row, history);
			if (why === null) continue;
			if (
				!(await claim(
					bucketId,
					accountId,
					row.day,
					networkKey(row),
					browserKey(row)
				))
			) {
				continue;
			}
			row.alerted = why;
			alerts.push({ row, user, bucket, why });
		}
	}
	return alerts;
}

/*
 * Which of these rows' owners to email, marking each such row. Never throws: a failure here must not cost the rows
 * their write, so it logs the count of projects only and emails nobody.
 */
export async function alertsFor(
	rows: readonly PersonActivityRow[],
	now: Date = new Date()
): Promise<Alert[]> {
	try {
		const signedIn = rows
			.filter(isSignedIn)
			.sort((a, b) => a.firstAt.getTime() - b.firstAt.getTime());
		if (signedIn.length === 0) return [];
		if (!(await mailDeliveryConfigured())) return [];
		const byProject = new Map<string, PersonActivityRow[]>();
		for (const row of signedIn) {
			const list = byProject.get(row.bucketId) ?? [];
			list.push(row);
			byProject.set(row.bucketId, list);
		}
		const alerts: Alert[] = [];
		for (const [bucketId, list] of byProject) {
			alerts.push(...(await forProject(bucketId, list, now)));
		}
		return alerts;
	} catch (error) {
		console.error('new sign-in emails not decided', { error });
		return [];
	}
}

function methodWords(
	row: PersonActivityRow,
	names: Names,
	language: Language
): string {
	const T = ACCOUNT_TEXTS[language];
	switch (row.method) {
		case 'password_code':
			return T.methodPasswordCode;
		case 'provider': {
			const provider = row.place.providerId
				? names.provider(row.place.providerId)
				: null;
			return provider
				? text(T.methodProvider, { provider })
				: T.methodProviderGone;
		}
		default:
			return T.methodPassword;
	}
}

function browserWords(
	row: PersonActivityRow,
	language: Language
): string | null {
	if (!row.device) return null;
	const T = ACCOUNT_TEXTS[language];
	const browser = BROWSER_NAMES[row.device.browser] ?? T.otherBrowser;
	const system = SYSTEM_NAMES[row.device.system];
	return system === null ? browser : text(T.browserOn, { browser, system });
}

function placeWords(row: PersonActivityRow, language: Language): string | null {
	const country = row.facts?.country
		? countryWords(row.facts.country, language)
		: null;
	const parts = [row.lookup?.city, row.lookup?.region, country].filter(
		(part): part is string => typeof part === 'string' && part !== ''
	);
	return parts.length > 0 ? parts.join(', ') : null;
}

export async function appName(
	row: PersonActivityRow,
	names: Names
): Promise<string | null> {
	if (row.place.appOrigin) {
		return (await names.appAt(row.place.appOrigin))?.name ?? null;
	}
	return row.place.clientId ? names.client(row.place.clientId) : null;
}

/* The words of a sign-in, the same in the owner's email and in the super administrators' notice. */
export async function signInWords(
	row: PersonActivityRow,
	bucket: UserBucket,
	language: Language
): Promise<{
	app: string;
	method: string;
	browser: string | null;
	place: string | null;
	network: string | null;
}> {
	const names = new Names(bucket);
	return {
		app: (await appName(row, names)) ?? ACCOUNT_TEXTS[language].deletedApp,
		method: methodWords(row, names, language),
		browser: browserWords(row, language),
		place: placeWords(row, language),
		network: row.lookup?.asName ?? null
	};
}

/*
 * Sends the emails decided for rows that were written. Each failure is logged by project only and never retried: a
 * retried email about a sign-in is worse than a missing one, and the row's mark stays as the decision that was made.
 */
export async function sendAlerts(alerts: readonly Alert[]): Promise<void> {
	for (const { row, user, bucket, why } of alerts) {
		try {
			const language = emailLanguage(user);
			const url = await issueNotMeLink(bucket, user._id, row._id);
			const words = await signInWords(row, bucket, language);
			await deliver({
				to: user.email,
				...newSignInEmail(
					{
						service:
							bucket._id === ADMIN_BUCKET_ID ? null : shownNameOf(bucket),
						email: user.email,
						at: row.firstAt,
						...words,
						why
					},
					url,
					language
				)
			});
		} catch (error) {
			console.error('new sign-in email not sent', {
				bucketId: bucket._id,
				error
			});
		}
	}
}
