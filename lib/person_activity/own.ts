import { getPersonActivityStore } from '../adapters/index.js';
import type {
	ActivityBrowser,
	ActivitySystem,
	PersonActivityRow,
	UserBucket
} from '../adapters/types.js';
import { ACCOUNT_PAGE_CLIENT_PREFIX } from '../consts/account_page.js';
import { COUNTRY_CODES } from '../consts/countries.js';
import { PERSON_ACTIVITY_DAYS } from '../consts/person_activity.js';
import { ApplicationConfig } from '../configs/application.js';
import { Names, recordingBegan } from './read.js';
import { wordsOf } from './words.js';

/*
 * A person's own recent sign-ins, for their account page (specs/135 data-model §1). Built field by field from the
 * row, so the address, where it came from, the network categories and anything an administrator's rule or tool row
 * named never reach the view: what is not copied here cannot be shown (SI-1).
 */

export const OWN_SIGN_INS_SHOWN = 10;

/* A sign-in's time and the session's sign-in time are taken at the same resume; a little apart, never seconds. */
const SAME_SIGN_IN_MS = 5_000;
const DAY_MS = 86_400_000;
const KNOWN_COUNTRIES = new Set(COUNTRY_CODES);

export type OwnPlace =
	{ kind: 'app'; name: string } | { kind: 'accountPage' } | { kind: 'gone' };

export interface OwnSignIn {
	at: Date;
	place: OwnPlace;
	method: NonNullable<PersonActivityRow['method']>;
	/* For a sign-in through a provider: its name today, or null when the project no longer has it. */
	provider?: string | null;
	device?: { browser: ActivityBrowser; system: ActivitySystem };
	country?: string;
	thisBrowser: boolean;
}

export type OwnSignInsView =
	| { state: 'off' }
	| { state: 'empty'; since: Date }
	| { state: 'list'; rows: OwnSignIn[] };

async function placeOf(
	row: PersonActivityRow,
	bucket: UserBucket,
	names: Names
): Promise<OwnPlace> {
	const { clientId, appOrigin } = row.place;
	if (clientId === `${ACCOUNT_PAGE_CLIENT_PREFIX}${bucket._id}`) {
		return { kind: 'accountPage' };
	}
	const name = appOrigin
		? ((await names.appAt(appOrigin))?.name ?? null)
		: clientId
			? await names.client(clientId)
			: null;
	return name ? { kind: 'app', name } : { kind: 'gone' };
}

/* The one row the browser's own sign-in wrote, if it is written yet: the closest within a few seconds. */
function thisBrowserRow(
	rows: readonly PersonActivityRow[],
	loginTs: number | undefined
): PersonActivityRow | undefined {
	if (typeof loginTs !== 'number') return undefined;
	const at = loginTs * 1000;
	let best: PersonActivityRow | undefined;
	for (const row of rows) {
		const apart = Math.abs(row.firstAt.getTime() - at);
		if (apart > SAME_SIGN_IN_MS) continue;
		if (!best || apart < Math.abs(best.firstAt.getTime() - at)) best = row;
	}
	return best;
}

/*
 * An administrator's own recent sign-ins (specs/137 data-model §4), refused ones included, for the console header. In
 * the console's English words, built field by field like the person's: a thief signed in as the administrator must not
 * learn where the real one signs in from, so no address, category, owner or location is copied (SI-3).
 */
export interface OwnAdminSignIn {
	at: string;
	outcome: 'let_in' | 'refused';
	place: string;
	method: string | null;
	reason: string | null;
	device: string | null;
	country: string | null;
}

export type OwnAdminSignInsView =
	| { state: 'off' }
	| { state: 'empty'; since: string }
	| { state: 'list'; rows: OwnAdminSignIn[] };

export async function ownAdminSignIns(
	bucket: UserBucket,
	accountId: string,
	now: Date
): Promise<OwnAdminSignInsView> {
	if (!ApplicationConfig['personActivity.enabled']) return { state: 'off' };
	const page = await getPersonActivityStore().listForPerson(
		bucket._id,
		accountId,
		{ kind: 'signIn', limit: OWN_SIGN_INS_SHOWN, now }
	);
	if (page.rows.length === 0) {
		const began = (await recordingBegan(bucket._id)) ?? bucket.createdAt;
		return {
			state: 'empty',
			since: new Date(
				Math.max(began.getTime(), now.getTime() - PERSON_ACTIVITY_DAYS * DAY_MS)
			).toISOString()
		};
	}
	const names = new Names(bucket);
	return {
		state: 'list',
		rows: await Promise.all(
			page.rows.map(async (row): Promise<OwnAdminSignIn> => {
				const place = row.place.clientId
					? await names.client(row.place.clientId)
					: null;
				const provider = row.place.providerId
					? names.provider(row.place.providerId)
					: null;
				const words = wordsOf(row, { place, client: null, provider });
				const country = row.facts?.country;
				const refused = row.outcome !== 'let_in';
				return {
					at: row.lastAt.toISOString(),
					outcome: refused ? 'refused' : 'let_in',
					place: place ?? 'An application that no longer exists',
					method: refused ? null : words.method,
					reason: refused ? words.reason : null,
					device: words.device,
					country: country && KNOWN_COUNTRIES.has(country) ? country : null
				};
			})
		)
	};
}

export async function ownSignIns(
	bucket: UserBucket,
	accountId: string,
	loginTs: number | undefined,
	now: Date
): Promise<OwnSignInsView> {
	if (!ApplicationConfig['personActivity.enabled']) return { state: 'off' };
	const page = await getPersonActivityStore().listForPerson(
		bucket._id,
		accountId,
		{ kind: 'signIn', outcome: 'let_in', limit: OWN_SIGN_INS_SHOWN, now }
	);
	const rows = page.rows.filter((row) => row.reason === 'signed_in');
	if (rows.length === 0) {
		const began = (await recordingBegan(bucket._id)) ?? bucket.createdAt;
		return {
			state: 'empty',
			since: new Date(
				Math.max(
					began.getTime(),
					bucket.createdAt.getTime(),
					now.getTime() - PERSON_ACTIVITY_DAYS * DAY_MS
				)
			)
		};
	}
	const names = new Names(bucket);
	const mine = thisBrowserRow(rows, loginTs);
	return {
		state: 'list',
		rows: await Promise.all(
			rows.map(async (row): Promise<OwnSignIn> => {
				const country = row.facts?.country;
				return {
					at: row.firstAt,
					place: await placeOf(row, bucket, names),
					method: row.method ?? 'password',
					...(row.method === 'provider'
						? {
								provider: row.place.providerId
									? names.provider(row.place.providerId)
									: null
							}
						: {}),
					...(row.device
						? {
								device: {
									browser: row.device.browser,
									system: row.device.system
								}
							}
						: {}),
					...(country && KNOWN_COUNTRIES.has(country) ? { country } : {}),
					thisBrowser: row === mine
				};
			})
		)
	};
}
