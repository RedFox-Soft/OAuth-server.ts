import {
	getActivityStore,
	getBehindProxyAppStore,
	getPersonActivityStore,
	getProtectedResourceStore,
	getSchemaMigrationStore
} from '../adapters/index.js';
import type {
	BehindProxyApp,
	PersonActivityCursor,
	PersonActivityRow,
	ProtectedResource,
	UserBucket
} from '../adapters/types.js';
import { dayOf, monthOf } from '../activity/periods.js';
import {
	NEW_ADDRESS_AFTER,
	PERSON_ACTIVITY_DAYS
} from '../consts/person_activity.js';
import { PERSON_ACTIVITY_FENCE_ID } from '../consts/migrations.js';
import { knownProviderByIssuer } from '../consts/known_providers.js';
import { ApplicationConfig } from '../configs/application.js';
import { Client } from '../models/client.js';
import { namespaceOf } from '../resources/namespace.js';
import { wordsOf, type RowWords } from './words.js';

/*
 * Reading a person's activity (specs/133 contracts/admin-api.md). Names are looked up as they are today, for the
 * console to show; the reason phrases come from the fixed table and name only what was recorded (research R18).
 */

let began: Date | null = null;

/*
 * When recording began: the time the fence migration was recorded (research R14), on a fresh install the
 * provisioning. Kept once found, because it never changes; read again while absent, because `db:migrate` may record
 * it while the server runs.
 */
export async function recordingBegan(): Promise<Date | null> {
	if (began) return began;
	const records = await getSchemaMigrationStore().all();
	const fence = records.find(
		(record) => record.id === PERSON_ACTIVITY_FENCE_ID
	);
	if (fence) began = fence.appliedAt;
	return began;
}

export function forgetRecordingBeganForTests(): void {
	began = null;
}

export interface ActivityRowView {
	id: string;
	day: string;
	kind: PersonActivityRow['kind'];
	outcome: PersonActivityRow['outcome'];
	reason: PersonActivityRow['reason'];
	words: RowWords;
	place: PersonActivityRow['place'] & { name: string | null };
	client: string | null;
	address: string | null;
	addressFrom: 'sign_in' | 'proxy' | null;
	facts: { country: string | null; categories: string[] } | null;
	newAddress: boolean;
	count: number;
	firstAt: string;
	lastAt: string;
	check: { app: string } | { api: string } | null;
}

export interface ActivityPageView {
	/* Whether this server records now: the console says so when an operator turned it off. */
	recording: boolean;
	recordingBegan: string | null;
	keptDays: number;
	rows: ActivityRowView[];
	next: string | null;
	busyDays: string[];
}

export interface ActivityPageQuery {
	kind?: PersonActivityRow['kind'];
	outcome?: PersonActivityRow['outcome'];
	before?: string;
	limit?: number;
}

/* The cursor is opaque to its reader: the last row's time and id, so the next page starts strictly after it. */
function encodeCursor(cursor: PersonActivityCursor): string {
	return Buffer.from(
		JSON.stringify([cursor.lastAt.toISOString(), cursor.id])
	).toString('base64url');
}

function decodeCursor(
	text: string | undefined
): PersonActivityCursor | undefined {
	if (text === undefined || text === '') return undefined;
	try {
		const parsed: unknown = JSON.parse(
			Buffer.from(text, 'base64url').toString('utf8')
		);
		if (
			Array.isArray(parsed) &&
			parsed.length === 2 &&
			typeof parsed[0] === 'string' &&
			typeof parsed[1] === 'string'
		) {
			const lastAt = new Date(parsed[0]);
			if (!Number.isNaN(lastAt.getTime())) return { lastAt, id: parsed[1] };
		}
	} catch {
		return undefined;
	}
	return undefined;
}

/* Today's names for what the rows name, read once per page. */
class Names {
	private apps = new Map<string, Promise<BehindProxyApp | null>>();
	private appsByOrigin: Promise<BehindProxyApp[]> | null = null;
	private apis = new Map<string, Promise<ProtectedResource | null>>();
	private clients = new Map<string, Promise<string | null>>();

	constructor(private bucket: UserBucket) {}

	app(id: string): Promise<BehindProxyApp | null> {
		let found = this.apps.get(id);
		if (!found) {
			found = getBehindProxyAppStore()
				.find(id)
				.then((app) => (app?.bucketId === this.bucket._id ? app : null));
			this.apps.set(id, found);
		}
		return found;
	}

	async appAt(origin: string): Promise<BehindProxyApp | null> {
		this.appsByOrigin ??= getBehindProxyAppStore().listByBucket(
			this.bucket._id
		);
		const apps = await this.appsByOrigin;
		return (
			apps.find((app) => {
				try {
					return new URL(app.address).origin === origin;
				} catch {
					return false;
				}
			}) ?? null
		);
	}

	api(identifier: string): Promise<ProtectedResource | null> {
		let found = this.apis.get(identifier);
		if (!found) {
			found = getProtectedResourceStore()
				.find(namespaceOf(this.bucket), identifier)
				.then((api) => (api?.bucketId === this.bucket._id ? api : null));
			this.apis.set(identifier, found);
		}
		return found;
	}

	client(id: string): Promise<string | null> {
		let found = this.clients.get(id);
		if (!found) {
			found = Client.tryFind(id).then((client) => client?.clientName ?? null);
			this.clients.set(id, found);
		}
		return found;
	}

	provider(id: string): string | null {
		const provider = this.bucket.federation.find((p) => p.id === id);
		if (!provider) return null;
		return (
			knownProviderByIssuer(provider.issuer)?.displayName ??
			provider.displayName
		);
	}
}

async function viewOf(
	row: PersonActivityRow,
	names: Names,
	newAddress: boolean
): Promise<ActivityRowView> {
	let place: string | null = null;
	let client: string | null = null;
	let check: ActivityRowView['check'] = null;
	if (row.kind === 'app' && row.place.appId) {
		const app = await names.app(row.place.appId);
		place = app?.name ?? null;
		if (app) check = { app: app._id };
	} else if (row.kind === 'api' && row.place.resource) {
		const api = await names.api(row.place.resource);
		place = api?.name ?? null;
		if (api) check = { api: api.identifier };
		if (row.place.clientId) client = await names.client(row.place.clientId);
	} else if (row.place.appOrigin) {
		place = (await names.appAt(row.place.appOrigin))?.name ?? null;
	} else if (row.place.clientId) {
		place = await names.client(row.place.clientId);
	}
	const provider = row.place.providerId
		? names.provider(row.place.providerId)
		: null;
	return {
		id: row._id,
		day: row.day,
		kind: row.kind,
		outcome: row.outcome,
		reason: row.reason,
		words: wordsOf(row, { place, client, provider }),
		place: { ...row.place, name: place },
		client,
		address: row.address ?? null,
		addressFrom: row.addressFrom ?? null,
		facts: row.facts
			? {
					country: row.facts.country ?? null,
					categories: [...row.facts.categories]
				}
			: null,
		newAddress,
		count: row.count,
		firstAt: row.firstAt.toISOString(),
		lastAt: row.lastAt.toISOString(),
		check
	};
}

/*
 * "New address" (FR-022, У10): a successful sign-in from an address none of the person's earlier successful sign-ins
 * used, said only once there are at least five of them to compare with. Never on an app or API row.
 */
async function newAddressIds(
	bucketId: string,
	accountId: string,
	rows: readonly PersonActivityRow[],
	now: Date
): Promise<Set<string>> {
	const candidates = rows.filter(
		(row) => row.kind === 'signIn' && row.outcome === 'let_in' && row.address
	);
	if (candidates.length === 0) return new Set();
	/* Every successful sign-in kept: within 90 days they are at most a few hundred for one person. */
	const { rows: history } = await getPersonActivityStore().listForPerson(
		bucketId,
		accountId,
		{ kind: 'signIn', outcome: 'let_in', limit: 500, now }
	);
	const newAddress = new Set<string>();
	for (const row of candidates) {
		const earlier = history.filter(
			(other) =>
				other.lastAt.getTime() < row.lastAt.getTime() ||
				(other.lastAt.getTime() === row.lastAt.getTime() && other._id < row._id)
		);
		if (earlier.length < NEW_ADDRESS_AFTER) continue;
		if (!earlier.some((other) => other.address === row.address)) {
			newAddress.add(row._id);
		}
	}
	return newAddress;
}

export async function activityPage(
	bucket: UserBucket,
	accountId: string,
	query: ActivityPageQuery
): Promise<ActivityPageView> {
	const now = new Date();
	const store = getPersonActivityStore();
	const before = decodeCursor(query.before);
	const page = await store.listForPerson(bucket._id, accountId, {
		limit: query.limit ?? 50,
		now,
		...(query.kind === undefined ? {} : { kind: query.kind }),
		...(query.outcome === undefined ? {} : { outcome: query.outcome }),
		...(before === undefined ? {} : { before })
	});
	const names = new Names(bucket);
	const fresh = await newAddressIds(bucket._id, accountId, page.rows, now);
	const rows = await Promise.all(
		page.rows.map((row) => viewOf(row, names, fresh.has(row._id)))
	);
	const days = [...new Set(page.rows.map((row) => row.day))];
	const [busyDays, startedAt] = await Promise.all([
		store.overflowDays(bucket._id, days, now),
		recordingBegan()
	]);
	return {
		recording: ApplicationConfig['personActivity.enabled'],
		recordingBegan: startedAt?.toISOString() ?? null,
		keptDays: PERSON_ACTIVITY_DAYS,
		rows,
		next: page.next ? encodeCursor(page.next) : null,
		busyDays: busyDays.sort()
	};
}

export interface ActivitySummary {
	recordingBegan: string | null;
	keptDays: number;
	lastSignIn: {
		at: string;
		clientId: string | null;
		name: string | null;
		method: string | null;
	} | null;
	notLetInSince: {
		at: string;
		count: number;
		reason: string;
		kind: PersonActivityRow['kind'];
	} | null;
	lastActive: { day: string } | { month: string } | null;
}

const RECENT_ROWS = 200;
const DAY_MS = 24 * 60 * 60 * 1000;

/* The latest day the person was marked active in the last 40 days, else the latest month in the last 13 (R17). */
async function lastActive(
	bucketId: string,
	accountId: string,
	now: Date
): Promise<ActivitySummary['lastActive']> {
	const days = Array.from({ length: 41 }, (_, i) =>
		dayOf(new Date(now.getTime() - i * DAY_MS))
	);
	const store = getActivityStore();
	const markedDays = await store.markedPeriods(bucketId, accountId, days, now);
	if (markedDays.length > 0)
		return { day: [...markedDays].sort().at(-1) ?? '' };
	const months = Array.from({ length: 14 }, (_, i) =>
		monthOf(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1)))
	);
	const markedMonths = await store.markedPeriods(
		bucketId,
		accountId,
		months,
		now
	);
	return markedMonths.length > 0
		? { month: [...markedMonths].sort().at(-1) ?? '' }
		: null;
}

/*
 * The Profile tab's lines (FR-021). No address, country or device: it is read on every person's page, unaudited, so it
 * carries nothing the audit of the timeline protects (research R16).
 */
export async function activitySummary(
	bucket: UserBucket,
	accountId: string
): Promise<ActivitySummary> {
	const now = new Date();
	const store = getPersonActivityStore();
	const [recent, signedIn, startedAt, active] = await Promise.all([
		store.listForPerson(bucket._id, accountId, { limit: RECENT_ROWS, now }),
		store.listForPerson(bucket._id, accountId, {
			kind: 'signIn',
			outcome: 'let_in',
			limit: 1,
			now
		}),
		recordingBegan(),
		lastActive(bucket._id, accountId, now)
	]);
	const last = signedIn.rows.at(0);
	const names = new Names(bucket);
	let lastSignIn: ActivitySummary['lastSignIn'] = null;
	if (last) {
		const view = await viewOf(last, names, false);
		lastSignIn = {
			at: view.lastAt,
			clientId: last.place.clientId ?? null,
			name: view.place.name,
			method: view.words.method
		};
	}
	const after = recent.rows.filter(
		(row) =>
			row.outcome !== 'let_in' &&
			(!last || row.lastAt.getTime() > last.lastAt.getTime())
	);
	let notLetInSince: ActivitySummary['notLetInSince'] = null;
	const latest = after.at(0);
	if (latest) {
		const view = await viewOf(latest, names, false);
		notLetInSince = {
			at: view.lastAt,
			count: after.reduce((sum, row) => sum + row.count, 0),
			reason: view.words.reason,
			kind: latest.kind
		};
	}
	return {
		recordingBegan: startedAt?.toISOString() ?? null,
		keptDays: PERSON_ACTIVITY_DAYS,
		lastSignIn,
		notLetInSince,
		lastActive: active
	};
}
