import QuickLRU from 'quick-lru';

import { getBehindProxyAppStore } from '../adapters/index.js';
import type { BehindProxyApp, BehindProxyAppUsage } from '../adapters/types.js';
import { BEHIND_PROXY_CHECK_ROUTE } from '../consts/behind_proxy.js';
import { captureFault } from '../error_store/capture.js';
import { hasControlCharacter } from './decide.js';

/*
 * What the Connect page's checklist reads about an app behind a proxy (specs/122 US5, R11): when the proxy first
 * and last asked about it, when someone first signed in through it and first got through, and which hosts the
 * proxy reported for it that were not its address.
 *
 * Every page asset of every person is one check, so none of this may cost a write per request: "last asked" is
 * written at most once a minute per app on each server, and each "first" at most once per server, claimed before
 * the write as `noteClientUse` does (lib/models/client/usage.ts), never awaited, and a failure is captured rather
 * than answered. The store writes each "first" only where none is recorded, so a second server's claim cannot move
 * it. The reported hosts are kept in memory only: a hint for whoever is wiring the proxy now, not a record.
 */

const ASKED_RESOLUTION_MS = 60_000;

const asked = new QuickLRU<string, number>({ maxSize: 50_000 });
/* `<field>:<appId>` for each "first" this server has already sent; the record itself says it from then on. */
const firsts = new QuickLRU<string, true>({ maxSize: 50_000 });
const pending = new Set<Promise<void>>();

type First = 'firstAskedAt' | 'firstSignInAt' | 'firstAllowedAt';

function claimFirst(app: BehindProxyApp, field: First): boolean {
	if (app[field]) return false;
	const key = `${field}:${app._id}`;
	if (firsts.has(key)) return false;
	firsts.set(key, true);
	return true;
}

function write(
	app: BehindProxyApp,
	fields: BehindProxyAppUsage,
	release: () => void
): void {
	const written = getBehindProxyAppStore()
		.noteUsage(app._id, fields)
		.catch((error: unknown) => {
			release();
			console.error('app behind a proxy: use not recorded', {
				appId: app._id,
				error
			});
			captureFault({
				surface: 'oauth',
				route: BEHIND_PROXY_CHECK_ROUTE,
				method: 'GET',
				// The check was answered; this is the class of the fault, not the answer's status.
				status: 500,
				errorCode: 'behind_proxy_use_not_recorded',
				error,
				headers: new Headers()
			});
		});
	pending.add(written);
	void written.finally(() => pending.delete(written));
}

/* A check for this app, at its address, reached the project (step 6 of the check). */
export function noteAsked(app: BehindProxyApp): void {
	const now = Date.now();
	const last = asked.get(app._id);
	if (last !== undefined && now - last < ASKED_RESOLUTION_MS) return;
	asked.set(app._id, now);
	const first = claimFirst(app, 'firstAskedAt');
	write(
		app,
		{
			lastAskedAt: new Date(now),
			...(first ? { firstAskedAt: new Date(now) } : {})
		},
		() => {
			if (last === undefined) asked.delete(app._id);
			else asked.set(app._id, last);
			if (first) firsts.delete(`firstAskedAt:${app._id}`);
		}
	);
}

/* The check let a named person through: the checklist's last step. */
export function noteAllowed(app: BehindProxyApp): void {
	noteFirst(app, 'firstAllowedAt');
}

/* Someone completed a sign-in through this app. */
export function noteSignedIn(app: BehindProxyApp): void {
	noteFirst(app, 'firstSignInAt');
}

function noteFirst(app: BehindProxyApp, field: First): void {
	if (!claimFirst(app, field)) return;
	write(app, { [field]: new Date() }, () =>
		firsts.delete(`${field}:${app._id}`)
	);
}

/*
 * The hosts a proxy reported for an app that were not its address. A few per app, for a quarter of an hour: enough
 * to name the mistake while someone is wiring the proxy, too little to be worth flooding. Anything that could not
 * be a host is not kept, so the page never shows a value a caller shaped to look like something else.
 */
const MISMATCH_MS = 15 * 60_000;
const MISMATCHES_PER_APP = 5;
const MAX_HOST_LENGTH = 260;

const mismatched = new QuickLRU<string, Map<string, number>>({
	maxSize: 10_000
});

export function noteMismatchedHost(appId: string, host: string): void {
	const value = host.trim().toLowerCase();
	if (
		value === '' ||
		value.length > MAX_HOST_LENGTH ||
		hasControlCharacter(value) ||
		/[^\x21-\x7e]/.test(value)
	) {
		return;
	}
	const hosts = mismatched.get(appId) ?? new Map<string, number>();
	hosts.delete(value);
	hosts.set(value, Date.now());
	while (hosts.size > MISMATCHES_PER_APP) {
		const oldest = hosts.keys().next().value;
		if (oldest === undefined) break;
		hosts.delete(oldest);
	}
	mismatched.set(appId, hosts);
}

/* Most recent first. */
export function mismatchedHostsOf(appId: string): string[] {
	const hosts = mismatched.get(appId);
	if (!hosts) return [];
	const since = Date.now() - MISMATCH_MS;
	return [...hosts]
		.filter(([, at]) => at >= since)
		.reverse()
		.map(([host]) => host);
}

/* Test-only: resolves once every write started so far has settled, so a case reads what it caused. */
export async function whenUsageRecorded(): Promise<void> {
	while (pending.size > 0) await Promise.allSettled([...pending]);
}
