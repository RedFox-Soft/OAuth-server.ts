import { Elysia } from 'elysia';

import { ReadyResponse } from 'lib/shared/response_schemas.js';
import { storagePing } from 'lib/adapters/index.js';

/*
 * Readiness: whether this server can actually serve.
 *
 * Separate from `/health`, and the separation is the point. Liveness answers "this process is alive"
 * and a failure means restart it; readiness answers "route traffic to me" and a failure means stop
 * routing, not restart. Merging them makes both wrong — a restart loop against a database outage, or
 * traffic sent to a server that cannot persist.
 *
 * `/health` therefore stays exactly as it is: dependency-free and exempt from rate limiting. This
 * route reaches storage, so it is rate-limited like any public route. Folding the two together would
 * have turned the one unmetered endpoint into an unauthenticated amplifier onto the datastore.
 *
 * The response names the failing subsystem and nothing else. A probe response is read by machines and
 * pasted into issues by people; a connection string or a driver error has no business in either.
 */

/*
 * The last probe's answer, held briefly.
 *
 * An orchestrator polls this on a fixed interval and there is usually more than one replica, so the
 * cache is what stops a rate limit's worth of probes becoming a rate limit's worth of database round
 * trips. Short enough that recovery is observed without operator action — a database that comes back
 * is reported ready within a second, not within a minute.
 */
const CACHE_MS = 1000;

let lastChecked = 0;
let lastReachable = false;

/*
 * The probe currently in flight, if any, shared by everyone who asks meanwhile.
 *
 * The cache above only helps once an answer exists. A database that has stopped answering — as
 * opposed to refusing connections — leaves the probe outstanding for its whole deadline, and every
 * probe arriving in that window would otherwise start a query of its own against a database already
 * failing to keep up. Sharing the outstanding one bounds the damage to a single query per deadline,
 * which is the difference between a readiness probe reporting a problem and joining it.
 */
let inFlight: Promise<boolean> | null = null;

async function storageReachable(): Promise<boolean> {
	const now = Date.now();
	if (now - lastChecked < CACHE_MS) return lastReachable;
	if (inFlight) return inFlight;

	inFlight = probeStorage().finally(() => {
		inFlight = null;
	});
	return inFlight;
}

async function probeStorage(): Promise<boolean> {
	try {
		await storagePing();
		lastReachable = true;
	} catch {
		/* Why it failed is not the caller's business and not safe to repeat: the driver's message
		 * routinely carries the host, and sometimes the credentials. The fault itself reaches the error
		 * store through the ordinary path. */
		lastReachable = false;
	}

	lastChecked = Date.now();
	return lastReachable;
}

export const readyCheck = new Elysia().get(
	'/ready',
	async ({ set }) => {
		if (await storageReachable()) {
			return { status: 'ready' as const };
		}

		/* 503 rather than 500: the server is working and its dependency is not, which is precisely the
		 * distinction an orchestrator acts on. */
		set.status = 503;
		return { status: 'not_ready' as const, subsystem: 'storage' as const };
	},
	{
		response: { 200: ReadyResponse, 503: ReadyResponse }
	}
);

/* Test-only: the cache would otherwise carry one spec's answer into the next. */
export function resetReadinessCache(): void {
	lastChecked = 0;
	lastReachable = false;
	inFlight = null;
}
