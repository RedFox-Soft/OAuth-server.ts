import QuickLRU from 'quick-lru';

import type { OIDCContext } from '../helpers/oidc_context.js';
import type { TokenParams } from '../actions/token.js';
import { getActivityStore } from '../adapters/index.js';
import { captureFault } from '../error_store/capture.js';
import { now } from './clock.js';
import { dayOf } from './periods.js';
import { kindOf } from './kinds.js';

/*
 * Records that a successful grant was activity of an end user in their bucket (specs/076). Called once, by
 * `executeGrant`, after the handler resolved — the one place every token issued on a person's behalf
 * passes — and never awaited there: counting must never slow a token request or fail one (FR-008).
 *
 * A direct call rather than an `eventBus` listener: the bus is a synchronous emitter, so a listener that
 * threw would fail a request whose tokens were already saved, and nothing would see an async listener's
 * rejection. Here the never-fail guarantee is a property of one function.
 */

/*
 * What this instance has already written today. A client refreshing every few minutes would otherwise cost
 * two upserts a refresh; with this it costs one pair per person, per kind, per day, per instance. It is
 * per instance and lossy on purpose: correctness never depends on it — a miss is only a redundant
 * idempotent upsert — so another instance, an eviction or a restart costs a write, never a miscount.
 */
const recorded = new QuickLRU<string, true>({ maxSize: 50_000 });
const pending = new Set<Promise<void>>();
let sinceRecorded = false;

export function noteActivity(oidc: OIDCContext<TokenParams>): void {
	const account = oidc.entities.Account;
	// No account: a client acting for itself (client_credentials), which is nobody's activity (FR-005).
	if (!account) return;

	const at = now();
	const kind = kindOf(oidc.params.grant_type, signInOf(oidc));
	const { bucketId, accountId, provisioned } = account;
	const key = `${bucketId}|${dayOf(at)}|${accountId}|${kind}`;
	if (recorded.has(key)) return;
	recorded.set(key, true);

	const store = getActivityStore();
	if (!sinceRecorded) {
		sinceRecorded = true;
		track(store.countingSince(at).then(() => undefined));
	}
	track(
		store
			.mark({ bucketId, accountId, kind, provisioned, at })
			.catch((error: unknown) => {
				recorded.delete(key);
				/*
				 * Logged unconditionally and recorded as a fault when recording is on: an undercount nobody can
				 * see is the failure this guards against, and an operator may have fault recording switched off.
				 * The bucket only — an account id in a log line is the record of who used what that FR-021 keeps
				 * out of every surface.
				 */
				console.error('activity not recorded', { bucketId, error });
				captureFault({
					surface: 'oauth',
					route: '/token',
					method: 'POST',
					/*
					 * The class of the fault, not the status of the response, which was 200: the tokens were issued.
					 * The headers are empty on purpose — the fault is the datastore's, none of the request's headers
					 * would help diagnose it, and `OIDCContext` keeps them private.
					 */
					status: 500,
					errorCode: 'activity_not_recorded',
					error,
					clientId: oidc.entities.Client?.clientId ?? null,
					headers: new Headers()
				});
			})
	);
}

/* The sign-in the artifact behind this grant recorded, if it recorded one. */
function signInOf(oidc: OIDCContext<TokenParams>) {
	const { AuthorizationCode, DeviceCode, BackchannelAuthenticationRequest } =
		oidc.entities;
	return (AuthorizationCode ?? DeviceCode ?? BackchannelAuthenticationRequest)
		?.payload.signIn;
}

function track(write: Promise<void>): void {
	pending.add(write);
	void write.finally(() => pending.delete(write));
}

/* Test-only: resolves once every write started so far has settled, so a case reads what it caused. */
export async function whenRecorded(): Promise<void> {
	while (pending.size > 0) await Promise.allSettled([...pending]);
}

/* Test-only: forget what this instance has written, so a case can count from a fresh store. */
export function resetActivityCacheForTests(): void {
	recorded.clear();
	sinceRecorded = false;
}
