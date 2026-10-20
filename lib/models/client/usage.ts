import { Type as t, type Static } from '@sinclair/typebox';
import QuickLRU from 'quick-lru';
import { adapter } from '../../adapters/index.js';
import { captureFault } from '../../error_store/capture.js';
import epochTime from '../../helpers/epoch_time.js';

/*
 * When an application first and last received a token (spec 107): what lets its page say "Not used yet" and then
 * "Last sign-in: 2 minutes ago" — the proof that a developer's own integration works, which no console button can
 * give. One record per application, keyed by its id; nothing about the person, the request or the grant, because the
 * question it answers is about the application and nothing else is needed to answer it.
 */
export const ClientUsagePayload = t.Object({
	clientId: t.String(),
	firstUsedAt: t.Number(),
	lastUsedAt: t.Number()
});

export type ClientUsagePayload = Static<typeof ClientUsagePayload>;

export interface LastUsed {
	firstUsedAt: number;
	lastUsedAt: number;
}

/*
 * Written at most this often per application on each server: an application refreshing tokens for many people would
 * otherwise cost a database write per token. "Last used" to the minute is all the page claims.
 */
const RESOLUTION_SECONDS = 60;

const written = new QuickLRU<string, number>({ maxSize: 50_000 });
const pending = new Set<Promise<void>>();

export async function readClientUsage(
	clientId: string
): Promise<LastUsed | null> {
	return lastUsedOf(await adapter('ClientUsage').find(clientId));
}

/* A stored record read through its shape: one that does not have it reads as never used. */
function lastUsedOf(
	record: Record<string, unknown> | undefined
): LastUsed | null {
	const firstUsedAt = record?.firstUsedAt;
	const lastUsedAt = record?.lastUsedAt;
	return typeof firstUsedAt === 'number' && typeof lastUsedAt === 'number'
		? { firstUsedAt, lastUsedAt }
		: null;
}

/*
 * Only an application an administrator created is recorded. One that registered itself, a URL client ID and a client
 * the server synthesizes have no stored, operator-made record, so their use would be an unbounded set of rows nobody
 * has a page to read them on — and a self-registered client's deletion path does not sweep client-owned areas.
 */
async function record(clientId: string, at: number): Promise<void> {
	const client = await adapter('Client').find(clientId);
	if (!client || client.registeredDynamically === true) return;
	const prior = lastUsedOf(await adapter('ClientUsage').find(clientId));
	await adapter('ClientUsage').upsert(clientId, {
		clientId,
		firstUsedAt: prior?.firstUsedAt ?? at,
		lastUsedAt: at
	});
}

/*
 * Called once per token issued at the token endpoint, beside the activity recorder, and never awaited: knowing an
 * application was used must never slow a token response or fail one.
 */
export function noteClientUse(clientId: string | undefined): void {
	if (!clientId) return;
	const at = epochTime();
	const last = written.get(clientId);
	if (last !== undefined && at - last < RESOLUTION_SECONDS) return;
	written.set(clientId, at);

	const write = record(clientId, at).catch((error: unknown) => {
		written.delete(clientId);
		console.error('application use not recorded', { clientId, error });
		captureFault({
			surface: 'oauth',
			route: '/token',
			method: 'POST',
			// The tokens were issued; this is the class of the fault, not the response's status.
			status: 500,
			errorCode: 'client_use_not_recorded',
			error,
			clientId,
			headers: new Headers()
		});
	});
	pending.add(write);
	void write.finally(() => pending.delete(write));
}

/* Test-only: resolves once every write started so far has settled, so a case reads what it caused. */
export async function whenClientUseRecorded(): Promise<void> {
	while (pending.size > 0) await Promise.allSettled([...pending]);
}

/* Test-only: forget what this instance has written, so a case starts from nothing. */
export function resetClientUseForTests(): void {
	written.clear();
}
