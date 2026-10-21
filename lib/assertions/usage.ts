import { Type as t, type Static } from '@sinclair/typebox';
import QuickLRU from 'quick-lru';
import { adapter } from '../adapters/index.js';
import { captureFault } from '../error_store/capture.js';
import epochTime from '../helpers/epoch_time.js';

/*
 * When an assertion trust was last used (specs/108): a provider's assertion accepted, or an ID-JAG issued for
 * an outside authorization server connection. It is what lets an administrator tell a trust nobody relies on
 * from one they are about to break. Nothing about the person or the request: the question is about the trust.
 */
export const AssertionUsagePayload = t.Object({
	lastUsedAt: t.Number()
});
export type AssertionUsagePayload = Static<typeof AssertionUsagePayload>;

/* As for an application's use (lib/models/client/usage.ts): to the minute is all a page claims. */
const RESOLUTION_SECONDS = 60;

const written = new QuickLRU<string, number>({ maxSize: 50_000 });
const pending = new Set<Promise<void>>();

export const providerUsageKey = (bucketId: string, providerId: string) =>
	`provider:${bucketId}:${providerId}`;
export const outsideServerUsageKey = (connectionId: string) =>
	`outside:${connectionId}`;

export async function readAssertionUsage(key: string): Promise<number | null> {
	const lastUsedAt = (await adapter('AssertionUsage').find(key))?.lastUsedAt;
	return typeof lastUsedAt === 'number' ? lastUsedAt : null;
}

export async function forgetAssertionUsage(key: string): Promise<void> {
	written.delete(key);
	await adapter('AssertionUsage').destroy(key);
}

/* Never awaited by a grant: knowing a trust was used must never slow a token response or fail one. */
function note(key: string, clientId: string): void {
	const at = epochTime();
	const last = written.get(key);
	if (last !== undefined && at - last < RESOLUTION_SECONDS) return;
	written.set(key, at);

	const write = adapter('AssertionUsage')
		.upsert(key, { lastUsedAt: at })
		.catch((error: unknown) => {
			written.delete(key);
			console.error('assertion use not recorded', { key, error });
			captureFault({
				surface: 'oauth',
				route: '/token',
				method: 'POST',
				// The tokens were issued; this is the class of the fault, not the response's status.
				status: 500,
				errorCode: 'assertion_use_not_recorded',
				error,
				clientId,
				headers: new Headers()
			});
		});
	pending.add(write);
	void write.finally(() => pending.delete(write));
}

export function noteProviderAssertionUse(
	bucketId: string,
	providerId: string,
	clientId: string
): void {
	note(providerUsageKey(bucketId, providerId), clientId);
}

export function noteOutsideServerUse(
	connectionId: string,
	clientId: string
): void {
	note(outsideServerUsageKey(connectionId), clientId);
}

/* Test-only: resolves once every write started so far has settled. */
export async function whenAssertionUseRecorded(): Promise<void> {
	while (pending.size > 0) await Promise.allSettled([...pending]);
}

/* Test-only: forget what this instance has written, so a case starts from nothing. */
export function resetAssertionUseForTests(): void {
	written.clear();
}
