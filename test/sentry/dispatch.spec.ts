import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { InvalidGrant } from 'lib/helpers/errors.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { resetOriginSalt } from 'lib/error_store/redact.ts';
import { initSentry, resetForTest as resetClient } from 'lib/sentry/client.ts';
import {
	droppedCount,
	flushForTest as flushSentry,
	resetForTest as resetDispatch
} from 'lib/sentry/dispatch.ts';
import { clearRecorded, recordedEnvelopes } from 'lib/sentry/transport.ts';

/*
 * What becomes an outbound event, exercised through the real global error handler.
 *
 * Driven through the handler rather than by calling the dispatch function directly, for the same
 * reason the error store's own capture spec is: the classification lives in the handler, and a unit
 * test of the dispatcher would pass happily while the handler declined to call it — or called it for
 * traffic that is not a fault at all.
 *
 * Every case provokes its fault on a route this spec mounts, and assertions are scoped to that route.
 * The store and the queue are process-wide singletons.
 */
const previous = {
	store: ApplicationConfig['errorStore.enabled'],
	sentry: ApplicationConfig['sentry.enabled'],
	dsn: ApplicationConfig['sentry.dsn']
};

function appThrowing(route: string, thrown: () => never) {
	return new Elysia().onError(errorHandler).get(route, () => thrown());
}

/* The event payloads of everything the transport was handed, in order. */
function capturedEvents(): Record<string, unknown>[] {
	const events: Record<string, unknown>[] = [];
	for (const [, items] of recordedEnvelopes()) {
		for (const [header, payload] of items as [{ type?: string }, unknown][]) {
			if (header?.type === 'event') {
				events.push(payload as Record<string, unknown>);
			}
		}
	}
	return events;
}

async function settle() {
	await flushForTest();
	await flushSentry();
}

describe('sentry dispatch', () => {
	beforeEach(() => {
		resetQueue();
		resetOriginSalt();
		resetDispatch();
		resetClient();
		clearRecorded();
		ApplicationConfig['errorStore.enabled'] = true;
		ApplicationConfig['sentry.enabled'] = true;
		ApplicationConfig['sentry.dsn'] = 'https://publickey@o0.ingest.invalid/1';
		initSentry();
	});

	afterEach(() => {
		resetDispatch();
		resetClient();
		clearRecorded();
		ApplicationConfig['errorStore.enabled'] = previous.store;
		ApplicationConfig['sentry.enabled'] = previous.sentry;
		ApplicationConfig['sentry.dsn'] = previous.dsn;
	});

	it('sends exactly one event for one unexpected fault', async () => {
		const app = appThrowing('/sentry-one', () => {
			throw new Error('kaboom');
		});

		const response = await app.handle(new Request('http://e.ly/sentry-one'));
		expect(response.status).toBe(500);
		await settle();

		const events = capturedEvents();
		expect(events).toHaveLength(1);
		expect(JSON.stringify(events[0])).toContain('kaboom');
	});

	/*
	 * The reference is the join: an operator reads it off a Sentry alert and looks the full record up
	 * in the console. If these two ever disagree the outbound event is unactionable.
	 */
	it('carries the same reference the caller received', async () => {
		const app = appThrowing('/sentry-ref', () => {
			throw new Error('joinable');
		});

		const response = await app.handle(new Request('http://e.ly/sentry-ref'));
		const body = (await response.json()) as { error_reference?: string };
		expect(body.error_reference).toMatch(/^err_/);
		await settle();

		const reference = body.error_reference ?? '';
		const [event] = capturedEvents();
		expect((event.tags as Record<string, string>).reference).toBe(reference);
	});

	/*
	 * The case the official Elysia plugin gets wrong, and the reason this integration does not use it:
	 * its capture predicate reads the response status and reports when it is still undefined, so a
	 * routine protocol rejection ships as an unhandled fault. On an authorization server those
	 * rejections are the normal traffic.
	 */
	it('sends nothing for an expected protocol rejection', async () => {
		const app = appThrowing('/sentry-rejected', () => {
			throw new InvalidGrant('grant request is invalid');
		});

		const response = await app.handle(
			new Request('http://e.ly/sentry-rejected')
		);
		expect(response.status).toBeLessThan(500);
		await settle();

		expect(capturedEvents()).toHaveLength(0);
	});

	it('sends nothing when a request succeeds', async () => {
		const app = new Elysia()
			.onError(errorHandler)
			.get('/sentry-ok', () => 'ok');
		await app.handle(new Request('http://e.ly/sentry-ok'));
		await settle();
		expect(capturedEvents()).toHaveLength(0);
	});

	/*
	 * Off by default means nothing leaves — and the fault is still recorded locally, which is the half
	 * of the requirement that would be easy to break while making the first half true.
	 */
	it('sends nothing when the capability is off, and still records the fault', async () => {
		ApplicationConfig['sentry.enabled'] = false;
		resetClient();

		const app = appThrowing('/sentry-off', () => {
			throw new Error('unreported');
		});
		await app.handle(new Request('http://e.ly/sentry-off'));
		await settle();

		expect(capturedEvents()).toHaveLength(0);
		const page = await errorStore.list({ route: '/sentry-off' });
		expect(page.groups).toHaveLength(1);
	});

	/* Recording is the prerequisite, so with the store off there is no event source at all. */
	it('sends nothing when the error store is off', async () => {
		ApplicationConfig['errorStore.enabled'] = false;

		const app = appThrowing('/sentry-nostore', () => {
			throw new Error('unrecorded');
		});
		await app.handle(new Request('http://e.ly/sentry-nostore'));
		await settle();

		expect(capturedEvents()).toHaveLength(0);
	});

	it('reports a fault alongside the local record, never instead of it', async () => {
		const app = appThrowing('/sentry-both', () => {
			throw new Error('both');
		});
		await app.handle(new Request('http://e.ly/sentry-both'));
		await settle();

		expect(capturedEvents()).toHaveLength(1);
		const page = await errorStore.list({ route: '/sentry-both' });
		expect(page.groups).toHaveLength(1);
	});

	it('groups by the same fingerprint the store groups by', async () => {
		const app = appThrowing('/sentry-group', () => {
			throw new Error('repeated');
		});
		for (let i = 0; i < 3; i += 1) {
			await app.handle(new Request('http://e.ly/sentry-group'));
		}
		await settle();

		const events = capturedEvents();
		expect(events).toHaveLength(3);
		const prints = new Set(events.map((e) => JSON.stringify(e.fingerprint)));
		expect(prints.size).toBe(1);

		const page = await errorStore.list({ route: '/sentry-group' });
		expect((events[0].fingerprint as string[])[0]).toBe(
			page.groups[0].fingerprint
		);
	});

	it('starts with no drops', () => {
		expect(droppedCount()).toBe(0);
	});
});
