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
	refusedCount,
	reportFault,
	resetForTest as resetDispatch
} from 'lib/sentry/dispatch.ts';
import type { ErrorOccurrence, ErrorRecord } from 'lib/adapters/types.ts';
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

	/*
	 * The single assertion that makes "grouping is unchanged" true rather than argued.
	 *
	 * The destination's own grouping algorithm runs only when the client sets no fingerprint, or when
	 * server-side rules ask for `{{ default }}`. This event does neither: one element, the store's own
	 * key, verbatim. So nothing about how the headline or the locator read can split a group, merge
	 * two, or reorder anything — and if someone later adds `{{ default }}` here to "improve" grouping,
	 * this fails and says why.
	 */
	it('groups by the store key alone, leaving no room for the destination to regroup', async () => {
		const app = appThrowing('/sentry-group', () => {
			throw new Error('groupable');
		});
		await app.handle(new Request('http://e.ly/sentry-group'));
		await settle();

		const fingerprint = capturedEvents()[0].fingerprint as string[];
		expect(fingerprint).toHaveLength(1);
		expect(fingerprint[0]).toMatch(/^[0-9a-f]{32}$/);
		expect(fingerprint).not.toContain('{{ default }}');

		/* The same key the internal store filed it under — the join that makes the alert actionable. */
		const groups = await errorStore.list({ route: '/sentry-group' });
		expect(groups.groups[0].fingerprint).toBe(fingerprint[0]);
	});

	/*
	 * The headline: the diagnostic message, prefixed with the failure kind.
	 *
	 * This is the field the destination titles an issue with, and it used to hold
	 * `errorCode method route` — identical for every fault on an endpoint, while the message that
	 * would have told them apart sat in a context object nobody sees without opening the alert.
	 */
	it('titles the event with the failure kind and the diagnostic message', async () => {
		const app = appThrowing('/sentry-headline', () => {
			throw new Error('the connection pool is exhausted');
		});
		await app.handle(new Request('http://e.ly/sentry-headline'));
		await settle();

		expect(capturedEvents()[0].message).toBe(
			'server_error: the connection pool is exhausted'
		);
	});

	/*
	 * The secondary line: method, route pattern, and code location, and nothing else.
	 *
	 * Deterministic for every occurrence in a group, which is what lets it be read as an identity
	 * rather than as noise — the headline varies with the message, this does not.
	 */
	it('locates the event by endpoint and code location', async () => {
		const app = appThrowing('/sentry-locator', () => {
			throw new Error('locate me');
		});
		await app.handle(new Request('http://e.ly/sentry-locator'));
		await settle();

		const transaction = capturedEvents()[0].transaction as string;
		expect(transaction).toStartWith('GET /sentry-locator ');
		expect(transaction).toMatch(/dispatch\.spec\.ts:\d+\)$/);
	});

	/*
	 * The reported complaint, in one assertion: two different problems on one endpoint used to arrive
	 * under byte-identical titles.
	 */
	it('distinguishes two faults raised at different lines on one endpoint', async () => {
		/*
		 * Two throw sites behind ONE route pattern and method, which is the case the complaint was
		 * about. Two different routes would make the transactions differ trivially and prove nothing.
		 */
		const firstSite = (): never => {
			throw new Error('first site');
		};
		const secondSite = (): never => {
			throw new Error('second site');
		};
		const app = new Elysia()
			.onError(errorHandler)
			.get('/sentry-two/:which', ({ params }) =>
				params.which === 'a' ? firstSite() : secondSite()
			);
		await app.handle(new Request('http://e.ly/sentry-two/a'));
		await app.handle(new Request('http://e.ly/sentry-two/b'));
		await settle();

		const events = capturedEvents();
		expect(events).toHaveLength(2);

		/* Same endpoint on both, so the difference can only come from the code location. */
		const routes = events.map((e) => (e.tags as Record<string, string>).route);
		expect(routes).toEqual(['/sentry-two/:which', '/sentry-two/:which']);
		expect(events[0].transaction).not.toBe(events[1].transaction);
		expect(events[0].message).not.toBe(events[1].message);
	});

	/*
	 * The file, as something an operator can filter on — "show me everything wrong in the admin client
	 * routes" rather than "show me this one fault".
	 *
	 * The file and not the line or the function: a tag's cost is cardinality and the number of source
	 * files carrying a fault site is small, while filtering to a single line is what the group already
	 * is. Both are readable in the locator and the fault context regardless.
	 */
	it('exposes the file as a searchable tag, and only the file', async () => {
		const app = appThrowing('/sentry-tag', () => {
			throw new Error('taggable');
		});
		await app.handle(new Request('http://e.ly/sentry-tag'));
		await settle();

		const event = capturedEvents()[0];
		const tags = event.tags as Record<string, string>;
		const location = (event.contexts as Record<string, Record<string, unknown>>)
			.fault.codeLocation as { file: string };

		expect(tags.codeFile).toBe(location.file);
		expect(tags).not.toHaveProperty('codeLine');
		expect(tags).not.toHaveProperty('codeFunction');
	});

	/*
	 * The location, in the one place an operator reads it after opening an alert.
	 *
	 * Structured rather than rendered into a string, so file and line stay separately readable — the
	 * rendered form lives in the transaction, and having both is deliberate: one is for scanning a
	 * list, this one is for acting on a single fault.
	 */
	it('carries the code location in the fault context', async () => {
		const app = appThrowing('/sentry-location', () => {
			throw new Error('locatable');
		});
		await app.handle(new Request('http://e.ly/sentry-location'));
		await settle();

		const fault = (
			capturedEvents()[0].contexts as Record<string, Record<string, unknown>>
		).fault;
		const location = fault.codeLocation as Record<string, unknown>;
		expect(Object.keys(location).sort()).toEqual(['file', 'frame', 'line']);
		expect(location.file).toContain('dispatch.spec.ts');
		expect(typeof location.line).toBe('number');

		/* The message stays where it was. Promoting it did not mean moving it out of the context. */
		expect(fault.detail).toBe('locatable');
	});

	/*
	 * The refusal branch, reached the only way it can be.
	 *
	 * Every other case in this file drives through the real error handler, deliberately. This one
	 * cannot: the stack parser never produces a stray key, so no request can provoke the offence. What
	 * makes the path real rather than synthetic is that `codeLocation` is projected *by reference* —
	 * whatever sits on the occurrence's origin arrives in the outbound event unchanged. So a future
	 * capture site that decorated the origin with a request id would land here, which is exactly the
	 * accident the guard exists to catch.
	 */
	it('refuses an event whose code location carries a stray field', async () => {
		const record: ErrorRecord = {
			reference: 'err_BBBBBBBBBBBBBBBB',
			at: new Date(),
			clientId: null,
			actor: null,
			scope: null,
			requestId: null,
			origin: null,
			userAgent: null,
			submittedFields: []
		};
		const occurrence = {
			fingerprint: 'fp-refuse',
			errorCode: 'server_error',
			status: 500,
			surface: 'oauth',
			route: '/sentry-refuse',
			method: 'GET',
			origin: {
				file: 'lib/x.ts',
				line: 1,
				frame: 'x',
				requestId: 'ZZsmuggledZZ'
			},
			message: 'deliberate fault',
			record
		} as unknown as ErrorOccurrence;

		reportFault(occurrence);
		await settle();

		expect(refusedCount()).toBe(1);
		/* Refused, not scrubbed and sent — an unsent event costs an alert, a wrong one costs data. */
		expect(capturedEvents()).toHaveLength(0);
		expect(JSON.stringify(recordedEnvelopes())).not.toContain('ZZsmuggledZZ');
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
