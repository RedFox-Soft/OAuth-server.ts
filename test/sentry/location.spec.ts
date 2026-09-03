import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import type { ErrorOccurrence, ErrorRecord } from 'lib/adapters/types.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { resetOriginSalt } from 'lib/error_store/redact.ts';
import { initSentry, resetForTest as resetClient } from 'lib/sentry/client.ts';
import {
	flushForTest as flushSentry,
	reportFault,
	resetForTest as resetDispatch
} from 'lib/sentry/dispatch.ts';
import { clearRecorded, recordedEnvelopes } from 'lib/sentry/transport.ts';

/*
 * What a reported failure reads like when the location is not the happy case.
 *
 * Split from dispatch.spec.ts because the degenerate cases outnumber the ordinary one and would bury
 * it. Every case here is a shape the stack parser genuinely produces — an unresolvable location, a
 * frame with no line, a frame name that fell back to the file — and each of them once had a plausible
 * wrong answer: a placeholder `0`, an omitted field, a filename presented as a function.
 *
 * Most cases call `reportFault` directly rather than provoking a real throw, because the point is the
 * *rendering* of a given location and a real throw cannot be made to yield one on demand. The two
 * cases that must prove the location is real — that it matches the record, and that a thrown
 * non-Error still reports — go through the handler.
 */
const previous = {
	store: ApplicationConfig['errorStore.enabled'],
	sentry: ApplicationConfig['sentry.enabled'],
	dsn: ApplicationConfig['sentry.dsn']
};

const record: ErrorRecord = {
	reference: 'err_CCCCCCCCCCCCCCCC',
	at: new Date('2026-09-02T10:00:00.000Z'),
	clientId: null,
	actor: null,
	scope: null,
	requestId: null,
	origin: null,
	userAgent: null,
	submittedFields: []
};

function occurrenceWith(
	origin: ErrorOccurrence['origin'],
	overrides: Partial<ErrorOccurrence> = {}
): ErrorOccurrence {
	return {
		fingerprint: 'fp-location',
		errorCode: 'server_error',
		status: 500,
		surface: 'oauth',
		route: '/token',
		method: 'POST',
		origin,
		message: 'something broke',
		record,
		...overrides
	};
}

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

function faultContext(event: Record<string, unknown>): Record<string, unknown> {
	return (event.contexts as Record<string, Record<string, unknown>>).fault;
}

async function settle() {
	await flushForTest();
	await flushSentry();
}

/* Reports one occurrence and returns the single event it produced. */
async function reported(
	occurrence: ErrorOccurrence
): Promise<Record<string, unknown>> {
	reportFault(occurrence);
	await settle();
	const events = capturedEvents();
	expect(events).toHaveLength(1);
	return events[0];
}

describe('sentry fault location', () => {
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

	it('carries the location a real fault was raised at', async () => {
		const app = new Elysia().onError(errorHandler).get('/loc-real', () => {
			throw new Error('deliberate fault');
		});
		await app.handle(new Request('http://e.ly/loc-real'));
		await settle();

		const location = faultContext(capturedEvents()[0]).codeLocation as {
			file: string;
			line: number | null;
			frame: string;
		};
		/* The spec file itself is where the throw is, which is what makes this assertion meaningful. */
		expect(location.file).toContain('location.spec.ts');
		expect(typeof location.line).toBe('number');
		expect(location.frame).toBeTruthy();
	});

	/*
	 * A thrown non-Error has no stack to parse. The requirement is that this still *reports* — an
	 * unplaceable fault is still a fault, and dropping it would make the least diagnosable failures
	 * also the invisible ones.
	 */
	it('reports a fault whose location cannot be resolved', async () => {
		const app = new Elysia().onError(errorHandler).get('/loc-unknown', () => {
			throw 'a string, not an Error';
		});
		await app.handle(new Request('http://e.ly/loc-unknown'));
		await settle();

		const events = capturedEvents();
		expect(events).toHaveLength(1);
		expect(faultContext(events[0]).codeLocation).toEqual({
			file: 'unknown',
			line: null,
			frame: 'unknown'
		});
	});

	/*
	 * Absent must read as absent. A placeholder `0` would be a line number that exists in no file, and
	 * an omitted key would make "we did not parse a line" indistinguishable from "the field is gone".
	 */
	it('reports a missing line as null, never as zero or absent', async () => {
		const event = await reported(
			occurrenceWith({ file: 'lib/x.ts', line: null, frame: 'handler' })
		);
		const location = faultContext(event).codeLocation as Record<
			string,
			unknown
		>;
		expect(location).toHaveProperty('line');
		expect(location.line).toBeNull();
		expect(location.line).not.toBe(0);
	});

	it('carries the location verbatim, without re-truncating or reformatting', async () => {
		const origin = {
			file: 'lib/actions/grants/authorization_code.ts',
			line: 128,
			frame: 'authorizationCodeGrant'
		};
		const event = await reported(occurrenceWith(origin));
		expect(faultContext(event).codeLocation).toEqual(origin);
	});

	/*
	 * The secondary line, in each shape the parser can hand it.
	 *
	 * Asserted as exact strings, which is only possible because these cases go through `reportFault`
	 * with a location chosen rather than thrown. A real throw would pin the assertions to this file's
	 * own line numbers, and they would then break on every edit above them for no reason.
	 */
	it('renders the full location as endpoint, function and file:line', async () => {
		const event = await reported(
			occurrenceWith({ file: 'lib/x.ts', line: 42, frame: 'handler' })
		);
		expect(event.transaction).toBe('POST /token handler (lib/x.ts:42)');
	});

	/*
	 * The parser sets `frame` to the file when it could not read a function name. Repeating it would
	 * present a filename as a function that exists in the source, which is a claim about the code that
	 * is simply false.
	 */
	it('omits the function when the parser fell back to the file name', async () => {
		const event = await reported(
			occurrenceWith({ file: 'lib/x.ts', line: 42, frame: 'lib/x.ts' })
		);
		expect(event.transaction).toBe('POST /token (lib/x.ts:42)');
	});

	it('omits the line when the frame carried none', async () => {
		const event = await reported(
			occurrenceWith({ file: 'lib/x.ts', line: null, frame: 'handler' })
		);
		expect(event.transaction).toBe('POST /token handler (lib/x.ts)');
	});

	/*
	 * Still names the endpoint. An unplaceable fault is the case an operator most needs to be able to
	 * read, so the line degrades rather than disappearing.
	 */
	it('still names the endpoint when the location is unknown', async () => {
		const event = await reported(
			occurrenceWith({ file: 'unknown', line: null, frame: 'unknown' })
		);
		expect(event.transaction).toBe('POST /token (unknown)');
	});

	/*
	 * A blank headline would be worse than the identical ones this feature replaced — an operator would
	 * have nothing at all to read. Falls back to the format that shipped before.
	 */
	it('falls back to the endpoint headline when the message is blank', async () => {
		const event = await reported(
			occurrenceWith(
				{ file: 'lib/x.ts', line: 42, frame: 'handler' },
				{ message: '   ' }
			)
		);
		expect(event.message).toBe('server_error POST /token');
	});

	it('titles the event with the message when there is one', async () => {
		const event = await reported(
			occurrenceWith({ file: 'lib/x.ts', line: 42, frame: 'handler' })
		);
		expect(event.message).toBe('server_error: something broke');
	});

	/*
	 * Present, not absent, when the location could not be resolved.
	 *
	 * An absent tag would make unplaceable faults unfilterable as a set — the operator could not ask
	 * "what am I failing to place?", which is a question worth being able to ask.
	 */
	it('tags an unresolvable location as unknown rather than omitting the tag', async () => {
		const event = await reported(
			occurrenceWith({ file: 'unknown', line: null, frame: 'unknown' })
		);
		expect((event.tags as Record<string, string>).codeFile).toBe('unknown');
	});

	it('tags faults from different files with different values', async () => {
		reportFault(
			occurrenceWith(
				{ file: 'lib/a.ts', line: 1, frame: 'a' },
				{ route: '/token' }
			)
		);
		reportFault(
			occurrenceWith(
				{ file: 'lib/b.ts', line: 2, frame: 'b' },
				{ route: '/authorize' }
			)
		);
		await settle();

		const files = capturedEvents().map(
			(e) => (e.tags as Record<string, string>).codeFile
		);
		expect(files).toEqual(['lib/a.ts', 'lib/b.ts']);
	});

	/*
	 * One fault, many concrete paths. The route pattern is what reaches the secondary line, so a
	 * thousand identifiers cannot become a thousand things to read — and the grouping key, which
	 * already excluded the path, is untouched.
	 */
	it('yields one group and one locator across many concrete paths', async () => {
		for (let i = 0; i < 100; i += 1) {
			reportFault(
				occurrenceWith(
					{ file: 'lib/x.ts', line: 42, frame: 'handler' },
					{ route: '/clients/:id', method: 'GET' }
				)
			);
		}
		await settle();

		const events = capturedEvents();
		expect(events).toHaveLength(100);
		expect(new Set(events.map((e) => e.transaction)).size).toBe(1);
		expect(new Set(events.map((e) => JSON.stringify(e.fingerprint))).size).toBe(
			1
		);
		expect(events[0].transaction).toBe(
			'GET /clients/:id handler (lib/x.ts:42)'
		);
	});
});
