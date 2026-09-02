import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { initSentry, resetForTest as resetClient } from 'lib/sentry/client.ts';
import { reportStartupFailure } from 'lib/sentry/startup.ts';
import { clearRecorded, recordedEnvelopes } from 'lib/sentry/transport.ts';
import { PERMITTED_STARTUP_KEYS } from 'lib/sentry/types.ts';

/*
 * The declared exception to "every event comes from an internal record".
 *
 * A failure that stops the server starting has no record to be projected from — the store does not
 * exist yet — so it travels this path instead. What matters is that it stays impoverished: no
 * request data, because there is no request, and no reference, because there is nothing for one to
 * resolve to.
 */
const previous = {
	enabled: ApplicationConfig['sentry.enabled'],
	dsn: ApplicationConfig['sentry.dsn']
};

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

describe('sentry startup reporting', () => {
	beforeEach(() => {
		resetClient();
		clearRecorded();
		ApplicationConfig['sentry.enabled'] = true;
		ApplicationConfig['sentry.dsn'] = 'https://publickey@o0.ingest.invalid/1';
		initSentry();
	});

	afterEach(() => {
		resetClient();
		clearRecorded();
		ApplicationConfig['sentry.enabled'] = previous.enabled;
		ApplicationConfig['sentry.dsn'] = previous.dsn;
	});

	it('sends exactly one event for a startup failure', async () => {
		await reportStartupFailure('EADDRINUSE', 'listen');
		const events = capturedEvents();
		expect(events).toHaveLength(1);
		expect(JSON.stringify(events[0])).toContain('EADDRINUSE');
		expect(JSON.stringify(events[0])).toContain('listen');
	});

	it('marks the event as a startup failure so it is filterable', async () => {
		await reportStartupFailure('EADDRINUSE', 'listen');
		const tags = capturedEvents()[0].tags as Record<string, string>;
		expect(tags.startup).toBe('true');
		expect(tags.kind).toBe('EADDRINUSE');
		expect(tags.phase).toBe('listen');
	});

	it('carries the instance label', async () => {
		await reportStartupFailure('boom', 'listen');
		expect(capturedEvents()[0].server_name).toBe(process.env.ISSUER);
	});

	/*
	 * The impoverishment is the point: at this stage there is no request, so any of these appearing
	 * would mean something was invented.
	 */
	it('carries no request data and no reference', async () => {
		await reportStartupFailure('boom', 'listen');
		const event = capturedEvents()[0];
		expect(event).not.toHaveProperty('request');
		expect(event).not.toHaveProperty('user');
		const tags = event.tags as Record<string, string>;
		expect(tags).not.toHaveProperty('reference');
		expect(tags).not.toHaveProperty('clientId');
		expect(tags).not.toHaveProperty('route');
	});

	it('permits only the five declared fields on the projected shape', () => {
		expect([...PERMITTED_STARTUP_KEYS].sort()).toEqual([
			'environment',
			'instance',
			'kind',
			'phase',
			'release'
		]);
	});

	it('sends nothing when the capability is off', async () => {
		ApplicationConfig['sentry.enabled'] = false;
		resetClient();
		await reportStartupFailure('boom', 'listen');
		expect(capturedEvents()).toHaveLength(0);
	});

	/*
	 * Resolves rather than throwing, whatever happens. A boot that fails must fail the way it always
	 * did; the reporter cannot be the reason it hangs or the reason it reports a different error.
	 */
	it('resolves without throwing when it cannot be armed', async () => {
		ApplicationConfig['sentry.dsn'] = '';
		resetClient();
		await expect(
			reportStartupFailure('boom', 'listen')
		).resolves.toBeUndefined();
	});

	it('resolves within its bound rather than hanging', async () => {
		const started = Date.now();
		await reportStartupFailure('boom', 'listen', 50);
		expect(Date.now() - started).toBeLessThan(2000);
	});
});
