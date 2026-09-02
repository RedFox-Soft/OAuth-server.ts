import { describe, it, expect } from 'bun:test';

import type { ErrorOccurrence, ErrorRecord } from 'lib/adapters/types.ts';
import { projectFault } from 'lib/sentry/event.ts';
import { PERMITTED_EVENT_KEYS } from 'lib/sentry/types.ts';

/*
 * The projection, tested as a closed shape.
 *
 * The assertion that matters is key-set *equality*, not containment. A subset check would pass while
 * a new field on the internal record flowed straight out to a third party, which is the whole failure
 * mode the permitted list exists to prevent — so adding a field upstream must break this file.
 */
const record: ErrorRecord = {
	reference: 'err_AAAAAAAAAAAAAAAA',
	at: new Date('2026-09-02T10:00:00.000Z'),
	clientId: 'some-client',
	actor: { id: 'user-1', email: 'person@example.com' },
	scope: 'openid profile',
	requestId: 'req-1',
	origin: 'deadbeefdeadbeef',
	userAgent: 'Mozilla/5.0 (a device fingerprint)',
	submittedFields: ['client_id', 'grant_type']
};

const occurrence: ErrorOccurrence = {
	fingerprint: 'fp-1',
	errorCode: 'server_error',
	status: 500,
	surface: 'oauth',
	route: '/token',
	method: 'POST',
	origin: { file: 'lib/actions/token.ts', line: 42, frame: 'tokenAction' },
	message: 'something broke',
	record
};

const labels = { environment: 'test', instance: 'https://e.ly' };

describe('sentry event projection', () => {
	it('projects exactly the permitted key set', () => {
		const event = projectFault(occurrence, labels);
		expect(Object.keys(event).sort()).toEqual(
			[...PERMITTED_EVENT_KEYS].filter((k) => k !== 'release').sort()
		);
	});

	it('carries the context needed to act on the fault', () => {
		const event = projectFault(occurrence, labels);
		expect(event.at).toEqual(record.at);
		expect(event.surface).toBe('oauth');
		expect(event.route).toBe('/token');
		expect(event.method).toBe('POST');
		expect(event.errorCode).toBe('server_error');
		expect(event.status).toBe(500);
		expect(event.message).toBe('something broke');
		expect(event.fingerprint).toBe('fp-1');
	});

	/* The join key an operator follows from a Sentry alert back to the full internal record. */
	it('carries the reference the caller received', () => {
		expect(projectFault(occurrence, labels).reference).toBe(record.reference);
	});

	/*
	 * Permitted deliberately: OAuth defines the client identifier as non-secret, it travels in the
	 * clear on every authorization request, and it is the axis an operator triages on.
	 */
	it('carries the client identifier when the fault is attributable', () => {
		expect(projectFault(occurrence, labels).clientId).toBe('some-client');
	});

	it('carries null rather than a guess when it is not', () => {
		const event = projectFault(
			{ ...occurrence, record: { ...record, clientId: null } },
			labels
		);
		expect(event.clientId).toBeNull();
	});

	/*
	 * The two exclusions that are requirements rather than tidiness. `actor` is an end-user's id and
	 * email; `userAgent` identifies a device. Neither tells anyone which endpoint is broken.
	 */
	it('excludes the actor', () => {
		const event = projectFault(occurrence, labels);
		expect(event).not.toHaveProperty('actor');
		expect(JSON.stringify(event)).not.toContain('person@example.com');
		expect(JSON.stringify(event)).not.toContain('user-1');
	});

	it('excludes the user agent', () => {
		const event = projectFault(occurrence, labels);
		expect(event).not.toHaveProperty('userAgent');
		expect(JSON.stringify(event)).not.toContain('Mozilla');
	});

	/*
	 * The code location lives on the occurrence and is deliberately not projected: it is not on the
	 * permitted list. Pinned so that adding it becomes a decision someone makes on purpose.
	 */
	it('does not project the internal code location', () => {
		const event = projectFault(occurrence, labels);
		expect(JSON.stringify(event)).not.toContain('tokenAction');
		expect(JSON.stringify(event)).not.toContain('lib/actions/token.ts');
	});

	/* The network origin passes through at whatever level the store already applied, never widened. */
	it('passes the network origin through unchanged', () => {
		expect(projectFault(occurrence, labels).origin).toBe('deadbeefdeadbeef');
		expect(
			projectFault(
				{ ...occurrence, record: { ...record, origin: 'not-captured' } },
				labels
			).origin
		).toBe('not-captured');
	});

	it('carries submitted field names but never values', () => {
		expect(projectFault(occurrence, labels).submittedFields).toEqual([
			'client_id',
			'grant_type'
		]);
	});

	it('carries the environment and instance labels', () => {
		const event = projectFault(occurrence, labels);
		expect(event.environment).toBe('test');
		expect(event.instance).toBe('https://e.ly');
	});

	/* An empty release is omitted, not sent blank — see the client spec for why. */
	it('omits the release when none is configured', () => {
		expect(projectFault(occurrence, labels)).not.toHaveProperty('release');
	});

	it('carries the release when one is configured', () => {
		const event = projectFault(occurrence, { ...labels, release: '2026.09' });
		expect(event.release).toBe('2026.09');
		expect(Object.keys(event).sort()).toEqual([...PERMITTED_EVENT_KEYS].sort());
	});
});
