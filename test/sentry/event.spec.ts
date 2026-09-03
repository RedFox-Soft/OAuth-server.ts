import { describe, it, expect } from 'bun:test';

import type { ErrorOccurrence, ErrorRecord } from 'lib/adapters/types.ts';
import { projectFault, unpermittedKeys } from 'lib/sentry/event.ts';
import {
	PERMITTED_EVENT_KEYS,
	PERMITTED_LOCATION_KEYS,
	type SentryFailureEvent
} from 'lib/sentry/types.ts';

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
	 * Copied, not rebuilt. A projection that reformatted the location could widen it — an untruncated
	 * path, a re-derived frame — and the whole point of taking the record's value is that the record's
	 * value is the one already known to carry no request data.
	 */
	it('projects the internal code location verbatim', () => {
		const event = projectFault(occurrence, labels);
		expect(event.codeLocation).toEqual(occurrence.origin);
	});

	/*
	 * The inner list, asserted the same way as the outer one and for the same reason. Without this the
	 * permitted-key guarantee would stop at `codeLocation`'s boundary, and a field added inside it
	 * later would reach a third party with nothing failing.
	 */
	it('projects exactly the permitted location key set', () => {
		const event = projectFault(occurrence, labels);
		expect(Object.keys(event.codeLocation).sort()).toEqual(
			[...PERMITTED_LOCATION_KEYS].sort()
		);
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

/*
 * The guard, exercised directly rather than only through the projection.
 *
 * The projection cannot produce a forbidden key, so going through it would prove nothing about the
 * guard — every case below has to be constructed by hand, which is exactly the situation the guard
 * exists for: an event that came from somewhere other than `projectFault`.
 */
describe('sentry permitted-key guard', () => {
	it('accepts a conformant event', () => {
		expect(unpermittedKeys(projectFault(occurrence, labels))).toEqual([]);
	});

	it('names a forbidden top-level field', () => {
		const event = {
			...projectFault(occurrence, labels),
			userAgent: 'Mozilla/5.0'
		} as unknown as SentryFailureEvent;
		expect(unpermittedKeys(event)).toEqual(['userAgent']);
	});

	/*
	 * The case the inner list was added for. A subset check at the top level would pass this event
	 * happily, because `codeLocation` is itself permitted — the offence is inside it.
	 */
	it('names a forbidden field inside the code location', () => {
		const event = {
			...projectFault(occurrence, labels),
			codeLocation: {
				file: 'lib/actions/token.ts',
				line: 42,
				frame: 'tokenAction',
				requestId: 'req-1'
			}
		} as unknown as SentryFailureEvent;
		expect(unpermittedKeys(event)).toEqual(['codeLocation.requestId']);
	});

	it('reports the offending path, not just the offending name', () => {
		const event = {
			...projectFault(occurrence, labels),
			codeLocation: { file: 'f', line: 1, frame: 'x', stack: 'at ...' }
		} as unknown as SentryFailureEvent;
		/* `codeLocation.stack`, never a bare `stack` — the reader needs to know where to look. */
		expect(unpermittedKeys(event)).toEqual(['codeLocation.stack']);
	});

	/*
	 * Absent is an offence, not a pass. An event without a location did not come from the projection,
	 * and unknown provenance is the thing being refused.
	 */
	it('refuses an event whose code location is missing', () => {
		const { codeLocation: _dropped, ...rest } = projectFault(
			occurrence,
			labels
		);
		expect(unpermittedKeys(rest as SentryFailureEvent)).toEqual([
			'codeLocation'
		]);
	});

	it('refuses an event whose code location is not an object', () => {
		const event = {
			...projectFault(occurrence, labels),
			codeLocation: 'lib/actions/token.ts:42'
		} as unknown as SentryFailureEvent;
		expect(unpermittedKeys(event)).toEqual(['codeLocation']);
	});

	it('reports offences at both levels together', () => {
		const event = {
			...projectFault(occurrence, labels),
			actor: { id: 'user-1' },
			codeLocation: { file: 'f', line: 1, frame: 'x', secret: 'shh' }
		} as unknown as SentryFailureEvent;
		expect(unpermittedKeys(event).sort()).toEqual([
			'actor',
			'codeLocation.secret'
		]);
	});
});
