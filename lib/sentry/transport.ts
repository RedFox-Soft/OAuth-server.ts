import type { Envelope } from '@sentry/core';

/*
 * A transport that keeps envelopes instead of sending them.
 *
 * The default test run must attempt no outbound delivery, and must still be able to see exactly what
 * *would* have been delivered — otherwise "no event carries a secret" is an assertion nobody can
 * make, and the data-protection guarantees rest on review rather than on tests.
 *
 * Replacing the transport is what buys that, rather than a `beforeSend` returning null: beforeSend
 * observes the event but still leaves the network path armed, and it cannot demonstrate that
 * *nothing* was attempted. Here there is no fetch to make.
 */
const envelopes: Envelope[] = [];

/* What would have been delivered, in dispatch order. */
export function recordedEnvelopes(): Envelope[] {
	return [...envelopes];
}

export function clearRecorded(): void {
	envelopes.length = 0;
}

/*
 * Answers as a healthy Sentry ingest endpoint would: an accepted status and no rate-limit headers.
 * A transport that reported failure would exercise the SDK's retry bookkeeping on every test, which
 * is not what any of them are about.
 */
export function recordingTransport() {
	return {
		send(envelope: Envelope) {
			envelopes.push(envelope);
			return Promise.resolve({
				statusCode: 200,
				headers: { 'x-sentry-rate-limits': null, 'retry-after': null }
			});
		},
		flush() {
			return Promise.resolve(true);
		}
	};
}
