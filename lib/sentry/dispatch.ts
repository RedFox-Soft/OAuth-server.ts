import { captureEvent } from '@sentry/bun';

import type { ErrorOccurrence } from '../adapters/types.js';
import { ApplicationConfig } from '../configs/application.js';
import { initSentry, isArmed } from './client.js';
import { projectFault, unpermittedKeys } from './event.js';
import { eventLabels } from './labels.js';
import type { SentryFailureEvent } from './types.js';

/*
 * The outbound path: project, queue, and return.
 *
 * Reporting must not delay a response and a monitoring outage must not become a second failure the
 * caller sees, so the send cannot be awaited on the fault path. A queue is also the only shape that
 * makes the loss window *stated* rather than unbounded: a process killed abruptly loses at most
 * SENTRY_QUEUE_DEPTH events, and a full queue counts what it could not accept instead of growing.
 *
 * Structurally the same as lib/error_store/queue.ts, and separate from it on purpose. Sharing one
 * queue would let a stalled third party consume the depth the durable local write needs and delay its
 * drain — which would inverct the priority the requirement sets: the local record comes first.
 */
/*
 * The outbound bound, a constant rather than a setting — and deliberately unlike
 * `errorStore.queueDepth`, which is one.
 *
 * The asymmetry is the point. The store's depth bounds loss of the *only* copy of a fault, which is a
 * retention decision an operator can reasonably have an opinion about. This bounds loss of the
 * *second* copy: every event dropped here is a fault still recorded locally and still reachable in
 * the console, so it costs an alert rather than data.
 *
 * Nor is there a question an operator could answer to set it. Choosing a value needs the fault rate
 * measured against the destination's ingest latency, which nobody has — so the setting would sit at
 * its default forever, and a setting that does nothing is worse than its absence (the same reasoning
 * that removed `errorStore.mcpPurgeEnabled`).
 *
 * In practice the queue barely fills at all: the drain runs on a microtask and the send is
 * synchronous, so it empties between any two awaited requests. This is a rail against a pathological
 * burst inside one tick, not a throughput knob. The admin card reports it read-only.
 */
export const SENTRY_QUEUE_DEPTH = 500;

const pending: SentryFailureEvent[] = [];
let flushing = false;
let dropped = 0;
let refused = 0;
let drainInstalled = false;

/*
 * Events the queue could not accept since this process started. Non-zero means Sentry is missing
 * faults that really happened and were recorded locally — a caveat an operator needs stated rather
 * than left to infer from a quiet dashboard.
 */
export function droppedCount(): number {
	return dropped;
}

/* Events refused by the permitted-key check rather than by the bound. Should always be zero. */
export function refusedCount(): number {
	return refused;
}

/* Test seam: forget the queue's state between cases. */
export function resetForTest(): void {
	pending.length = 0;
	dropped = 0;
	refused = 0;
	flushing = false;
}

async function drainOnce(): Promise<void> {
	if (flushing) {
		return;
	}
	flushing = true;
	try {
		while (pending.length > 0) {
			const event = pending.shift();
			if (!event) {
				break;
			}
			try {
				send(event);
			} catch (error) {
				/*
				 * Reported here and nowhere else. The request that produced the fault was answered long
				 * ago, so there is no caller to tell, and re-throwing would turn a monitoring problem into
				 * an unhandled rejection. Deliberately not routed back through the error store: recording a
				 * fault about failing to report a fault is the recursion this whole path must not start.
				 */
				console.error('sentry integration could not send an event:', error);
			}
		}
	} finally {
		flushing = false;
	}
}

/*
 * The line an operator reads beneath the headline, and the reason two faults on one endpoint can be
 * told apart at a glance.
 *
 * Built from the method, the route pattern and the code location, and from nothing else — so it is
 * identical for every occurrence in a group. That determinism is what makes it readable as an
 * identity: the headline moves with the message, this does not. A concrete path here would produce
 * one line per identifier that ever hit the endpoint, which is the failure the route *pattern* exists
 * to avoid.
 *
 * Degrades rather than disappearing, because the faults hardest to place are the ones an operator
 * most needs to be able to read.
 */
function locatorOf(event: SentryFailureEvent): string {
	const endpoint = `${event.method} ${event.route}`;
	const { file, line, frame } = event.codeLocation;

	if (file === 'unknown') {
		return `${endpoint} (unknown)`;
	}

	const at = line === null ? file : `${file}:${line}`;
	/*
	 * The parser sets `frame` to the file when it could not read a function name. Printing it anyway
	 * would present a filename as a function that exists in the source — a false claim about the code,
	 * and a confusing one to act on.
	 */
	return frame === file
		? `${endpoint} (${at})`
		: `${endpoint} ${frame} (${at})`;
}

/*
 * The title. The diagnostic message, which is what actually distinguishes one fault from another.
 *
 * It used to be `errorCode method route`, identical for every fault on an endpoint, while the message
 * sat in a context object nobody reads without opening the alert. The message may interpolate request
 * values and so may vary between occurrences of one group; that is tolerable here and nowhere else,
 * because grouping is pinned by the fingerprint and because the message already left this server as
 * `contexts.fault.detail`. It is not licence to put anything further from the request in this string.
 */
function headlineOf(event: SentryFailureEvent): string {
	const detail = event.message.trim();
	/*
	 * A blank message would leave nothing at all to read, which is worse than the identical titles
	 * this replaced. Falls back to the format that shipped before.
	 */
	return detail
		? `${event.errorCode}: ${detail}`
		: `${event.errorCode} ${event.method} ${event.route}`;
}

/*
 * Hands one event to the SDK.
 *
 * The mapping is the contract. `fingerprint` is set so Sentry groups exactly as the store does, the
 * searchable identifiers become tags, and everything else rides in one context object. The `request`
 * slot is never populated — the SDK offers one, and leaving it empty is what keeps the request URL,
 * headers and body out of the event.
 *
 * `message` and `transaction` are inputs to nothing but presentation: a client-supplied `fingerprint`
 * with no `{{ default }}` suppresses the destination's own grouping algorithm entirely, so how these
 * two read cannot split a group, merge two, or reorder anything.
 */
function send(event: SentryFailureEvent): void {
	captureEvent({
		message: headlineOf(event),
		level: 'error',
		timestamp: event.at.getTime() / 1000,
		fingerprint: [event.fingerprint],
		transaction: locatorOf(event),
		environment: event.environment,
		server_name: event.instance,
		...(event.release ? { release: event.release } : {}),
		tags: {
			reference: event.reference,
			surface: event.surface,
			errorCode: event.errorCode,
			route: event.route,
			method: event.method,
			status: String(event.status),
			/*
			 * The file alone, so an operator can ask "what is wrong in this part of the server?" — the
			 * question a per-fault view cannot answer. Sent verbatim, including the literal 'unknown',
			 * because an absent tag would leave unplaceable faults unfilterable as a set.
			 *
			 * Not the line or the function. A tag's cost is cardinality, filtering to one line is what
			 * the group already is, and both stay readable in the locator and the fault context.
			 */
			codeFile: event.codeLocation.file,
			/* Omitted rather than sent as the string "null" when the fault has no client. */
			...(event.clientId ? { clientId: event.clientId } : {})
		},
		contexts: {
			fault: {
				detail: event.message,
				origin: event.origin,
				/*
				 * Structured, not the rendered string the transaction carries. The two are for different
				 * jobs: the transaction is scanned in a list, this is read while acting on one fault, and
				 * a reader following it back to source wants the line as a number rather than as text
				 * they have to pick out of a sentence.
				 */
				codeLocation: event.codeLocation,
				submittedFields: event.submittedFields
			}
		}
	});
}

/*
 * Schedules a drain without awaiting it. Deliberately not on a timer: a timer keeps the test process
 * alive and fires between unrelated specs — the same reason the error store's queue schedules on a
 * microtask instead.
 */
function scheduleDrain(): void {
	queueMicrotask(() => {
		void drainOnce();
	});
}

/*
 * Flushes what is queued, bounded in time.
 *
 * The bound is a requirement rather than caution: a destination that has stopped answering must not
 * hold the process open. A shutdown that hangs is worse than one that loses the tail, because the
 * events are lost either way and the second at least ends.
 */
export async function drainForShutdown(timeoutMs = 2000): Promise<void> {
	await Promise.race([
		drainOnce(),
		new Promise<void>((resolve) => {
			setTimeout(resolve, timeoutMs).unref?.();
		})
	]);
}

/*
 * Installs the shutdown drain once.
 *
 * Idempotent because it must be: the test suite imports the app repeatedly within one process, so
 * registering per import would accumulate listeners until the runtime warned about a leak. `once`
 * rather than `on`, so a second signal cannot start a second drain.
 */
function installShutdownDrain(): void {
	if (drainInstalled) {
		return;
	}
	drainInstalled = true;
	for (const signal of ['SIGTERM', 'SIGINT'] as const) {
		process.once(signal, () => {
			void drainForShutdown();
		});
	}
}

/*
 * Accepts one recorded fault for reporting. Never throws, never awaits.
 *
 * The caller is inside the error store's record continuation, one step after the durable write was
 * accepted — so by the time this runs the fault is already recorded locally, which is what makes
 * "an additional destination, never an alternative" true by construction rather than by policy.
 *
 * Reads its configuration flat per call rather than at boot, matching the capture path it is called
 * from: a deployment applies settings by restart, but the suite drives one long-lived instance and
 * flips them between cases.
 */
export function reportFault(occurrence: ErrorOccurrence): void {
	if (!ApplicationConfig['sentry.enabled']) {
		return;
	}

	try {
		initSentry();
		if (!isArmed()) {
			return;
		}
		installShutdownDrain();

		const event = projectFault(occurrence, eventLabels());

		/*
		 * Refused rather than scrubbed and sent. The projection cannot produce a forbidden key today,
		 * so reaching this branch means something changed upstream — and in that case dropping the
		 * event is the safe answer: an unsent event costs an operator one alert, a wrongly sent one
		 * puts credential material in somebody else's system.
		 */
		const unpermitted = unpermittedKeys(event);
		if (unpermitted.length > 0) {
			refused += 1;
			console.error(
				'sentry integration refused an event carrying unpermitted fields:',
				unpermitted.join(', ')
			);
			return;
		}

		if (pending.length >= SENTRY_QUEUE_DEPTH) {
			// Counted, not blocked and not silently discarded, so an operator can see that reporting
			// fell behind rather than reading a quiet dashboard as "nothing is wrong".
			dropped += 1;
			/*
			 * Said once, on the first drop, rather than on every one. A queue overflowing is exactly the
			 * moment an error storm is underway, and a line per dropped event would turn the monitoring
			 * channel's own back-pressure into a second flood in the log an operator is trying to read.
			 * The count stays exact either way, and `droppedCount()` reports it.
			 */
			if (dropped === 1) {
				console.error(
					`sentry integration queue is full at ${SENTRY_QUEUE_DEPTH} events; further faults are recorded locally but not reported until it drains`
				);
			}
			return;
		}

		pending.push(event);
		scheduleDrain();
	} catch (error) {
		console.error('sentry integration could not queue an event:', error);
	}
}

/* Test seam: await the queue reaching empty, so a spec need not poll. */
export async function flushForTest(): Promise<void> {
	await drainOnce();
}
