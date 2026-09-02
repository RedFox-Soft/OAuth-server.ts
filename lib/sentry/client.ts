import * as Sentry from '@sentry/bun';
import type { BunOptions, ErrorEvent, EventHint } from '@sentry/bun';

import { ApplicationConfig } from '../configs/application.js';
import { eventLabels } from './labels.js';
import { recordingTransport } from './transport.js';

/*
 * The client, armed with every automatic behaviour switched off.
 *
 * `defaultIntegrations: false` is the load-bearing option, not a precaution. The Bun SDK's defaults
 * include HTTP instrumentation (which would put code on the request path and add headers to
 * responses), uncaught-exception and unhandled-rejection handlers (which would report faults that
 * never passed this server's own classification), and request-data capture (which would attach the
 * URL and headers this server must never send). Every one of those breaks a requirement, so the
 * whole set is refused rather than pruned: an allowlist of "harmless" integrations would need
 * re-reviewing on every SDK upgrade, because behaviour can move into one we had judged harmless.
 *
 * `initWithoutDefaultIntegrations` in the SDK is equivalent, but the option is kept explicit in the
 * object so the guard spec has something to read.
 *
 * This is the only place a client is created, and nothing here touches Elysia. The module registers
 * no lifecycle hook, so there is no code on the request path that could add a header, add latency,
 * or fail — which is what makes the "responses are unchanged" requirement true by construction
 * rather than by measurement.
 */
let armed = false;

/*
 * The last options used to arm the client, kept for the guard spec.
 *
 * Read back rather than re-derived: a spec that rebuilt the options it expects would pass while the
 * real init drifted away from them, which is the exact class of bug this module cannot afford.
 */
let lastOptions: BunOptions | undefined;

export function isArmed(): boolean {
	return armed;
}

export function initOptionsForTest(): BunOptions | undefined {
	return lastOptions;
}

export function resetForTest(): void {
	armed = false;
	lastOptions = undefined;
}

/*
 * Strips anything the SDK attached on its own.
 *
 * Defence in depth, not the primary mechanism: the event is assembled from a named list of permitted
 * fields, so these slots are empty already. They are cleared anyway because the SDK owns the event
 * on the way out and a future version could populate them — and the cost of being wrong here is a
 * credential in someone else's system, which is not a risk worth carrying for the sake of trusting
 * an upstream default.
 */
function stripSdkAttachments(event: ErrorEvent, _hint: EventHint): ErrorEvent {
	delete event.request;
	delete event.user;
	if (event.contexts) {
		delete event.contexts.response;
	}
	return event;
}

/*
 * Under the test runner, the transport that sends nothing — always, not when a spec remembers to ask.
 *
 * The requirement is that the default test run attempt no outbound delivery *regardless of the
 * configuration present in the test environment*, and a per-spec opt-in cannot deliver that: one
 * spec that switches the capability on without the harness would start talking to the network, and
 * the first sign of it would be a slow suite or someone else's Sentry project filling with test
 * faults. Deciding it here makes the guarantee independent of test discipline.
 *
 * NODE_ENV is set to 'test' by `bun test` itself, so this cannot be lost by a missing .env.
 */
function transportFor(): BunOptions['transport'] {
	return process.env.NODE_ENV === 'test' ? recordingTransport : undefined;
}

/*
 * Arms the client if the capability is on and a usable credential is configured.
 *
 * Idempotent, and it never throws. A malformed credential is already a configuration error refused
 * at boot by checkSentry, so anything reaching here and failing is unexpected — and an unexpected
 * failure in the monitoring channel must not be the thing that stops the server from starting.
 */
export function initSentry(): void {
	if (armed || !ApplicationConfig['sentry.enabled']) {
		return;
	}

	const dsn = ApplicationConfig['sentry.dsn'].trim();
	if (!dsn) {
		return;
	}

	const labels = eventLabels();
	const options: BunOptions = {
		dsn,
		environment: labels.environment,
		/*
		 * Omitted rather than sent empty when absent. An empty release label is not "no release" to
		 * Sentry — it is a release named "", which groups every unlabelled deployment together.
		 */
		...(labels.release ? { release: labels.release } : {}),
		serverName: labels.instance,
		defaultIntegrations: false,
		integrations: [],
		beforeSend: stripSdkAttachments,
		transport: transportFor()
	};

	try {
		Sentry.init(options);
		armed = true;
		lastOptions = options;
	} catch (error) {
		console.error('sentry integration could not be armed:', error);
	}
}
