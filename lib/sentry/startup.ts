import { captureEvent, flush } from '@sentry/bun';

import { ApplicationConfig } from '../configs/application.js';
import { initSentry, isArmed } from './client.js';
import { eventLabels } from './labels.js';
import type { SentryStartupEvent } from './types.js';

/*
 * The one exception to "every outbound event comes from an internal error record".
 *
 * A failure that stops the server starting cannot be recorded internally, because the store it would
 * be written to does not exist yet. Leaving it unreported would mean the single worst incident — a
 * server that will not boot — is also the only one nobody is told about, so it is reported over this
 * path instead, and this path is deliberately the only exception there is.
 *
 * It carries no request data because there is no request. No reference identifier either: there is
 * no record for one to point at, and inventing one would produce an alert whose join key resolves to
 * nothing.
 */
function projectStartup(kind: string, phase: string): SentryStartupEvent {
	const labels = eventLabels();
	return {
		kind,
		phase,
		environment: labels.environment,
		instance: labels.instance,
		...(labels.release ? { release: labels.release } : {})
	};
}

/*
 * Reports a startup failure, best-effort and bounded.
 *
 * Resolves whether or not delivery succeeded, and never throws. Startup failure behaviour must be
 * exactly what it was before this feature existed: the server still fails, still says what it said,
 * and still exits the way it did. The short flush bound follows the shutdown drain's reasoning — a
 * boot that hangs waiting on a monitoring endpoint is worse than one that fails promptly and loses
 * the notification.
 */
export async function reportStartupFailure(
	kind: string,
	phase: string,
	timeoutMs = 2000
): Promise<void> {
	if (!ApplicationConfig['sentry.enabled']) {
		return;
	}

	try {
		initSentry();
		if (!isArmed()) {
			return;
		}

		const event = projectStartup(kind, phase);
		captureEvent({
			message: `startup failed during ${event.phase}: ${event.kind}`,
			level: 'fatal',
			environment: event.environment,
			server_name: event.instance,
			...(event.release ? { release: event.release } : {}),
			tags: { kind: event.kind, phase: event.phase, startup: 'true' }
		});

		await Promise.race([
			flush(timeoutMs),
			new Promise<void>((resolve) => {
				setTimeout(resolve, timeoutMs).unref?.();
			})
		]);
	} catch (error) {
		console.error(
			'sentry integration could not report a startup failure:',
			error
		);
	}
}
