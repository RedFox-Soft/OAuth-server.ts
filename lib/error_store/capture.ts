import { ApplicationConfig } from '../configs/application.js';
import type {
	ErrorStoreBounds,
	ErrorSurface,
	OriginCaptureLevel
} from '../adapters/types.js';
import { faultMessage, fingerprintOf, parseOrigin } from './fingerprint.js';
import { mintReference } from './reference.js';
import { buildRecord, type CaptureSubject } from './redact.js';
import { enqueue, installShutdownDrain } from './queue.js';

/*
 * The one place a fault becomes a record.
 *
 * Only unexpected internal faults are recorded. A routine client rejection — a bad grant, a wrong
 * password, an expired code, a request that fails validation — is correct behaviour, not a defect, and
 * recording it would bury the defects among traffic. That is the same judgement the global error
 * handler already makes when it declines to report a gate refusal on the channel operators watch for
 * genuine faults.
 *
 * Reads configuration flat per call rather than capturing it at boot, matching featureGate: settings
 * are applied by restart in a deployment, but the test suite drives one long-lived instance and flips
 * them between cases.
 */
export interface CaptureInput extends CaptureSubject {
	surface: ErrorSurface;
	route: string;
	method: string;
	status: number;
	errorCode: string;
	error: unknown;
}

function boundsFromConfig(): ErrorStoreBounds {
	return {
		retentionDays: ApplicationConfig['errorStore.retentionDays'],
		maxGroups: ApplicationConfig['errorStore.maxGroups'],
		samplesPerGroup: ApplicationConfig['errorStore.samplesPerGroup']
	};
}

/*
 * Guards against a fault raised while recording a fault.
 *
 * Without it, an error thrown inside this module would reach the handler that called it, be classified
 * as a new internal fault, and be captured again — recursing until the stack gave out, on the one code
 * path whose entire job is to not make things worse.
 */
let capturing = false;

/*
 * Records a fault, if the capability is on and the fault is one this store is for. Returns the
 * reference to attach to the response, or undefined when nothing was recorded — which is what makes
 * "only recorded faults carry a reference" true by construction rather than by remembering to check.
 */
export function captureFault(input: CaptureInput): string | undefined {
	if (!ApplicationConfig['errorStore.enabled'] || capturing) {
		return undefined;
	}

	capturing = true;
	try {
		installShutdownDrain();

		const origin = parseOrigin(input.error);
		const reference = mintReference();
		const fingerprint = fingerprintOf({
			errorCode: input.errorCode,
			surface: input.surface,
			route: input.route,
			method: input.method,
			origin
		});
		const level = ApplicationConfig[
			'errorStore.originCaptureLevel'
		] as OriginCaptureLevel;
		const bounds = boundsFromConfig();
		const queueDepth = ApplicationConfig['errorStore.queueDepth'];

		/*
		 * The record is assembled asynchronously — the anonymized origin needs the deployment's key,
		 * which may not be resolved yet — but nothing here is awaited: the caller is an error handler on
		 * its way to answering a request. The reference is minted above, synchronously, so it can be
		 * returned now and the record that carries it can be built a microtask later.
		 */
		void buildRecord(input, reference, level)
			.then((record) => {
				enqueue(
					{
						fingerprint,
						errorCode: input.errorCode,
						status: input.status,
						surface: input.surface,
						route: input.route,
						method: input.method,
						origin,
						message: faultMessage(input.error),
						record
					},
					bounds,
					queueDepth
				);
			})
			.catch((error) => {
				// Assembling a record failed, which is not the caller's problem and must not become an
				// unhandled rejection. The console is the fallback the server used before this feature.
				console.error('error store could not assemble a record:', error);
			});

		return reference;
	} catch (error) {
		console.error('error store capture failed:', error);
		return undefined;
	} finally {
		capturing = false;
	}
}
