import { packageVersion } from '../helpers/package_version.js';
import { TELEMETRY_DESTINATION } from '../consts/telemetry_fields.js';

export const SEND_TIMEOUT_MS = 10_000;

/*
 * One attempt to deliver a report; true only when the receiver accepted it with a 2xx.
 *
 * Everything else — a refusal, a redirect, an unresolvable host, a timeout — is false and nothing more: no
 * log line, no captured fault, no retry. The owner's decision (2026-10-28) is that a report which cannot be
 * delivered is not an error, so an air-gapped server must look exactly like one that reported. Redirects
 * are not followed because the destination is fixed; a redirect means it is not the receiver answering.
 */
export async function sendReport(
	report: unknown,
	url: string = TELEMETRY_DESTINATION,
	timeoutMs: number = SEND_TIMEOUT_MS
): Promise<boolean> {
	const version = packageVersion();
	try {
		const response = await fetch(url, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				'user-agent': version === undefined ? 'FoxAuth' : `FoxAuth/${version}`
			},
			body: JSON.stringify(report),
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs)
		});
		return response.status >= 200 && response.status < 300;
	} catch {
		return false;
	}
}
