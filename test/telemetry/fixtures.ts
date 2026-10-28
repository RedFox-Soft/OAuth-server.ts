import { spyOn } from 'bun:test';

import { agent, seedBucket } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { fetchAnswering } from '../fetch_mock.ts';
import { setClockForTests } from 'lib/telemetry/clock.ts';
import { setClockForTests as setActivityClock } from 'lib/activity/clock.ts';
import { TELEMETRY_DESTINATION } from 'lib/consts/telemetry_fields.ts';
import { reportPass } from 'lib/telemetry/scheduler.ts';
import { sendReport } from 'lib/telemetry/send.ts';

/*
 * A receiver standing in for FoxTrust: the bodies it was sent, in order, and how many requests reached it.
 * Answers `status` until told otherwise. Requests anywhere else fail, as the real network is never reached.
 */
export function receiver(status = 204) {
	const state = { status, bodies: [] as unknown[], requests: 0 };
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(async (input, init) => {
			const url = input instanceof Request ? input.url : String(input);
			if (url !== TELEMETRY_DESTINATION) {
				throw new TypeError(`unexpected request to ${url}`);
			}
			state.requests += 1;
			state.bodies.push(
				JSON.parse(typeof init?.body === 'string' ? init.body : 'null')
			);
			return new Response(null, { status: state.status });
		})
	);
	return state;
}

/* A destination that never answers: the request ends only when its own signal aborts it. */
export function hangingReceiver() {
	const state = { requests: 0 };
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(
			(_input, init) =>
				new Promise<Response>((_resolve, reject) => {
					state.requests += 1;
					init?.signal?.addEventListener('abort', () =>
						reject(new Error('aborted by its own signal'))
					);
				})
		)
	);
	return state;
}

/* Moves the reporting clock and the activity clock to `iso` together; answers the undo. */
export function onDay(iso: string): () => void {
	const at = new Date(iso);
	const undoReporting = setClockForTests(() => at);
	const undoActivity = setActivityClock(() => at);
	return () => {
		undoActivity();
		undoReporting();
	};
}

/* One pass at `iso`, past any report slot of that day, sending with `send`. */
export async function passOn(
	iso: string,
	send: typeof sendReport = sendReport
): Promise<void> {
	const undo = onDay(iso);
	try {
		await reportPass(new Date(iso), send, { ignoreSlot: true });
	} finally {
		undo();
	}
}

export async function issueMachineTokens(count: number): Promise<void> {
	for (let i = 0; i < count; i += 1) {
		const { status } = await agent.token.post(
			{ grant_type: 'client_credentials', scope: 'api:read' },
			{
				headers: AuthorizationRequest.basicAuthHeader(
					'tele-machine',
					'tele-secret'
				)
			}
		);
		if (status !== 200) throw new Error(`token request answered ${status}`);
	}
}

/* `count` machine tokens issued at `iso`, as far as the day counters can tell. */
export async function issueOn(iso: string, count: number): Promise<void> {
	const undo = onDay(iso);
	try {
		await issueMachineTokens(count);
	} finally {
		undo();
	}
}

/*
 * Strings a report must never carry: a project's name and address, an application id, an end user's
 * subject and email. Each is long and odd enough that finding it anywhere in a body can only mean a leak.
 */
export const DISTINCTIVE = {
	projectName: 'Zebrafinch Holdings Project',
	projectSlug: 'zebrafinch-slug',
	clientId: 'zebrafinch-app-7c1d',
	accountId: 'zebrafinch-subject-90af',
	email: 'zebrafinch.person@zebrafinch-mail.example'
} as const;

export async function seedDistinctiveProject(): Promise<void> {
	await seedBucket({
		bucketId: 'zebrafinch-bucket',
		name: DISTINCTIVE.projectName,
		slug: DISTINCTIVE.projectSlug,
		clientId: DISTINCTIVE.clientId,
		accountId: DISTINCTIVE.accountId,
		user: { email: DISTINCTIVE.email }
	});
}
