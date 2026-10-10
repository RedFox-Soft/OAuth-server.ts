import { useEffect, useMemo } from 'react';
import { App, Typography } from 'antd';
import type { FormInstance } from 'antd';
import type { AdminErrorBody, RequestResult } from './request.js';

/*
 * How the console reports an outcome, in one place.
 *
 * Through antd's `App` context rather than the static `message`/`notification`/`Modal` functions: those
 * render outside the console's theme and, under the themed `ConfigProvider`, generate runtime CSS the
 * zeroRuntime build exists to avoid. The linter forbids the static functions under lib/admin/ui.
 *
 * - `done` — every committed change says so, in one past-tense sentence naming the object.
 * - `refused` — the server's reason, verbatim: on its field when the refusal names one and the caller
 *   passed the form, otherwise as a message. Never a generic "failed to …".
 * - `fault` — a 5xx with an error reference stays on screen until dismissed, with the reference copyable,
 *   because the reference is what an operator quotes when they ask for help.
 */
export interface Feedback {
	done(text: string): void;
	refused(
		result: { error: AdminErrorBody } | AdminErrorBody,
		form?: FormInstance
	): void;
	fault(error: AdminErrorBody): void;
	/* Any failed request: a fault when the server says it was one, a refusal otherwise. */
	failed(result: RequestResult<unknown>, form?: FormInstance): void;
}

function bodyOf(result: { error: AdminErrorBody } | AdminErrorBody) {
	return 'error' in result && typeof result.error === 'object'
		? result.error
		: (result as AdminErrorBody);
}

export function useFeedback(): Feedback {
	const { message, notification } = App.useApp();
	// Stable for the life of the App context, so a page may list it among an effect's dependencies.
	return useMemo(() => {
		const fault = (error: AdminErrorBody) => {
			const reference = error.error_reference;
			notification.error({
				title: 'Something went wrong on the server',
				description: reference ? (
					<>
						{error.message}{' '}
						<Typography.Text copyable={{ text: reference }}>
							Reference {reference}
						</Typography.Text>
					</>
				) : (
					error.message
				),
				duration: 0
			});
		};
		const refused: Feedback['refused'] = (result, form) => {
			const error = bodyOf(result);
			if (form && error.field) {
				form.setFields([{ name: error.field, errors: [error.message] }]);
				return;
			}
			void message.error(error.message);
		};
		return {
			done: (text) => void message.success(text),
			refused,
			fault,
			failed: (result, form) => {
				if (result.ok) return;
				if (result.status >= 500 || result.error.error_reference) {
					fault(result.error);
					return;
				}
				refused(result, form);
			}
		};
	}, [message, notification]);
}

/*
 * For code that runs outside React — the unhandled-rejection report in adminClient.tsx — and so cannot
 * call a hook. A provider inside the tree fills it in once mounted.
 */
let bridge: Feedback | null = null;

export function FeedbackBridge() {
	const feedback = useFeedback();
	useEffect(() => {
		bridge = feedback;
		return () => {
			bridge = null;
		};
	}, [feedback]);
	return null;
}

export function reportOutsideReact(text: string): void {
	bridge?.refused({ error: 'client', message: text });
}
