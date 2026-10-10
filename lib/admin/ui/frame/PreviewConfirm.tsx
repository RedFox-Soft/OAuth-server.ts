import { useState, type ReactNode } from 'react';
import { Modal } from 'antd';
import { useFeedback } from './feedback.js';
import type { RequestResult } from './request.js';

/*
 * The C4 confirmation (actions.ts): the server says what the act would touch, then the operator agrees.
 *
 * Used where only the server holds the full list — what moves with a bucket, how many faults a purge
 * removes. The first step asks for the preview, the second commits; changing the input drops the preview,
 * so the operator never commits on a list computed for something else.
 *
 * `step(false)` asks; `step(true)` commits. The caller maps its endpoint's answers onto the three outcomes
 * because the endpoints differ: a move answers its preview as a 409 `confirmationRequired`, a purge has a
 * preview route of its own.
 */
export type PreviewStep<P> =
	| { kind: 'preview'; preview: P }
	| { kind: 'done'; text: string }
	| { kind: 'failed'; result: RequestResult<unknown> };

export function PreviewConfirm<P>({
	open,
	title,
	nextText = 'Next',
	commitText,
	danger = false,
	ready = true,
	preview,
	onPreview,
	step,
	renderPreview,
	onClose,
	onDone,
	children
}: {
	open: boolean;
	title: string;
	nextText?: string;
	commitText: string;
	/* The commit destroys something (a purge), so its button is red. */
	danger?: boolean;
	/* False while the input the preview depends on is incomplete. */
	ready?: boolean;
	/* Held by the caller, so the caller can drop it when its input changes. */
	preview: P | null;
	onPreview: (preview: P | null) => void;
	step: (commit: boolean) => Promise<PreviewStep<P>>;
	renderPreview: (preview: P) => ReactNode;
	onClose: () => void;
	onDone: () => void;
	children?: ReactNode;
}) {
	const [busy, setBusy] = useState(false);
	const feedback = useFeedback();

	async function advance() {
		setBusy(true);
		const outcome = await step(preview !== null);
		setBusy(false);
		if (outcome.kind === 'preview') {
			onPreview(outcome.preview);
			return;
		}
		if (outcome.kind === 'failed') {
			feedback.failed(outcome.result);
			return;
		}
		feedback.done(outcome.text);
		onPreview(null);
		onDone();
	}

	return (
		<Modal
			open={open}
			title={title}
			okText={preview === null ? nextText : commitText}
			okButtonProps={{ disabled: !ready, danger: danger && preview !== null }}
			confirmLoading={busy}
			onOk={() => void advance()}
			onCancel={() => {
				onPreview(null);
				onClose();
			}}
			destroyOnHidden
		>
			{children}
			{preview !== null && renderPreview(preview)}
		</Modal>
	);
}
