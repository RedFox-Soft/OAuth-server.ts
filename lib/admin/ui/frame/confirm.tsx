import { useCallback } from 'react';
import { App, Typography } from 'antd';
import { ACTIONS, type ActionId, type ActionSpec } from './actions.js';

/*
 * The C0–C2 confirmations (actions.ts), asked the same way everywhere.
 *
 * C0 answers yes at once, so a caller never decides for itself whether to ask: it names the action and
 * the table decides. C1 is a plain question. C2 is a danger question with Cancel focused, so Enter
 * after a slip of the mouse keeps things as they were, and the consequences are listed rather than
 * implied. C3 and C4 are dialogs of their own (ConfirmDestruction, PreviewConfirm) and are refused here.
 *
 * Never two confirmations stacked: a second request while one is open is answered no, so a double
 * click cannot queue a second question behind the first.
 */
export interface ConfirmOptions {
	/* What is acted on, as the operator knows it: a name, an email, a key id. */
	target: string;
	/* What the act ends or changes, one line each, with counts where there are any. */
	consequences?: readonly string[];
}

export function useConfirm(): (
	action: ActionId,
	options: ConfirmOptions
) => Promise<boolean> {
	const { modal } = App.useApp();
	return useCallback(
		(action, { target, consequences }) => {
			const spec: ActionSpec = ACTIONS[action];
			if (spec.class === 'C0') return Promise.resolve(true);
			if (spec.class !== 'C1' && spec.class !== 'C2') {
				throw new Error(
					`${action} is ${spec.class}: use its own dialog, not useConfirm`
				);
			}
			if (document.querySelector('.ant-modal-confirm')) {
				return Promise.resolve(false);
			}
			const danger = spec.class === 'C2';
			return new Promise<boolean>((resolve) => {
				modal.confirm({
					title: spec.title ? spec.title(target) : `${action}?`,
					content:
						consequences && consequences.length > 0 ? (
							<ul style={{ margin: 0, paddingLeft: 20 }}>
								{consequences.map((line) => (
									<li key={line}>
										<Typography.Text>{line}</Typography.Text>
									</li>
								))}
							</ul>
						) : undefined,
					okText: spec.okText ?? 'Confirm',
					okButtonProps: danger ? { danger: true } : undefined,
					cancelText: 'Cancel',
					focusable: { autoFocusButton: danger ? 'cancel' : 'ok' },
					onOk: () => {
						resolve(true);
					},
					onCancel: () => {
						resolve(false);
					}
				});
			});
		},
		[modal]
	);
}
