import { cloneElement, type ReactElement, type ReactNode } from 'react';
import { Space, Typography } from 'antd';

/*
 * The two ways the console answers "may I do this?" (specs/079 US4).
 *
 * No right — the control is not there. The server's `can` says the caller would be refused, and a button
 * that only ever answers 403 teaches an operator that the console's buttons lie.
 *
 * The right, but the thing's state stands in the way — the control is there, disabled, with the reason
 * written beside it. Hidden would leave the operator looking for it; a tooltip alone is missed on touch
 * and by keyboard users.
 */

export function Allowed({
	when,
	children
}: {
	when: boolean | undefined;
	children: ReactNode;
}) {
	return when === true ? <>{children}</> : null;
}

export function Blocked({
	reason,
	children
}: {
	/* Null when nothing stands in the way, so the call site reads the same either way. */
	reason: string | null | undefined;
	children: ReactElement<{ disabled?: boolean }>;
}) {
	if (!reason) return children;
	return (
		<Space
			size={8}
			wrap
		>
			{cloneElement(children, { disabled: true })}
			<Typography.Text type="secondary">{reason}</Typography.Text>
		</Space>
	);
}
