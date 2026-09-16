import { useState } from 'react';
import { Modal, Alert, Checkbox, Input, Space, Typography } from 'antd';

/*
 * The word an administrator types before a container is destroyed.
 *
 * A fixed word rather than the container's own name: the name is on the screen to be copied, so
 * asking for it tests reading rather than attention, which is the thing this control exists to buy.
 */
export const CONFIRM_WORD = 'delete';

/*
 * Trimmed and compared case-insensitively, decided here and nowhere else so the two screens using
 * this control cannot answer the same keystrokes differently. Trimmed because a trailing space from
 * a paste is not a different intention; case-insensitive because DELETE and delete are one word and
 * refusing one of them teaches an operator nothing.
 */
function typedTheWord(value: string): boolean {
	return value.trim().toLowerCase() === CONFIRM_WORD;
}

export interface CascadeOffer {
	/* What is inside, in the plural, as an operator would say it: "clients", "end-user accounts". */
	readonly noun: string;
	readonly count: number;
	/* Shown when the administrator wants to look before deciding. Omitted where there is nowhere to go. */
	readonly onInspect?: () => void;
	readonly inspectLabel?: string;
}

/*
 * The one destructive-confirmation gesture in this console, shared by the project and bucket screens.
 *
 * Three acts, deliberately separate and deliberately in this order: see what would go, consent to its
 * destruction, then type the word. Collapsing any two of them would let one gesture do the work of
 * two, and the whole point is that destroying a container's contents is never the same motion as
 * agreeing to delete the container.
 *
 * The cascade checkbox is never pre-checked. A default that destroys is a default nobody chose.
 *
 * Deliberately NOT the `Popconfirm` the rest of the console uses for a destructive row action. Those
 * destroy one thing the administrator is pointing at; these two destroy an unbounded number of things
 * they are not.
 */
export function ConfirmDestruction({
	open,
	title,
	consequences,
	cascade,
	busy,
	onCancel,
	onConfirm
}: {
	open: boolean;
	title: string;
	/* What this deletion ends, stated before it happens. One line each. */
	consequences: readonly string[];
	/* Absent when the container is empty, so an empty container never offers to destroy nothing. */
	cascade?: CascadeOffer;
	busy?: boolean;
	onCancel: () => void;
	onConfirm: (withCascade: boolean) => void;
}) {
	const [typed, setTyped] = useState('');
	const [withCascade, setWithCascade] = useState(false);

	function reset() {
		setTyped('');
		setWithCascade(false);
	}

	/*
	 * Blocked while the container holds things the administrator has not consented to destroy: the
	 * request would be refused by the server anyway, and a button that submits a known refusal is a
	 * button that teaches the operator to ignore what the screen says.
	 */
	const blocked = cascade !== undefined && !withCascade;

	return (
		<Modal
			title={title}
			open={open}
			okText={`Delete permanently`}
			okButtonProps={{
				danger: true,
				disabled: blocked || !typedTheWord(typed)
			}}
			confirmLoading={busy}
			onCancel={() => {
				reset();
				onCancel();
			}}
			onOk={() => {
				onConfirm(withCascade);
				reset();
			}}
			destroyOnHidden
		>
			<Space
				direction="vertical"
				size="middle"
				style={{ width: '100%' }}
			>
				<Alert
					type="warning"
					showIcon
					message="This cannot be undone"
					description={
						<ul style={{ margin: 0, paddingInlineStart: 20 }}>
							{consequences.map((line) => (
								<li key={line}>{line}</li>
							))}
						</ul>
					}
				/>

				{cascade ? (
					<Space
						direction="vertical"
						size={4}
						style={{ width: '100%' }}
					>
						<Checkbox
							checked={withCascade}
							onChange={(e) => setWithCascade(e.target.checked)}
						>
							Also destroy the {cascade.count} {cascade.noun} it holds
						</Checkbox>
						{cascade.onInspect ? (
							<Typography.Link
								onClick={() => {
									reset();
									cascade.onInspect?.();
								}}
							>
								{cascade.inspectLabel ?? `Look at them first`}
							</Typography.Link>
						) : null}
						{blocked ? (
							<Typography.Text type="secondary">
								Nothing is deleted while it still holds {cascade.noun}.
							</Typography.Text>
						) : null}
					</Space>
				) : null}

				<Space
					direction="vertical"
					size={4}
					style={{ width: '100%' }}
				>
					<Typography.Text>
						Type <Typography.Text strong>{CONFIRM_WORD}</Typography.Text> to
						confirm
					</Typography.Text>
					{/*
					 * No placeholder holding the word and no default value: a field already containing
					 * the answer is a click with extra steps, which is the one thing this control is
					 * here to prevent.
					 */}
					<Input
						value={typed}
						onChange={(e) => setTyped(e.target.value)}
						autoComplete="off"
					/>
				</Space>
			</Space>
		</Modal>
	);
}
