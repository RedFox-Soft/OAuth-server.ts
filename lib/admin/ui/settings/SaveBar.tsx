import { useState } from 'react';
import { Button, Drawer, Modal, Table, Tag, Typography } from 'antd';
import { ExclamationCircleOutlined } from '@ant-design/icons';
import { riskyChanges, type Change } from './model.js';

const show = (v: unknown): string => {
	if (v === undefined) return '—';
	if (typeof v === 'string') return v === '' ? '(empty)' : v;
	if (typeof v === 'boolean') return v ? 'on' : 'off';
	if (Array.isArray(v)) return v.length ? v.join(', ') : '(none)';
	if (typeof v === 'object' && v !== null) return JSON.stringify(v);
	return String(v);
};

/*
 * What is about to be saved, key by key. Offered before the save rather than reported after it: the
 * page's own alert used to name the changed keys only once they were already stored, which is the
 * one moment the information cannot be acted on.
 */
function ReviewDrawer({
	changes,
	open,
	onClose
}: {
	changes: Change[];
	open: boolean;
	onClose: () => void;
}) {
	return (
		<Drawer
			title={`${changes.length} unsaved ${changes.length === 1 ? 'change' : 'changes'}`}
			open={open}
			width={640}
			onClose={onClose}
		>
			<Table<Change>
				size="small"
				pagination={false}
				rowKey="key"
				dataSource={changes}
				columns={[
					{
						title: 'Setting',
						dataIndex: 'label',
						render: (label: string, row) => (
							<div>
								<div>
									{label}{' '}
									{row.risk === 'security' && (
										<Tag color="orange">security</Tag>
									)}
								</div>
								<Typography.Text
									type="secondary"
									style={{ fontSize: 12 }}
									code
								>
									{row.key}
								</Typography.Text>
							</div>
						)
					},
					{
						title: 'From',
						dataIndex: 'from',
						width: 140,
						render: (v: unknown) => (
							<Typography.Text type="secondary">{show(v)}</Typography.Text>
						)
					},
					{
						title: 'To',
						dataIndex: 'to',
						width: 140,
						render: (v: unknown) => (
							<Typography.Text strong>{show(v)}</Typography.Text>
						)
					}
				]}
			/>
		</Drawer>
	);
}

/*
 * The single save control for the boot-only settings.
 *
 * It appears only when there is something to save, and it says three things the page never used to:
 * how many settings are edited, that they take effect at restart rather than now, and — when one of
 * them is flagged — that saving will ask for confirmation first. The SMTP and Sentry cards keep
 * their own buttons, because they are separate endpoints that apply immediately; each says so.
 */
export function SaveBar({
	changes,
	saving,
	onSave,
	onDiscard
}: {
	changes: Change[];
	saving: boolean;
	onSave: () => void;
	onDiscard: () => void;
}) {
	const [reviewing, setReviewing] = useState(false);
	if (changes.length === 0) return null;

	const risky = riskyChanges(changes);

	/*
	 * A flagged change is confirmed, not merely clicked. These are the settings whose descriptions
	 * explain a consequence in at least one direction — replay detection off, the limiter off, the
	 * proxy header trusted — and they used to be indistinguishable from a user-code mask.
	 */
	function attempt() {
		if (risky.length === 0) {
			onSave();
			return;
		}
		Modal.confirm({
			title: 'Confirm a change with a security consequence',
			icon: <ExclamationCircleOutlined />,
			width: 560,
			okText: 'Save anyway',
			okButtonProps: { danger: true },
			content: (
				<div>
					<Typography.Paragraph>
						{risky.length === 1
							? 'This setting changes how the server protects itself:'
							: 'These settings change how the server protects itself:'}
					</Typography.Paragraph>
					<ul style={{ paddingLeft: 20, margin: 0 }}>
						{risky.map((c) => (
							<li key={c.key}>
								<Typography.Text strong>{c.label}</Typography.Text>{' '}
								<Typography.Text type="secondary">
									{show(c.from)} → {show(c.to)}
								</Typography.Text>
							</li>
						))}
					</ul>
				</div>
			),
			onOk: onSave
		});
	}

	return (
		<>
			<div
				style={{
					position: 'sticky',
					bottom: 0,
					marginTop: 8,
					padding: '12px 16px',
					display: 'flex',
					alignItems: 'center',
					gap: 12,
					flexWrap: 'wrap',
					background: 'var(--ant-color-bg-elevated, #fff)',
					borderTop: '1px solid var(--ant-color-split, rgba(5,5,5,0.06))',
					boxShadow: '0 -4px 12px rgba(0,0,0,0.05)',
					zIndex: 5
				}}
			>
				<Typography.Text strong>
					{changes.length} unsaved {changes.length === 1 ? 'change' : 'changes'}
				</Typography.Text>
				<Typography.Text type="secondary">
					· takes effect when the server restarts
				</Typography.Text>
				{risky.length > 0 && (
					<Tag color="orange">{risky.length} needs confirming</Tag>
				)}
				<span style={{ flex: 1 }} />
				<Button onClick={() => setReviewing(true)}>Review</Button>
				<Button
					onClick={onDiscard}
					disabled={saving}
				>
					Discard
				</Button>
				<Button
					type="primary"
					loading={saving}
					onClick={attempt}
				>
					Save
				</Button>
			</div>
			<ReviewDrawer
				changes={changes}
				open={reviewing}
				onClose={() => setReviewing(false)}
			/>
		</>
	);
}
