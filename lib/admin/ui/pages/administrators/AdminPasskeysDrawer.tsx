import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Drawer, Flex, Space, Tag, Typography } from 'antd';
import type {
	PasskeysOfPerson,
	PasskeyView
} from '../../../../passkeys/ways_in.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { EmptyState, LoadFailed } from '../../frame/states.js';

function deviceLabel(createdOn: PasskeyView['createdOn']): string {
	return `${createdOn.browser} on ${createdOn.system}`;
}

function formatDate(iso: string): string {
	return new Date(iso).toLocaleString(undefined, {
		dateStyle: 'medium',
		timeStyle: 'short'
	});
}

function stateTag(state: PasskeyView['state']) {
	switch (state) {
		case 'works':
			return <Tag color="green">Active</Tag>;
		case 'off':
			return <Tag>Off</Tag>;
		case 'old_address':
			return <Tag color="orange">Old address</Tag>;
		case 'copied':
			return <Tag color="red">Not usable</Tag>;
	}
}

/*
 * Super-administrator view and revocation of one administrator's passkeys (specs/144 contracts/console-ui.md §3).
 * Never offers revocation on the caller's own account: personal removal lives in the header account drawer.
 */
export function AdminPasskeysDrawer({
	target,
	self,
	onClose,
	onChanged
}: {
	target: { id: string; email: string } | null;
	self: boolean;
	onClose: () => void;
	onChanged: () => void;
}) {
	return (
		<Drawer
			title={target ? `Passkeys of ${target.email}` : 'Passkeys'}
			open={target !== null}
			onClose={onClose}
			size="large"
			destroyOnHidden
		>
			{target && (
				<AdminPasskeysBody
					target={target}
					self={self}
					onChanged={onChanged}
				/>
			)}
		</Drawer>
	);
}

function AdminPasskeysBody({
	target,
	self,
	onChanged
}: {
	target: { id: string; email: string };
	self: boolean;
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [data, setData] = useState<PasskeysOfPerson | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const base = `/admin/api/admins/${encodeURIComponent(target.id)}/passkeys`;

	const load = useCallback(async () => {
		try {
			const res = await request<PasskeysOfPerson>('GET', base);
			if (!res.ok) {
				setError(res.error.message);
				return;
			}
			setError(null);
			setData(res.data);
		} finally {
			setLoading(false);
		}
	}, [base]);

	useEffect(() => {
		void load();
	}, [load]);

	const hasOtherWay =
		data !== null && (data.ways.password || data.ways.providers.length > 0);

	async function onRevokeOne(passkey: PasskeyView) {
		const workingCount =
			data?.passkeys.filter((p) => p.state === 'works').length ?? 0;
		const leavesNoWay =
			passkey.state === 'works' && workingCount <= 1 && !hasOtherWay;
		const yes = await confirm('admin.passkey.revoke', {
			target: passkey.name ?? deviceLabel(passkey.createdOn),
			consequences: [
				`${target.email} is signed out everywhere, including open console sessions and agent tokens.`,
				...(leavesNoWay
					? [
							`${target.email} will have no remaining way to sign in to the console.`
						]
					: []),
				data?.mailable
					? 'They are emailed that an administrator removed this passkey.'
					: 'They have no verified email address to notify.'
			]
		});
		if (!yes) return;
		setBusy(true);
		try {
			const res = await request<{ revoked: number }>(
				'DELETE',
				`${base}/${encodeURIComponent(passkey.id)}`
			);
			if (!res.ok) {
				feedback.failed(res);
				return;
			}
			feedback.done(`Passkey of ${target.email} revoked.`);
			onChanged();
			await load();
		} finally {
			setBusy(false);
		}
	}

	async function onRevokeAll() {
		const yes = await confirm('admin.passkey.revokeAll', {
			target: target.email,
			consequences: [
				`Every passkey of ${target.email} is removed immediately.`,
				'They are signed out everywhere, including open console sessions and agent tokens.',
				...(!hasOtherWay
					? [
							`${target.email} will have no remaining way to sign in to the console.`
						]
					: [])
			]
		});
		if (!yes) return;
		setBusy(true);
		try {
			const res = await request<{ revoked: number }>('DELETE', base);
			if (!res.ok) {
				feedback.failed(res);
				return;
			}
			feedback.done(`All passkeys of ${target.email} revoked.`);
			onChanged();
			await load();
		} finally {
			setBusy(false);
		}
	}

	async function onSendLink() {
		const yes = await confirm('admin.passkey.linkSend', {
			target: target.email,
			consequences: [
				`A 24-hour single-use setup link is emailed to ${target.email}.`,
				'The link is delivered by email only and is never shown here.'
			]
		});
		if (!yes) return;
		setBusy(true);
		try {
			const res = await request(
				'POST',
				`/admin/api/admins/${encodeURIComponent(target.id)}/passkey-link`
			);
			if (!res.ok) {
				feedback.refused(res);
				return;
			}
			feedback.done(`Passkey setup link sent to ${target.email}.`);
		} finally {
			setBusy(false);
		}
	}

	if (error !== null) {
		return (
			<LoadFailed
				reason={error}
				onRetry={() => {
					setLoading(true);
					void load();
				}}
			/>
		);
	}
	if (loading || data === null) return null;

	return (
		<Flex
			vertical
			gap={16}
		>
			{self && (
				<Alert
					type="info"
					showIcon
					title="Manage your own passkeys from your email menu in the top-right header."
				/>
			)}
			{!self && (
				<Flex
					justify="end"
					gap={8}
					wrap
				>
					<Button
						loading={busy}
						onClick={() => void onSendLink()}
					>
						Send passkey setup link…
					</Button>
					{data.passkeys.length > 0 && (
						<Button
							danger
							loading={busy}
							onClick={() => void onRevokeAll()}
						>
							Revoke all
						</Button>
					)}
				</Flex>
			)}
			{data.passkeys.length === 0 ? (
				<EmptyState purpose={`${target.email} has no passkeys.`} />
			) : (
				<Flex
					vertical
					gap={12}
				>
					{data.passkeys.map((passkey) => (
						<Flex
							key={passkey.id}
							vertical
							gap={4}
							style={{
								padding: '10px 0',
								borderBottom: '1px solid rgba(5, 5, 5, 0.08)'
							}}
						>
							<Flex
								justify="space-between"
								align="center"
								gap={8}
								wrap
							>
								<Space
									size={6}
									wrap
								>
									<Typography.Text strong>
										{passkey.name ?? deviceLabel(passkey.createdOn)}
									</Typography.Text>
									{stateTag(passkey.state)}
								</Space>
								{!self && (
									<Button
										size="small"
										danger
										loading={busy}
										onClick={() => void onRevokeOne(passkey)}
									>
										Revoke
									</Button>
								)}
							</Flex>
							<Typography.Text type="secondary">
								Added {formatDate(passkey.createdAt)} ·{' '}
								{passkey.lastUsedAt
									? `Last used ${formatDate(passkey.lastUsedAt)}`
									: 'Never used'}{' '}
								· Created via {passkey.createdVia}
							</Typography.Text>
						</Flex>
					))}
				</Flex>
			)}
		</Flex>
	);
}
