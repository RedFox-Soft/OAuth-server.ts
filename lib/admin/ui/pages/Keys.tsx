import { useEffect, useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Popconfirm,
	Select,
	Space,
	Table,
	Tag,
	Typography,
	message
} from 'antd';

interface KeyView {
	kid: string;
	kty: string;
	alg?: string;
	use?: string;
	status: 'active' | 'pending activation' | 'pending removal';
}
interface JwksState {
	keys: KeyView[];
	restartRequired: boolean;
	changedKeys: string[];
	supportedAlgorithms: string[];
}

const STATUS_COLOR: Record<KeyView['status'], string> = {
	active: 'green',
	'pending activation': 'blue',
	'pending removal': 'orange'
};

// A key still present in the desired (stored) set — i.e. not already removed.
function inDesired(k: KeyView): boolean {
	return k.status !== 'pending removal';
}
function isSigning(k: KeyView): boolean {
	return (k.use ?? 'sig') !== 'enc';
}

export function Keys() {
	const [state, setState] = useState<JwksState | null>(null);
	const [loading, setLoading] = useState(true);
	const [generating, setGenerating] = useState(false);
	const [alg, setAlg] = useState('RS256');

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/jwks');
			if (res.ok) setState((await res.json()) as JwksState);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	async function generate() {
		setGenerating(true);
		try {
			const res = await fetch('/admin/api/jwks', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ alg })
			});
			const body = (await res.json().catch(() => null)) as
				(JwksState & { message?: string }) | null;
			if (!res.ok) {
				message.error(body?.message || 'failed to generate key');
				return;
			}
			if (body) setState(body);
			message.success(
				'key generated and now live — published for verification (the existing key keeps signing)'
			);
		} finally {
			setGenerating(false);
		}
	}

	async function remove(kid: string) {
		const res = await fetch(`/admin/api/jwks/${encodeURIComponent(kid)}`, {
			method: 'DELETE'
		});
		const body = (await res.json().catch(() => null)) as
			(JwksState & { message?: string }) | null;
		if (!res.ok) {
			message.error(body?.message || 'failed to remove key');
			return;
		}
		if (body) setState(body);
		message.success('key removed — takes effect after a server restart');
	}

	// The number of signing keys still in the desired set; used to block removing the last one.
	const signingInDesired = useMemo(
		() =>
			(state?.keys ?? []).filter((k) => inDesired(k) && isSigning(k)).length,
		[state]
	);

	const columns = [
		{ title: 'Key ID', dataIndex: 'kid', key: 'kid', ellipsis: true },
		{ title: 'Type', dataIndex: 'kty', key: 'kty' },
		{ title: 'Algorithm', dataIndex: 'alg', key: 'alg' },
		{
			title: 'Use',
			dataIndex: 'use',
			key: 'use',
			render: (use?: string) => use ?? 'sig'
		},
		{
			title: 'Status',
			dataIndex: 'status',
			key: 'status',
			render: (status: KeyView['status']) => (
				<Tag color={STATUS_COLOR[status]}>{status}</Tag>
			)
		},
		{
			title: 'Actions',
			key: 'actions',
			render: (_: unknown, row: KeyView) => {
				if (!inDesired(row)) return null;
				const isLastSigning = isSigning(row) && signingInDesired <= 1;
				const active = row.status === 'active';
				return (
					<Popconfirm
						title="Remove this key?"
						description={
							active
								? 'This key is active. After the next restart the server will stop publishing it, and tokens already signed with it will no longer verify. Remove only after those tokens have expired.'
								: 'This key has not been activated yet and can be removed safely.'
						}
						okText="Remove"
						okButtonProps={{ danger: true }}
						disabled={isLastSigning}
						onConfirm={() => remove(row.kid)}
					>
						<Button
							danger
							size="small"
							disabled={isLastSigning}
							title={
								isLastSigning
									? 'At least one signing key must remain'
									: undefined
							}
						>
							Remove
						</Button>
					</Popconfirm>
				);
			}
		}
	];

	return (
		<>
			<div
				style={{
					display: 'flex',
					justifyContent: 'space-between',
					alignItems: 'center',
					marginBottom: 16
				}}
			>
				<Typography.Title
					level={4}
					style={{ margin: 0 }}
				>
					Signing keys
				</Typography.Title>
				<Space>
					<Select
						value={alg}
						style={{ minWidth: 140 }}
						onChange={setAlg}
						options={(state?.supportedAlgorithms ?? ['RS256']).map((a) => ({
							label: a,
							value: a
						}))}
					/>
					<Button
						type="primary"
						loading={generating}
						onClick={generate}
					>
						Generate key
					</Button>
				</Space>
			</div>

			{state?.restartRequired && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					message="Restart required to apply"
					description={`Pending key changes take effect after a server restart: ${state.changedKeys.join(', ')}`}
				/>
			)}

			<Card
				size="small"
				loading={loading}
			>
				<Table
					rowKey="kid"
					size="small"
					pagination={false}
					columns={columns}
					dataSource={state?.keys ?? []}
				/>
			</Card>
		</>
	);
}
