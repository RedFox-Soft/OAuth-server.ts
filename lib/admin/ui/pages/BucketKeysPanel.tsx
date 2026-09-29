import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Popconfirm,
	Select,
	Space,
	Table,
	Tag,
	Tooltip,
	Typography,
	message
} from 'antd';

/*
 * A bucket's own signing keys, for a bucket with an address of its own.
 *
 * The three buttons are the three steps of a rotation, and their order is the point: a new key is
 * published before it may sign, so Promote stays disabled until every instance serves it; the key it
 * replaces keeps verifying; and a retired key stays published until every token it signed has expired.
 * A bucket served at the root has no keys of its own and is sent to the instance key page instead.
 */

interface BucketKeyView {
	kid: string;
	alg: string;
	use: 'sig' | 'enc';
	state: 'published' | 'signing' | 'retired';
	createdAt: string;
	promotableAt?: string;
	removableAt?: string;
}

interface BucketKeysState {
	keys: BucketKeyView[];
	supportedAlgorithms: string[];
	publicationSeconds: number;
}

const STATE_COLOR: Record<BucketKeyView['state'], string> = {
	signing: 'green',
	published: 'blue',
	retired: 'orange'
};

function when(iso?: string): string {
	return iso ? new Date(iso).toLocaleString() : '—';
}

export function BucketKeysPanel({ bucketId }: { bucketId: string }) {
	const base = `/admin/api/buckets/${bucketId}/keys`;
	const [state, setState] = useState<BucketKeysState | null>(null);
	const [rootServed, setRootServed] = useState(false);
	const [alg, setAlg] = useState('RS256');
	const [busy, setBusy] = useState(false);

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchKeys = useCallback(async () => {
		try {
			const res = await fetch(base);
			setRootServed(res.status === 409);
			setState(res.ok ? ((await res.json()) as BucketKeysState) : null);
		} finally {
			setBusy(false);
		}
	}, [base]);
	useEffect(() => {
		void fetchKeys();
	}, [fetchKeys]);

	async function act(url: string, method: string, body?: unknown) {
		setBusy(true);
		try {
			const res = await fetch(url, {
				method,
				headers: { 'content-type': 'application/json' },
				body: body === undefined ? undefined : JSON.stringify(body)
			});
			if (!res.ok) {
				const detail = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(detail?.message ?? 'the key action was refused');
				return;
			}
			await fetchKeys();
		} finally {
			setBusy(false);
		}
	}

	if (rootServed) {
		return (
			<Card
				title="Signing keys"
				style={{ marginTop: 24 }}
			>
				<Alert
					type="info"
					showIcon
					message="This bucket signs with the instance keys"
					description="It has no address of its own, so it shares the root issuer and its key set. Those keys are managed on the Keys page."
				/>
			</Card>
		);
	}

	return (
		<Card
			title="Signing keys"
			style={{ marginTop: 24 }}
			extra={
				<Space>
					<Select
						value={alg}
						onChange={setAlg}
						style={{ width: 120 }}
						options={(state?.supportedAlgorithms ?? ['RS256']).map((a) => ({
							label: a,
							value: a
						}))}
					/>
					<Button
						loading={busy}
						onClick={() => void act(base, 'POST', { alg })}
					>
						Generate
					</Button>
				</Space>
			}
		>
			<Typography.Paragraph type="secondary">
				A new key is published first and can sign once every server instance
				serves it — after {state?.publicationSeconds ?? 60} seconds. The key it
				replaces keeps verifying, and a retired key stays published until every
				token it signed has expired.
			</Typography.Paragraph>
			<Table
				rowKey="kid"
				size="small"
				pagination={false}
				dataSource={state?.keys ?? []}
				columns={[
					{
						title: 'Key',
						dataIndex: 'kid',
						render: (kid: string) => (
							<Typography.Text
								code
								copyable
							>
								{kid}
							</Typography.Text>
						)
					},
					{ title: 'Algorithm', dataIndex: 'alg' },
					{
						title: 'State',
						dataIndex: 'state',
						render: (value: BucketKeyView['state']) => (
							<Tag color={STATE_COLOR[value]}>{value}</Tag>
						)
					},
					{
						title: 'Created',
						dataIndex: 'createdAt',
						render: (value: string) => when(value)
					},
					{
						title: 'Removed from the key set',
						dataIndex: 'removableAt',
						render: (value?: string) => when(value)
					},
					{
						title: '',
						key: 'actions',
						render: (_: unknown, row: BucketKeyView) => {
							const url = `${base}/${encodeURIComponent(row.kid)}`;
							const early =
								row.promotableAt !== undefined &&
								Date.now() < new Date(row.promotableAt).getTime();
							return (
								<Space>
									{row.state === 'published' && (
										<Tooltip
											title={
												early
													? `Can sign from ${when(row.promotableAt)}`
													: 'Sign with this key from now on'
											}
										>
											<Button
												size="small"
												disabled={early || busy}
												onClick={() => void act(`${url}/promote`, 'POST')}
											>
												Promote
											</Button>
										</Tooltip>
									)}
									{row.state === 'published' && (
										<Popconfirm
											title="Retire this key?"
											description="It keeps verifying until every token it signed has expired, then tokens signed with it stop verifying."
											okText="Retire"
											okButtonProps={{ danger: true }}
											onConfirm={() => void act(url, 'DELETE')}
										>
											<Button
												size="small"
												danger
												disabled={busy}
											>
												Retire
											</Button>
										</Popconfirm>
									)}
								</Space>
							);
						}
					}
				]}
			/>
		</Card>
	);
}
