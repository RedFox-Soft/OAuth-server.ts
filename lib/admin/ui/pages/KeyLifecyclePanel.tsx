import { useCallback, useEffect, useState } from 'react';
import {
	Button,
	Card,
	Input,
	Modal,
	Select,
	Space,
	Table,
	Tag,
	Tooltip,
	Typography,
	message
} from 'antd';

/*
 * One issuer's signing keys — the instance's or an addressable bucket's; both follow one lifecycle, so
 * one panel. The three buttons are the three steps of a rotation, and their order is the point: a new key
 * is published before it may sign, so Promote stays disabled until every instance serves it; the key it
 * replaces in its algorithm keeps verifying; and a retired key stays published until every token it
 * signed has expired, then is hidden. None of it needs a restart.
 */

interface KeyView {
	kid: string;
	kty?: string;
	alg: string;
	use: 'sig' | 'enc';
	state: 'published' | 'signing' | 'retired';
	createdAt: string;
	promotableAt?: string;
	removableAt?: string;
}

interface KeysState {
	keys: KeyView[];
	supportedAlgorithms: string[];
	publicationSeconds: number;
}

const STATE_COLOR: Record<KeyView['state'], string> = {
	signing: 'green',
	published: 'blue',
	retired: 'orange'
};

function when(iso?: string): string {
	return iso ? new Date(iso).toLocaleString() : '—';
}

/*
 * Retirement ends a key once its window closes — nothing it signed verifies again — so the operator types
 * the key's identifier to confirm it, and that value is what the server checks too.
 */
function RetireModal({
	target,
	busy,
	onCancel,
	onConfirm
}: {
	target: KeyView | null;
	busy: boolean;
	onCancel: () => void;
	onConfirm: (kid: string, confirm: string) => void;
}) {
	const [typed, setTyped] = useState('');
	const matches = target !== null && typed === target.kid;
	return (
		<Modal
			title="Retire this key?"
			open={target !== null}
			onCancel={() => {
				setTyped('');
				onCancel();
			}}
			onOk={() => {
				if (target && matches) onConfirm(target.kid, typed);
				setTyped('');
			}}
			okText="Retire"
			okButtonProps={{ danger: true, disabled: !matches, loading: busy }}
			destroyOnHidden
		>
			<Typography.Paragraph>
				It stops signing now, keeps verifying tokens it already signed for a
				day, and is then hidden for good — after that nothing it signed
				verifies.
			</Typography.Paragraph>
			<Typography.Paragraph>
				Type the key&apos;s identifier to confirm:{' '}
				<Typography.Text code>{target?.kid}</Typography.Text>
			</Typography.Paragraph>
			<Input
				value={typed}
				onChange={(event) => setTyped(event.target.value)}
				placeholder="key identifier"
				spellCheck={false}
				autoComplete="off"
			/>
		</Modal>
	);
}

export function KeyLifecyclePanel({
	base,
	title,
	onUnavailable
}: {
	base: string;
	title: string;
	/* Called with the response when the issuer has no keys here, so the caller can say where they are. */
	onUnavailable?: (status: number) => void;
}) {
	const [state, setState] = useState<KeysState | null>(null);
	const [alg, setAlg] = useState('RS256');
	const [busy, setBusy] = useState(false);
	const [retiring, setRetiring] = useState<KeyView | null>(null);

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchKeys = useCallback(async () => {
		try {
			const res = await fetch(base);
			if (!res.ok) onUnavailable?.(res.status);
			setState(res.ok ? ((await res.json()) as KeysState) : null);
		} finally {
			setBusy(false);
		}
	}, [base, onUnavailable]);
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
				return false;
			}
			await fetchKeys();
			return true;
		} finally {
			setBusy(false);
		}
	}

	return (
		<Card
			title={title}
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
				serves it — after {state?.publicationSeconds ?? 60} seconds. Promoting
				it replaces the key that signed in its algorithm, which keeps verifying.
				A retired key stays published until every token it signed has expired,
				then is hidden. Nothing here needs a restart.
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
						render: (value: KeyView['state']) => (
							<Tag color={STATE_COLOR[value]}>{value}</Tag>
						)
					},
					{
						title: 'Created',
						dataIndex: 'createdAt',
						render: (value: string) => when(value)
					},
					{
						title: 'Hidden from',
						dataIndex: 'removableAt',
						render: (value?: string) => when(value)
					},
					{
						title: '',
						key: 'actions',
						render: (_: unknown, row: KeyView) => {
							const url = `${base}/${encodeURIComponent(row.kid)}`;
							const early =
								row.promotableAt !== undefined &&
								Date.now() < new Date(row.promotableAt).getTime();
							return (
								<Space>
									{row.state === 'published' && row.use === 'sig' && (
										<Tooltip
											title={
												early
													? `Can sign from ${when(row.promotableAt)}`
													: `Sign in ${row.alg} with this key from now on`
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
										<Button
											size="small"
											danger
											disabled={busy}
											onClick={() => setRetiring(row)}
										>
											Retire
										</Button>
									)}
								</Space>
							);
						}
					}
				]}
			/>
			<RetireModal
				target={retiring}
				busy={busy}
				onCancel={() => setRetiring(null)}
				onConfirm={(kid, confirm) => {
					void act(`${base}/${encodeURIComponent(kid)}`, 'DELETE', {
						confirm
					}).then((done) => {
						if (done) setRetiring(null);
					});
				}}
			/>
		</Card>
	);
}
