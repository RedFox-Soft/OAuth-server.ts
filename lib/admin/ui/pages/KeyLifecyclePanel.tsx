import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Select,
	Space,
	Table,
	Tag,
	Typography
} from 'antd';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { LoadFailed } from '../frame/states.js';
import { ConfirmDestruction } from '../ConfirmDestruction.js';

/*
 * One issuer's signing keys — the instance's or an addressable bucket's; both follow one lifecycle, so
 * one panel. The three acts are the three steps of a rotation, and their order is the point: a new key
 * is published before it may sign, so Promote stays unavailable until every instance serves it; the key
 * it replaces in its algorithm keeps verifying; and a retired key stays published until every token it
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

export function KeyLifecyclePanel({
	base,
	title,
	onUnavailable,
	canEdit = true
}: {
	base: string;
	title: string;
	/* Called with the response when the issuer has no keys here, so the caller can say where they are. */
	onUnavailable?: (status: number) => void;
	/* False when the caller may read these keys but not change them; the server would refuse every write. */
	canEdit?: boolean;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [state, setState] = useState<KeysState | null>(null);
	const [loadFailure, setLoadFailure] = useState<string | null>(null);
	const [alg, setAlg] = useState('RS256');
	const [busy, setBusy] = useState(false);
	const [retiring, setRetiring] = useState<KeyView | null>(null);

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchKeys = useCallback(async () => {
		try {
			const result = await request<KeysState>('GET', base);
			if (result.ok) {
				setState(result.data);
				setLoadFailure(null);
			} else {
				onUnavailable?.(result.status);
				setLoadFailure(result.error.message);
			}
		} finally {
			setBusy(false);
		}
	}, [base, onUnavailable]);
	useEffect(() => {
		void fetchKeys();
	}, [fetchKeys]);

	async function act(
		method: string,
		url: string,
		body: unknown,
		done: string
	): Promise<boolean> {
		setBusy(true);
		const result = await request(method, url, body);
		if (!result.ok) {
			setBusy(false);
			feedback.failed(result);
			return false;
		}
		feedback.done(done);
		await fetchKeys();
		return true;
	}

	async function generate() {
		if (!(await confirm('key.generate', { target: alg }))) return;
		await act('POST', base, { alg }, `${alg} key generated.`);
	}

	async function promote(row: KeyView) {
		if (
			!(await confirm('key.promote', {
				target: row.kid,
				consequences: [
					`Every new ${row.alg} token is signed with this key from now on.`,
					`The key that signs ${row.alg} tokens today keeps verifying the tokens it signed.`
				]
			}))
		) {
			return;
		}
		await act(
			'POST',
			`${base}/${encodeURIComponent(row.kid)}/promote`,
			undefined,
			`Key ${row.kid} promoted.`
		);
	}

	function actionsFor(row: KeyView): RowAction[] {
		if (row.state !== 'published') return [];
		const early =
			row.promotableAt !== undefined &&
			Date.now() < new Date(row.promotableAt).getTime();
		const items: RowAction[] = [];
		if (row.use === 'sig') {
			items.push({
				key: 'promote',
				label: 'Promote…',
				group: 'state',
				blocked: early ? `Can sign from ${when(row.promotableAt)}` : null,
				onClick: () => void promote(row)
			});
		}
		items.push({
			key: 'retire',
			label: 'Retire…',
			group: 'danger',
			onClick: () => setRetiring(row)
		});
		return items;
	}

	return (
		<Card
			title={title}
			style={{ marginTop: 24 }}
			extra={
				canEdit && (
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
							onClick={() => void generate()}
						>
							Generate key
						</Button>
					</Space>
				)
			}
		>
			<Typography.Paragraph type="secondary">
				A new key is published first and can sign once every server instance
				serves it — after {state?.publicationSeconds ?? 60} seconds. Promoting
				it replaces the key that signed in its algorithm, which keeps verifying.
				A retired key stays published until every token it signed has expired,
				then is hidden. Nothing here needs a restart.
			</Typography.Paragraph>
			{!canEdit && (
				<Alert
					style={{ marginBottom: 12 }}
					type="info"
					showIcon
					title="Only members of the group that owns this bucket can change this."
				/>
			)}
			{loadFailure !== null ? (
				<LoadFailed
					reason={loadFailure}
					onRetry={() => void fetchKeys()}
				/>
			) : (
				<Table<KeyView>
					rowKey="kid"
					size="small"
					pagination={false}
					loading={state === null}
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
						...(canEdit
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, row: KeyView) => (
											<RowActions
												name={row.kid}
												items={actionsFor(row)}
											/>
										)
									}
								]
							: [])
					]}
				/>
			)}
			{/*
			 * Retirement ends a key once its window closes — nothing it signed verifies again — so it takes
			 * the typed word. The server still checks the key's identifier, sent as `confirm`, so a request
			 * that reached the wrong key is refused rather than retiring it.
			 */}
			<ConfirmDestruction
				open={retiring !== null}
				title={retiring ? `Retire key ${retiring.kid}?` : ''}
				consequences={[
					'It stops signing now and keeps verifying the tokens it already signed for a day.',
					'Then it is hidden for good, and nothing it signed verifies again.'
				]}
				word="retire"
				okText="Retire key"
				busy={busy}
				onCancel={() => setRetiring(null)}
				onConfirm={() => {
					if (!retiring) return;
					const kid = retiring.kid;
					void act(
						'DELETE',
						`${base}/${encodeURIComponent(kid)}`,
						{ confirm: kid },
						`Key ${kid} retired.`
					).then((done) => {
						if (done) setRetiring(null);
					});
				}}
			/>
		</Card>
	);
}
