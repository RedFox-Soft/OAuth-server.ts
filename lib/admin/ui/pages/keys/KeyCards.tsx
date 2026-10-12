import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Collapse,
	Empty,
	Flex,
	Modal,
	Radio,
	Space,
	Steps,
	Table,
	Tag,
	Typography
} from 'antd';
import { ConfirmDestruction } from '../../ConfirmDestruction.js';
import { useConfirm } from '../../frame/confirm.js';
import { useFeedback } from '../../frame/feedback.js';
import { request } from '../../frame/request.js';
import { Link } from '../../frame/router.js';
import { RowActions } from '../../frame/RowActions.js';
import { LoadFailed } from '../../frame/states.js';

/*
 * One issuer's signing keys — an addressable bucket's or the instance's — one card per algorithm (specs/086).
 *
 * The card is the point: each algorithm has exactly one signer, so promoting a key replaces the signer of its
 * own algorithm and nothing else, and a flat table read as "replace *the* signer". Each key says in words where
 * it is in its life; the next step (Promote) is the one inline action, and the irreversible one (Retire) sits
 * in the row's menu behind the typed word.
 */

interface KeyView {
	kid: string;
	alg: string;
	use: 'sig' | 'enc';
	state: 'published' | 'signing' | 'retired' | 'revoked' | (string & {});
	createdAt: string;
	promotableAt?: string;
	removableAt?: string;
	signedUntil?: string;
}

interface KeysRead {
	keys: KeyView[];
	supportedAlgorithms?: string[];
	publicationSeconds: number;
	retiredKeyLifetimeSeconds?: number;
}

/* One line of help per algorithm, for the choice a person makes perhaps twice a year. */
const ALG_HELP: Record<string, string> = {
	RS256: 'Every relying party verifies it. The usual choice.',
	PS256: 'Required by FAPI 2.0 profiles.',
	ES256: 'Smaller signatures. Check your relying parties support it.',
	ES384: 'Smaller signatures. Check your relying parties support it.',
	ES512: 'Smaller signatures. Check your relying parties support it.',
	EdDSA: 'Check your relying parties support it.'
};

const ORDER: Record<string, number> = { signing: 0, published: 1, retired: 2 };
const HOUR = 60 * 60 * 1000;

function when(iso: string): string {
	return new Date(iso).toLocaleString();
}

function day(iso: string): string {
	return new Date(iso).toLocaleDateString();
}

/* "k-7f3a…0c21": enough of a key id to tell keys apart in prose; the full one is in the table. */
function short(kid: string): string {
	return kid.length > 14 ? `${kid.slice(0, 6)}…${kid.slice(-4)}` : kid;
}

export interface Dependent {
	id: string;
	name: string;
	href: string;
}

export function KeyCards({
	base,
	keySetUrl,
	historyHref,
	canEdit,
	dependents
}: {
	base: string;
	keySetUrl: string | null;
	historyHref: string;
	canEdit: boolean;
	/* The instance's keys: every bucket signing with them, named in the retire question. */
	dependents?: Dependent[];
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [read, setRead] = useState<KeysRead | null>(null);
	const [failure, setFailure] = useState<string | null>(null);
	const [generating, setGenerating] = useState(false);
	const [retiring, setRetiring] = useState<KeyView | null>(null);
	const [revoking, setRevoking] = useState<KeyView | null>(null);
	const [busy, setBusy] = useState(false);
	// Ticks while a key waits for its publication window, so Promote becomes available on time.
	const [now, setNow] = useState(() => Date.now());

	// Every state write follows an await, so the effect below sets nothing synchronously.
	const load = useCallback(async () => {
		try {
			const result = await request<KeysRead>('GET', base);
			if (result.ok) {
				setRead(result.data);
				setFailure(null);
			} else {
				setFailure(result.error.message);
			}
		} finally {
			setBusy(false);
		}
	}, [base]);
	useEffect(() => {
		void load();
	}, [load]);

	const waiting = (read?.keys ?? []).some(
		(k) =>
			k.state === 'published' &&
			k.promotableAt !== undefined &&
			new Date(k.promotableAt).getTime() > now
	);
	useEffect(() => {
		if (!waiting) return;
		const timer = window.setInterval(() => setNow(Date.now()), 1000);
		return () => window.clearInterval(timer);
	}, [waiting]);

	const keys = read?.keys ?? [];
	const algorithms = [...new Set(keys.map((k) => k.alg))];
	const signerOf = (alg: string) =>
		keys.find((k) => k.alg === alg && k.state === 'signing');
	const ready = keys.filter(
		(k) =>
			k.state === 'published' &&
			k.use === 'sig' &&
			k.promotableAt !== undefined &&
			new Date(k.promotableAt).getTime() <= now
	);

	/* The key Rotate would promote: the oldest of the algorithm's published keys that may sign. */
	const readyOf = (alg: string) =>
		ready
			.filter((k) => k.alg === alg)
			.sort(
				(a, b) =>
					new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime()
			)
			.at(0);
	/*
	 * The key that is next in an algorithm (specs/087): the ready one Rotate would promote, else the newest
	 * waiting key that has never signed — the one the window is running for.
	 */
	const nextOf = (alg: string) =>
		readyOf(alg) ??
		keys
			.filter(
				(k) =>
					k.alg === alg &&
					k.state === 'published' &&
					k.use === 'sig' &&
					!k.signedUntil
			)
			.sort(
				(a, b) =>
					new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
			)
			.at(0);

	async function rotate(alg: string) {
		const next = readyOf(alg);
		const previous = signerOf(alg);
		const yes = await confirm('key.rotate', {
			target: alg,
			consequences: next
				? [
						`${short(next.kid)} signs ${alg} tokens from now on.`,
						previous
							? `${short(previous.kid)} stops signing and keeps verifying what it signed.`
							: `It becomes the only key signing ${alg} tokens.`,
						'A new key is published as the next one, ready for the rotation after this.'
					]
				: [
						`No ${alg} key may sign yet, so this only publishes the next key.`,
						'You can rotate once it has been published long enough for every server to serve it.'
					]
		});
		if (!yes) return;
		setBusy(true);
		const result = await request<{
			promoted?: string;
			generated: string;
			rotatableAt?: string;
		}>('POST', `${base}/rotate`, { alg });
		if (!result.ok) {
			feedback.failed(result);
			await load();
			return;
		}
		const { promoted, generated, rotatableAt } = result.data;
		feedback.done(
			promoted
				? `${short(promoted)} now signs ${alg} tokens; ${short(generated)} is published as the next key.`
				: `${short(generated)} is published as the next ${alg} key.${rotatableAt ? ` You can rotate from ${new Date(rotatableAt).toLocaleTimeString()}.` : ''}`
		);
		await load();
	}

	async function revoke(key: KeyView) {
		setBusy(true);
		const result = await request<{
			replacement?: string;
			replacementGenerated?: boolean;
		}>('POST', `${base}/${encodeURIComponent(key.kid)}/revoke`, {
			confirm: key.kid
		});
		if (!result.ok) {
			feedback.failed(result);
			await load();
			return;
		}
		setRevoking(null);
		const { replacement } = result.data;
		feedback.done(
			replacement
				? `${short(key.kid)} revoked. ${short(replacement)} now signs ${key.alg} tokens.`
				: `${short(key.kid)} revoked.`
		);
		await load();
	}

	async function promote(key: KeyView) {
		const previous = signerOf(key.alg);
		const age = now - new Date(key.createdAt).getTime();
		const yes = await confirm('key.promote', {
			target: short(key.kid),
			consequences: [
				previous
					? `${short(previous.kid)} stops signing ${key.alg} tokens and keeps verifying what it signed.`
					: `It becomes the only key signing ${key.alg} tokens.`,
				...(age < HOUR
					? [
							`It was published ${String(Math.max(1, Math.round(age / 60000)))} minutes ago. Relying parties that cache your key set for longer may reject new tokens until they refresh it.`
						]
					: [])
			]
		});
		if (!yes) return;
		setBusy(true);
		const result = await request(
			'POST',
			`${base}/${encodeURIComponent(key.kid)}/promote`
		);
		if (!result.ok) {
			feedback.failed(result);
			await load();
			return;
		}
		feedback.done(
			previous
				? `${short(key.kid)} now signs ${key.alg} tokens. ${short(previous.kid)} keeps verifying; retire it when nothing needs it.`
				: `${short(key.kid)} now signs ${key.alg} tokens.`
		);
		await load();
	}

	async function retire(key: KeyView) {
		setBusy(true);
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(key.kid)}`,
			{ confirm: key.kid }
		);
		if (!result.ok) {
			feedback.failed(result);
			await load();
			return;
		}
		setRetiring(null);
		feedback.done(`${short(key.kid)} retired.`);
		await load();
	}

	function stateCell(key: KeyView) {
		const label =
			key.state === 'signing'
				? 'Signing'
				: key.state === 'published'
					? 'Published'
					: key.state === 'retired'
						? 'Retired'
						: key.state;
		const color =
			key.state === 'signing'
				? 'green'
				: key.state === 'published'
					? 'blue'
					: key.state === 'retired'
						? 'orange'
						: undefined;
		let detail: string | null = null;
		if (key.state === 'published') {
			const at = key.promotableAt ? new Date(key.promotableAt).getTime() : 0;
			// A key just replaced has both: when it stopped signing, and when it may sign again.
			detail =
				[
					key.signedUntil ? `signed until ${when(key.signedUntil)}` : null,
					at > now ? `can sign at ${new Date(at).toLocaleTimeString()}` : null
				]
					.filter((part) => part !== null)
					.join(' · ') || null;
		}
		if (key.state === 'retired' && key.removableAt) {
			detail = `verifies until ${when(key.removableAt)}`;
		}
		return (
			<Space size={6}>
				<Tag color={color}>{label}</Tag>
				{nextOf(key.alg)?.kid === key.kid && (
					<Tag color="purple">{readyOf(key.alg) ? 'Next · ready' : 'Next'}</Tag>
				)}
				{detail && <Typography.Text type="secondary">{detail}</Typography.Text>}
			</Space>
		);
	}

	function actionsCell(key: KeyView) {
		if (
			!canEdit ||
			(key.state !== 'published' &&
				key.state !== 'signing' &&
				key.state !== 'retired')
		) {
			return null;
		}
		const early =
			key.promotableAt !== undefined &&
			new Date(key.promotableAt).getTime() > now;
		return (
			<RowActions
				name={key.kid}
				inline={
					key.state === 'published' && key.use === 'sig' ? (
						<Button
							size="small"
							disabled={early || busy}
							onClick={() => void promote(key)}
						>
							Promote
						</Button>
					) : undefined
				}
				items={[
					...(key.state === 'retired'
						? []
						: [
								{
									key: 'retire',
									label: 'Retire…',
									group: 'danger' as const,
									blocked:
										key.state === 'signing'
											? `Promote another ${key.alg} key first`
											: null,
									onClick: () => setRetiring(key)
								}
							]),
					{
						key: 'revoke',
						label: 'Revoke now…',
						group: 'danger',
						onClick: () => setRevoking(key)
					}
				]}
			/>
		);
	}

	const lifetime = (read?.retiredKeyLifetimeSeconds ?? 86400) * 1000;

	return (
		<Flex
			vertical
			gap={16}
		>
			<Flex
				justify="space-between"
				align="center"
				wrap
				gap={12}
			>
				{keySetUrl ? (
					<Typography.Text>
						Key set{' '}
						<Typography.Text
							code
							copyable
						>
							{keySetUrl}
						</Typography.Text>
					</Typography.Text>
				) : (
					<span />
				)}
				<Space>
					<Link href={historyHref}>History</Link>
					{canEdit && (
						<Button
							type="primary"
							onClick={() => setGenerating(true)}
						>
							Generate key…
						</Button>
					)}
				</Space>
			</Flex>
			<Collapse
				ghost
				size="small"
				items={[
					{
						key: 'how',
						label: 'How rotation works',
						children: (
							<Steps
								size="small"
								type="dot"
								current={-1}
								items={[
									{
										title: 'Next key',
										description:
											'Rotate publishes one if there is none; it signs nothing yet.'
									},
									{
										title: 'Wait',
										description: `At least ${String(Math.round((read?.publicationSeconds ?? 60) / 60) || 1)} minute, longer if your relying parties cache keys.`
									},
									{
										title: 'Rotate',
										description:
											'The next key signs; the previous signer keeps verifying; a new next key is published.'
									},
									{
										title: 'Retire',
										description: 'The previous key, once nothing needs it.'
									}
								]}
							/>
						)
					}
				]}
			/>
			<span
				aria-live="polite"
				style={{ position: 'absolute', left: -9999 }}
			>
				{ready.length > 0 ? 'Ready to promote' : ''}
			</span>
			{failure !== null ? (
				<LoadFailed
					reason={failure}
					onRetry={() => void load()}
				/>
			) : read !== null && keys.length === 0 ? (
				<Empty description="No keys yet. This issuer gets its first RS256 key the first time it signs a token, or you can generate one now." />
			) : (
				(read === null ? ['…'] : algorithms).map((alg) => {
					const rows = keys
						.filter((k) => k.alg === alg)
						.sort((a, b) => (ORDER[a.state] ?? 3) - (ORDER[b.state] ?? 3));
					return (
						<Card
							key={alg}
							title={alg}
							size="small"
							extra={
								canEdit && read !== null ? (
									<Button
										size="small"
										disabled={busy}
										onClick={() => void rotate(alg)}
									>
										Rotate
									</Button>
								) : null
							}
						>
							{read !== null && !signerOf(alg) && (
								<Alert
									type="warning"
									showIcon
									style={{ marginBottom: 8 }}
									title={`No key signs ${alg} tokens yet. Promote one when it may sign.`}
								/>
							)}
							<Table<KeyView>
								rowKey="kid"
								size="small"
								pagination={false}
								loading={read === null}
								dataSource={rows}
								columns={[
									{
										title: 'Key',
										dataIndex: 'kid',
										render: (kid: string) => (
											<Typography.Text
												code
												copyable
												title={kid}
											>
												{kid}
											</Typography.Text>
										)
									},
									{
										title: 'State',
										key: 'state',
										render: (_: unknown, k: KeyView) => stateCell(k)
									},
									{
										title: 'Created',
										dataIndex: 'createdAt',
										render: (v: string) => day(v)
									},
									{
										title: '',
										key: 'actions',
										render: (_: unknown, k: KeyView) => actionsCell(k)
									}
								]}
							/>
						</Card>
					);
				})
			)}
			{generating && (
				<GenerateDialog
					algorithms={read?.supportedAlgorithms ?? Object.keys(ALG_HELP)}
					initial={keys.find((k) => k.state === 'signing')?.alg ?? 'RS256'}
					onClose={() => setGenerating(false)}
					onGenerate={async (alg) => {
						const result = await request<{
							kid: string;
							promotableAt?: string;
						}>('POST', base, { alg });
						if (!result.ok) {
							feedback.failed(result);
							return;
						}
						setGenerating(false);
						feedback.done(
							result.data.promotableAt
								? `Key ${short(result.data.kid)} generated. You can promote it from ${new Date(result.data.promotableAt).toLocaleTimeString()}.`
								: `Key ${short(result.data.kid)} generated.`
						);
						await load();
					}}
				/>
			)}
			{/*
			 * Retirement ends a key once its window closes — nothing it signed verifies again — so it takes the
			 * typed word. The server checks the key's identifier, sent as `confirm`, so a request that reached the
			 * wrong key is refused rather than retiring it.
			 */}
			<ConfirmDestruction
				open={retiring !== null}
				title={retiring ? `Retire ${short(retiring.kid)}?` : ''}
				consequences={
					retiring
						? [
								`It stops being published on ${new Date(now + lifetime).toLocaleString()}. After that, anything it signed fails verification.`,
								...(retiring.signedUntil
									? [
											`It signed ${retiring.alg} tokens until ${when(retiring.signedUntil)}.`
										]
									: ['It never signed a token.']),
								'A retired key can’t be promoted again. To roll back you would need a new key.',
								...(dependents && dependents.length > 0
									? [
											`Every bucket listed above uses this key set, including the administrators’ sign-in.`
										]
									: [])
							]
						: []
				}
				word="retire"
				okText="Retire key"
				busy={busy}
				onCancel={() => setRetiring(null)}
				onConfirm={() => {
					if (retiring) void retire(retiring);
				}}
			/>
			{/*
			 * Revoking is for a compromised key: it leaves the key set at once, so a token it signed — forged or
			 * not — stops verifying. The signer is replaced in the same act by the server, by a ready key or, when
			 * there is none, by a new key that signs without the publication window.
			 */}
			<ConfirmDestruction
				open={revoking !== null}
				title={revoking ? `Revoke ${short(revoking.kid)} now?` : ''}
				consequences={
					revoking
						? [
								'It leaves the key set at once, and every token it signed stops verifying. People signed in with such tokens may have to sign in again.',
								...(revoking.state === 'signing'
									? [
											readyOf(revoking.alg)
												? `${short(readyOf(revoking.alg)?.kid ?? '')} signs ${revoking.alg} tokens from now on.`
												: `No other ${revoking.alg} key may sign yet, so a new key is generated and signs at once. Relying parties holding a cached copy of your key set may reject new tokens until they refresh it.`
										]
									: []),
								'Unlike retiring, there is no day of grace, and a revoked key never comes back.',
								...(dependents && dependents.length > 0
									? [
											'Every bucket listed above uses this key set, including the administrators’ sign-in.'
										]
									: [])
							]
						: []
				}
				word="revoke"
				okText="Revoke key"
				busy={busy}
				onCancel={() => setRevoking(null)}
				onConfirm={() => {
					if (revoking) void revoke(revoking);
				}}
			/>
		</Flex>
	);
}

/* Generating publishes a key and changes nothing for clients until a promote, so it asks nothing (C0). */
function GenerateDialog({
	algorithms,
	initial,
	onClose,
	onGenerate
}: {
	algorithms: string[];
	initial: string;
	onClose: () => void;
	onGenerate: (alg: string) => Promise<void>;
}) {
	const [alg, setAlg] = useState(
		algorithms.includes(initial) ? initial : (algorithms[0] ?? 'RS256')
	);
	const [busy, setBusy] = useState(false);
	return (
		<Modal
			open
			title="Generate key"
			okText="Generate key"
			confirmLoading={busy}
			onOk={() => {
				setBusy(true);
				void onGenerate(alg).finally(() => setBusy(false));
			}}
			onCancel={onClose}
			destroyOnHidden
		>
			<Radio.Group
				value={alg}
				onChange={(e) => setAlg(e.target.value as string)}
				style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
			>
				{algorithms.map((a) => (
					<Radio
						key={a}
						value={a}
					>
						<Typography.Text strong>{a}</Typography.Text>{' '}
						<Typography.Text type="secondary">
							{ALG_HELP[a] ?? ''}
						</Typography.Text>
					</Radio>
				))}
			</Radio.Group>
			<Typography.Paragraph
				type="secondary"
				style={{ marginTop: 12, marginBottom: 0 }}
			>
				It is published at once and can sign after about a minute, once you
				promote it. Nothing changes for your clients until then.
			</Typography.Paragraph>
		</Modal>
	);
}
