import { useCallback, useEffect, useRef, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Descriptions,
	Flex,
	Form,
	Input,
	InputNumber,
	Radio,
	Segmented,
	Select,
	Skeleton,
	Switch,
	Tag,
	Typography
} from 'antd';
import type { FederationProvider } from '../../../../federation/types.js';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';
import {
	bucketHref,
	connectionHref,
	providerHref
} from '../../frame/routes.js';
import { Link, useLeaveGuard, useNavigate } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { bucketCan } from '../../frame/can.js';
import { SecretReveal } from '../../frame/SecretReveal.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
import type { BucketView } from '../bucketView.js';
import {
	CREDENTIAL_KINDS,
	Copyable,
	MAX_WINDOW_SECONDS,
	MIN_WINDOW_SECONDS,
	WARNING_LABELS,
	WINDOW_UNITS,
	connectionsApi,
	describeWindow,
	parseJwks,
	people,
	setupDetails,
	when,
	windowParts,
	type ConnectionView,
	type CredentialKind,
	type Threshold
} from './connectionShared.js';
import { HoldPanel } from './HoldPanel.js';
import { RecentChanges } from '../../frame/RecentChanges.js';
import { deleteBlock, useConnectionActions } from './useConnectionActions.js';

export type ConnectionTab = 'overview' | 'setup' | 'settings';

const TABS: {
	key: ConnectionTab;
	area?: 'directory-setup' | 'settings';
	label: string;
}[] = [
	{ key: 'overview', label: 'Overview' },
	{ key: 'setup', area: 'directory-setup', label: 'Directory setup' },
	{ key: 'settings', area: 'settings', label: 'Settings' }
];

/*
 * One provisioning connection, at an address of its own (specs/084 US5): the address the hold email links to,
 * so an incident starts on the page that can end it. Overview is what it is doing and what can be done to it;
 * Directory setup is what to paste into the directory; Settings is how it decides, under one save bar.
 */
export function ConnectionPage({
	bucketId,
	connectionId,
	tab
}: {
	bucketId: string;
	connectionId: string;
	tab: ConnectionTab;
}) {
	const navigate = useNavigate();
	const actions = useConnectionActions(bucketId);
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [connection, setConnection] = useState<ConnectionView | null>(null);
	const [provider, setProvider] = useState<FederationProvider | null>(null);
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const credentialsRef = useRef<HTMLDivElement>(null);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchAll = useCallback(async () => {
		try {
			const [b, c, f] = await Promise.all([
				request<BucketView>(
					'GET',
					`/admin/api/buckets/${encodeURIComponent(bucketId)}`
				),
				request<ConnectionView>('GET', connectionsApi(bucketId, connectionId)),
				request<FederationProvider[]>(
					'GET',
					`/admin/api/buckets/${encodeURIComponent(bucketId)}/federation`
				)
			]);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setBucket(b.data);
			if (!c.ok) {
				setLoadStatus(c.status);
				setLoadMessage(c.error.message);
				return;
			}
			setLoadStatus(null);
			setConnection(c.data);
			setProvider(
				f.ok ? (f.data.find((p) => p.id === c.data.providerId) ?? null) : null
			);
		} finally {
			setLoading(false);
		}
	}, [bucketId, connectionId]);
	useEffect(() => {
		void fetchAll();
	}, [fetchAll]);
	const reload = () => void fetchAll();

	const can = bucketCan(bucket);
	const listHref = bucketHref(bucketId, 'provisioning');

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="provisioning connection"
				backHref={bucket ? listHref : '/admin/buckets'}
				backLabel={bucket ? 'Back to Provisioning' : 'Back to Buckets'}
			/>
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={reload}
			/>
		);
	}

	const disable = () =>
		connection &&
		void actions.setEnabled(connection, false).then((done) => done && reload());

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Buckets', href: '/admin/buckets' },
					{ label: bucket?.name ?? '…', href: bucketHref(bucketId) },
					{ label: 'Provisioning', href: listHref },
					{ label: connection?.displayName ?? '…' }
				]}
				title={connection?.displayName ?? '…'}
				tags={
					connection ? (
						<>
							<Tag color={connection.enabled ? 'green' : 'default'}>
								{connection.enabled ? 'Enabled' : 'Disabled'}
							</Tag>
							{connection.hold && <Tag color="red">Deprovisioning held</Tag>}
						</>
					) : undefined
				}
				meta={
					connection ? (
						<>
							Signs in with{' '}
							<Link href={providerHref(bucketId, connection.providerId)}>
								{provider?.displayName ?? connection.providerId}
							</Link>
							{' · '}Created {when(connection.createdAt)}
						</>
					) : undefined
				}
				actions={
					connection && can.edit ? (
						connection.enabled ? (
							<Button onClick={disable}>Disable…</Button>
						) : (
							<Button
								onClick={() =>
									void actions
										.setEnabled(connection, true)
										.then((done) => done && reload())
								}
							>
								Enable
							</Button>
						)
					) : undefined
				}
				tabs={TABS.map((t) => ({
					key: t.key,
					label: t.label,
					href: connectionHref(bucketId, connectionId, t.area)
				}))}
				activeTab={tab}
			/>
			{loading && !connection && <Skeleton active />}
			{bucket && !can.edit && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="Only members of the group that owns this bucket can change this."
				/>
			)}
			{connection && tab === 'overview' && (
				<Flex
					vertical
					gap={16}
				>
					{connection.warnings.length > 0 && (
						<Alert
							type="warning"
							showIcon
							title="The directory's requests will be refused until this is fixed"
							description={
								<ul style={{ margin: 0, paddingInlineStart: 20 }}>
									{connection.warnings.map((w) => (
										<li key={w}>
											{WARNING_LABELS[w]}
											{w === 'provider_disabled' && (
												<>
													{' — '}
													<Link
														href={providerHref(bucketId, connection.providerId)}
													>
														open the provider
													</Link>
													{
														": the directory's people can't sign in while it is off."
													}
												</>
											)}
										</li>
									))}
								</ul>
							}
						/>
					)}
					<HoldPanel
						key={connection.hold?.since ?? 'free'}
						bucketId={bucketId}
						connection={connection}
						canEdit={can.edit}
						onReleased={reload}
						onRevoke={() =>
							credentialsRef.current?.scrollIntoView({ behavior: 'smooth' })
						}
						onDisable={disable}
					/>
					<Card title="At a glance">
						<Descriptions
							column={1}
							size="small"
							items={[
								{
									label: 'Manages',
									children: (
										<>
											<Link
												href={`${bucketHref(bucketId, 'users')}?managedBy=${encodeURIComponent(connection.id)}`}
											>
												{people(connection.managedUsers)}
											</Link>
											{' · '}
											<Link
												href={`${bucketHref(bucketId, 'user-groups')}?keptBy=${encodeURIComponent(connection.id)}`}
											>
												{people(connection.managedGroups, 'group')}
											</Link>
										</>
									)
								},
								{
									label: 'Last request from the directory',
									children: when(connection.lastUsedAt)
								},
								{
									label: 'Safeguard',
									children: connection.threshold
										? `Hold after ${connection.threshold.count} removals within ${describeWindow(connection.threshold.windowSeconds)}`
										: 'Off — every removal applies immediately'
								}
							]}
						/>
					</Card>
					<div ref={credentialsRef}>
						<CredentialsCard
							bucketId={bucketId}
							connection={connection}
							canEdit={can.edit}
							onChanged={reload}
						/>
					</div>
					{can.edit && <ConnectionHistory connectionId={connection.id} />}
					{can.edit && (
						<Card
							title="Danger zone"
							styles={{ header: { color: 'var(--ant-color-error)' } }}
						>
							<Flex
								justify="space-between"
								align="center"
								gap={12}
								wrap
							>
								<div>
									<Typography.Text strong>
										Delete provisioning connection
									</Typography.Text>
									<br />
									<Typography.Text type="secondary">
										{deleteBlock(connection) ??
											'The directory can no longer provision this bucket, and every token it holds is revoked.'}
									</Typography.Text>
								</div>
								<Button
									danger
									disabled={deleteBlock(connection) !== null}
									onClick={() =>
										void actions.remove(connection).then((done) => {
											if (done) void navigate(listHref);
										})
									}
								>
									Delete connection…
								</Button>
							</Flex>
						</Card>
					)}
				</Flex>
			)}
			{connection && tab === 'setup' && (
				<DirectorySetup connection={connection} />
			)}
			{connection && tab === 'settings' && (
				<ConnectionSettings
					key={JSON.stringify([
						connection.displayName,
						connection.correlation,
						connection.emailTrust,
						connection.threshold ?? null,
						connection.hold?.since ?? null
					])}
					bucketId={bucketId}
					connection={connection}
					canEdit={can.edit}
					onSaved={reload}
				/>
			)}
		</>
	);
}

function DirectorySetup({ connection }: { connection: ConnectionView }) {
	const feedback = useFeedback();
	async function copySetup() {
		try {
			await navigator.clipboard.writeText(setupDetails(connection));
			feedback.done('Setup details copied, without the secret.');
		} catch {
			feedback.refused({
				error: 'clipboard',
				message:
					'The details could not be copied. Select them and copy them by hand.'
			});
		}
	}
	return (
		<Flex
			vertical
			gap={16}
		>
			<Card title="Values for the directory">
				<Descriptions
					column={1}
					size="small"
					bordered
					items={[
						{
							label: 'SCIM base URL',
							children: <Copyable value={connection.scimBaseUrl} />
						},
						{
							label: 'Token endpoint',
							children: <Copyable value={connection.tokenEndpoint} />
						},
						{
							label: 'Client id',
							children: <Copyable value={connection.clientId} />
						},
						{ label: 'Scope', children: <Copyable value={connection.scope} /> },
						{
							label: 'Metadata URL',
							children: <Copyable value={connection.metadataUrl} />
						}
					]}
				/>
				<Button
					style={{ marginTop: 12 }}
					onClick={() => void copySetup()}
				>
					Copy setup details (without the secret)
				</Button>
			</Card>
			<Card title="In the directory">
				<Typography.Paragraph>
					<strong>Microsoft Entra ID</strong>: in the enterprise application's
					Provisioning, set the mode to Automatic, choose{' '}
					<strong>OAuth2 client credentials</strong>, and paste the base URL,
					token endpoint, client id and a client secret issued here.
				</Typography.Paragraph>
				<Typography.Paragraph style={{ margin: 0 }}>
					<strong>Okta</strong>: in the app's Provisioning, enable API
					integration with <strong>HTTP Header</strong> authentication, paste
					the base URL, and a static token issued here as the bearer token.
				</Typography.Paragraph>
			</Card>
		</Flex>
	);
}

/*
 * One row per slot: the OAuth credential (a key or a secret) and the static token. Each slot holds one value,
 * so a replacement cuts the old one off the moment the new one exists — said before it happens, because the
 * directory still holding the old one stops working then.
 */
function CredentialsCard({
	bucketId,
	connection,
	canEdit,
	onChanged
}: {
	bucketId: string;
	connection: ConnectionView;
	canEdit: boolean;
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [revealed, setRevealed] = useState<{
		noun: string;
		value: string;
	} | null>(null);
	const [stored, setStored] = useState(false);
	const [keyOpen, setKeyOpen] = useState(false);
	const [busy, setBusy] = useState(false);
	const [keyForm] = Form.useForm<{
		source: 'jwks' | 'jwksUri';
		jwksText?: string;
		jwksUri?: string;
		signingAlg?: string;
	}>();
	const keySource = Form.useWatch('source', keyForm);
	const available: CredentialKind[] = connection.availableCredentialKinds;
	const base = connectionsApi(bucketId, connection.id);

	async function issue(
		kind: CredentialKind,
		extra: Record<string, unknown> = {}
	) {
		const slotTaken =
			kind === 'static_token'
				? connection.staticToken !== null
				: connection.oauthCredential !== null;
		const proceed = slotTaken
			? await confirm('connection.credential.replace', {
					target: connection.displayName,
					consequences: [
						'The current credential stops working now, and every token it obtained is revoked.',
						"The directory's synchronisation fails until it has the new one; Entra may quarantine the job."
					]
				})
			: await confirm('connection.credential.issue', {
					target: connection.displayName,
					consequences: [
						'Whoever holds it can create, change and remove the people of this bucket.'
					]
				});
		if (!proceed) return;
		setBusy(true);
		try {
			const result = await request<{ secret?: string; token?: string }>(
				'POST',
				`${base}/credentials`,
				{ kind, ...extra }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			setStored(false);
			if (result.data.secret)
				setRevealed({ noun: 'client secret', value: result.data.secret });
			else if (result.data.token)
				setRevealed({ noun: 'static token', value: result.data.token });
			else {
				feedback.done(`Key credential issued for ${connection.displayName}.`);
				setKeyOpen(false);
				keyForm.resetFields();
			}
			onChanged();
		} finally {
			setBusy(false);
		}
	}

	async function revoke(slot: 'oauth' | 'static_token') {
		if (
			!(await confirm('connection.credential.revoke', {
				target: connection.displayName,
				consequences: [
					slot === 'oauth'
						? 'Every token it obtained is revoked and the directory can no longer authenticate with it.'
						: 'The directory can no longer authenticate with it.'
				]
			}))
		) {
			return;
		}
		const result = await request('DELETE', `${base}/credentials/${slot}`);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			slot === 'oauth'
				? `OAuth credential of ${connection.displayName} revoked.`
				: `Static token of ${connection.displayName} revoked.`
		);
		onChanged();
	}

	async function submitKey() {
		let values;
		try {
			values = await keyForm.validateFields();
		} catch {
			return;
		}
		const signingAlg = values.signingAlg?.trim();
		await issue('key', {
			...(values.source === 'jwksUri'
				? { jwksUri: values.jwksUri?.trim() }
				: { jwks: parseJwks(values.jwksText) }),
			...(signingAlg ? { signingAlg } : {})
		});
	}

	const oauth = connection.oauthCredential;
	const unavailable = (kind: CredentialKind) =>
		!available.includes(kind)
			? 'Switched off on this instance (Settings → SCIM).'
			: null;
	const label = (kind: CredentialKind) =>
		CREDENTIAL_KINDS.find((k) => k.kind === kind)?.label ?? kind;

	return (
		<Card title="Credentials">
			<Flex
				vertical
				gap={16}
			>
				{revealed && (
					<Flex
						vertical
						gap={8}
					>
						<SecretReveal
							secret={revealed.value}
							noun={revealed.noun}
							acknowledged={stored}
							onAcknowledged={setStored}
							acknowledgement="I've put it into the directory"
						/>
						<div>
							<Button
								disabled={!stored}
								onClick={() => setRevealed(null)}
							>
								Done
							</Button>
						</div>
					</Flex>
				)}
				<Flex
					justify="space-between"
					align="center"
					gap={12}
					wrap
				>
					<div>
						<Typography.Text strong>OAuth credential</Typography.Text>
						<br />
						<Typography.Text type="secondary">
							{oauth === null
								? 'None'
								: oauth.kind === 'secret'
									? `Client secret, issued ${when(oauth.issuedAt)}`
									: `Public key${oauth.jwksUri ? ` at ${oauth.jwksUri}` : oauth.keyCount !== undefined ? ` (${oauth.keyCount} in the set)` : ''}, issued ${when(oauth.issuedAt)}`}
						</Typography.Text>
					</div>
					{canEdit && !revealed && (
						<Flex
							gap={8}
							wrap
						>
							<Button
								disabled={busy || unavailable('secret') !== null}
								title={unavailable('secret') ?? undefined}
								onClick={() => void issue('secret')}
							>
								{oauth
									? `Replace with a ${label('secret').toLowerCase()}…`
									: 'Issue client secret'}
							</Button>
							<Button
								disabled={keyOpen || unavailable('key') !== null}
								onClick={() => {
									keyForm.resetFields();
									setKeyOpen(true);
								}}
							>
								{oauth ? 'Replace with a public key…' : 'Issue public key…'}
							</Button>
							{oauth && (
								<Button
									danger
									onClick={() => void revoke('oauth')}
								>
									Revoke…
								</Button>
							)}
						</Flex>
					)}
				</Flex>
				{canEdit && keyOpen && (
					<Card
						size="small"
						title={oauth ? 'Replace with a public key' : 'Issue a public key'}
					>
						<Form
							form={keyForm}
							layout="vertical"
							initialValues={{ source: 'jwks' }}
						>
							<Form.Item
								name="source"
								label="Public keys"
							>
								<Radio.Group
									options={[
										{ label: 'Paste a key set', value: 'jwks' },
										{ label: 'Fetch from a URL', value: 'jwksUri' }
									]}
								/>
							</Form.Item>
							{keySource === 'jwksUri' ? (
								<Form.Item
									name="jwksUri"
									label="JWKS URI"
									rules={[{ required: true, type: 'url' }]}
								>
									<Input autoComplete="off" />
								</Form.Item>
							) : (
								<Form.Item
									name="jwksText"
									label="JWKS"
									tooltip="Public keys only. A private or symmetric key is refused."
									rules={[
										{ required: true },
										{
											validator: async (_rule, text: string | undefined) => {
												if (text?.trim()) parseJwks(text);
											}
										}
									]}
								>
									<Input.TextArea
										rows={6}
										spellCheck={false}
									/>
								</Form.Item>
							)}
							<Form.Item
								name="signingAlg"
								label="Signing algorithm"
							>
								<Input
									autoComplete="off"
									placeholder="RS256"
								/>
							</Form.Item>
							<Flex gap={8}>
								<Button
									type="primary"
									loading={busy}
									onClick={() => void submitKey()}
								>
									{oauth ? 'Replace…' : 'Issue key'}
								</Button>
								<Button onClick={() => setKeyOpen(false)}>Cancel</Button>
							</Flex>
						</Form>
					</Card>
				)}
				<Flex
					justify="space-between"
					align="center"
					gap={12}
					wrap
				>
					<div>
						<Typography.Text strong>Static token</Typography.Text>
						<br />
						<Typography.Text type="secondary">
							{connection.staticToken === null
								? 'None'
								: `Issued ${when(connection.staticToken.issuedAt)}`}
						</Typography.Text>
					</div>
					{canEdit && !revealed && (
						<Flex
							gap={8}
							wrap
						>
							<Button
								disabled={busy || unavailable('static_token') !== null}
								title={unavailable('static_token') ?? undefined}
								onClick={() => void issue('static_token')}
							>
								{connection.staticToken
									? 'Replace static token…'
									: 'Issue static token'}
							</Button>
							{connection.staticToken && (
								<Button
									danger
									onClick={() => void revoke('static_token')}
								>
									Revoke…
								</Button>
							)}
						</Flex>
					)}
				</Flex>
			</Flex>
		</Card>
	);
}

interface SettingsDraft {
	displayName: string;
	claim: string;
	attribute: 'externalId' | 'userName';
	emailTrust: 'trusted' | 'untrusted';
	guard: boolean;
	count: number;
	windowAmount: number;
	windowUnit: number;
}

const SETTING_LABELS: Record<keyof SettingsDraft, string> = {
	displayName: 'Name',
	claim: 'Matching claim',
	attribute: 'Matching attribute',
	emailTrust: 'Email addresses',
	guard: 'Safeguard',
	count: 'Safeguard limit',
	windowAmount: 'Safeguard window',
	windowUnit: 'Safeguard window unit'
};

function ConnectionSettings({
	bucketId,
	connection,
	canEdit,
	onSaved
}: {
	bucketId: string;
	connection: ConnectionView;
	canEdit: boolean;
	onSaved: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const span = connection.threshold
		? windowParts(connection.threshold.windowSeconds)
		: { amount: 1, unit: 3600 };
	const baseline: SettingsDraft = {
		displayName: connection.displayName,
		claim: connection.correlation.claim,
		attribute: connection.correlation.attribute,
		emailTrust: connection.emailTrust,
		guard: connection.threshold !== undefined,
		count: connection.threshold?.count ?? 50,
		windowAmount: span.amount,
		windowUnit: span.unit
	};
	const [draft, setDraft] = useState(baseline);
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);

	const keys = Object.keys(SETTING_LABELS) as (keyof SettingsDraft)[];
	const dirty = keys.filter((k) => draft[k] !== baseline[k]);
	useLeaveGuard(dirty.length > 0, dirty.length);
	const changes: Change[] = dirty.map((key) => ({
		key,
		label: SETTING_LABELS[key],
		group: 'connection',
		from: baseline[key],
		to: draft[key]
	}));
	const set = <K extends keyof SettingsDraft>(
		key: K,
		value: SettingsDraft[K]
	) => {
		setRefusal(null);
		setDraft((d) => ({ ...d, [key]: value }));
	};
	const seconds = draft.windowAmount * draft.windowUnit;
	const windowInvalid =
		draft.guard &&
		(seconds < MIN_WINDOW_SECONDS || seconds > MAX_WINDOW_SECONDS);

	async function save() {
		if (windowInvalid) {
			setRefusal('The window must be between 5 minutes and 7 days.');
			return;
		}
		if (baseline.guard && !draft.guard) {
			const agreed = await confirm('connection.guard.off', {
				target: connection.displayName,
				consequences: [
					'The directory can then deactivate or delete any number of people at once, and nothing holds it.'
				]
			});
			if (!agreed) return;
		}
		const body: Record<string, unknown> = {};
		if (dirty.includes('displayName')) body.displayName = draft.displayName;
		if (dirty.includes('emailTrust')) body.emailTrust = draft.emailTrust;
		if (dirty.includes('claim') || dirty.includes('attribute')) {
			body.correlation = {
				claim: draft.claim.trim(),
				attribute: draft.attribute
			};
		}
		if (
			dirty.some(
				(k) =>
					k === 'guard' ||
					k === 'count' ||
					k === 'windowAmount' ||
					k === 'windowUnit'
			)
		) {
			const threshold: Threshold | null = draft.guard
				? { count: draft.count, windowSeconds: seconds }
				: null;
			body.threshold = threshold;
		}
		setSaving(true);
		try {
			const result = await request(
				'PATCH',
				connectionsApi(bucketId, connection.id),
				body
			);
			if (!result.ok) {
				if (result.status >= 500 || result.error.error_reference)
					feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			feedback.done(`Provisioning connection ${draft.displayName} saved.`);
			onSaved();
		} finally {
			setSaving(false);
		}
	}

	if (!canEdit) {
		return (
			<Card title="Settings">
				<Descriptions
					column={1}
					size="small"
					items={[
						{ label: 'Name', children: connection.displayName },
						{
							label: 'Matching',
							children: `${connection.correlation.claim} ↔ ${connection.correlation.attribute}`
						},
						{
							label: 'Email addresses',
							children:
								connection.emailTrust === 'trusted'
									? 'Treated as verified'
									: 'Treated as unverified'
						},
						{
							label: 'Safeguard',
							children: connection.threshold
								? `Hold after ${connection.threshold.count} within ${describeWindow(connection.threshold.windowSeconds)}`
								: 'Off'
						}
					]}
				/>
			</Card>
		);
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			{refusal && (
				<Alert
					type="error"
					showIcon
					title="Not saved"
					description={refusal}
				/>
			)}
			<Card title="General">
				<Flex
					vertical
					gap={12}
					style={{ maxWidth: 520 }}
				>
					<div>
						<Typography.Text strong>Name</Typography.Text>
						<Input
							aria-label="Name"
							maxLength={100}
							value={draft.displayName}
							onChange={(e) => set('displayName', e.target.value)}
						/>
					</div>
					<div>
						<Typography.Text strong>
							How a sign-in finds the account
						</Typography.Text>
						<Flex gap={8}>
							<Input
								aria-label="ID token claim"
								value={draft.claim}
								onChange={(e) => set('claim', e.target.value)}
							/>
							<span style={{ alignSelf: 'center' }}>↔</span>
							<Select
								aria-label="SCIM attribute"
								value={draft.attribute}
								onChange={(v) => set('attribute', v)}
								style={{ width: 160 }}
								options={[
									{ label: 'externalId', value: 'externalId' },
									{ label: 'userName', value: 'userName' }
								]}
							/>
						</Flex>
					</div>
					<div>
						<Typography.Text strong>
							Email addresses from the directory
						</Typography.Text>
						<Radio.Group
							value={draft.emailTrust}
							onChange={(e) =>
								set('emailTrust', e.target.value as SettingsDraft['emailTrust'])
							}
							style={{ display: 'block' }}
						>
							<Flex
								vertical
								gap={4}
							>
								<Radio value="untrusted">Treat as unverified</Radio>
								<Radio value="trusted">Treat as verified</Radio>
							</Flex>
						</Radio.Group>
					</div>
				</Flex>
			</Card>
			<Card
				title="Safeguard"
				extra={<Tag color="orange">affects who keeps access</Tag>}
			>
				<Flex
					vertical
					gap={12}
				>
					<Flex
						gap={12}
						align="start"
					>
						<Switch
							aria-label="Hold when the directory removes many people at once"
							checked={draft.guard}
							disabled={connection.hold !== undefined && baseline.guard}
							onChange={(v) => set('guard', v)}
						/>
						<div>
							<Typography.Text strong>
								Hold when the directory removes many people at once
							</Typography.Text>
							<br />
							<Typography.Text type="secondary">
								{connection.hold && baseline.guard
									? 'Release the hold before turning the safeguard off.'
									: 'While held, the people it tries to remove keep their access until someone releases the hold.'}
							</Typography.Text>
						</div>
					</Flex>
					{draft.guard && (
						<Flex
							gap={8}
							align="center"
							wrap
						>
							<span>At most</span>
							<InputNumber
								aria-label="At most"
								min={1}
								max={100000}
								precision={0}
								value={draft.count}
								onChange={(v) => set('count', v ?? 1)}
								style={{ width: 110 }}
							/>
							<span>within</span>
							<InputNumber
								aria-label="Window"
								min={1}
								precision={0}
								value={draft.windowAmount}
								onChange={(v) => set('windowAmount', v ?? 1)}
								style={{ width: 80 }}
								status={windowInvalid ? 'error' : undefined}
							/>
							<Select
								aria-label="Window unit"
								value={draft.windowUnit}
								onChange={(v) => set('windowUnit', v)}
								options={WINDOW_UNITS}
								style={{ width: 110 }}
							/>
							{windowInvalid && (
								<Typography.Text type="danger">
									between 5 minutes and 7 days
								</Typography.Text>
							)}
						</Flex>
					)}
				</Flex>
			</Card>
			<SaveBar
				changes={changes}
				saving={saving}
				onSave={() => void save()}
				onDiscard={() => {
					setRefusal(null);
					setDraft(baseline);
				}}
			/>
		</Flex>
	);
}

type HistoryView = 'all' | 'directory' | 'administrators';

/*
 * What happened to and through this connection (specs/085): everything, what the directory itself did, and
 * what administrators changed about the connection. Shown to editors only — a partial history that looks
 * complete answers the incident question wrongly.
 */
function ConnectionHistory({ connectionId }: { connectionId: string }) {
	const [view, setView] = useState<HistoryView>('all');
	const params: Record<HistoryView, Record<string, string>> = {
		all: { connection: connectionId },
		directory: { actor: `connection:${connectionId}` },
		administrators: {
			targetType: 'ProvisioningConnection',
			targetId: connectionId
		}
	};
	return (
		<RecentChanges
			title="History"
			params={params[view]}
			empty={
				view === 'directory'
					? 'The directory has changed nothing yet.'
					: 'No changes recorded for this connection yet.'
			}
			extra={
				<Segmented<HistoryView>
					size="small"
					value={view}
					onChange={setView}
					options={[
						{ value: 'all', label: 'All' },
						{ value: 'directory', label: 'By the directory' },
						{ value: 'administrators', label: 'By administrators' }
					]}
				/>
			}
		/>
	);
}
