import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Collapse,
	Descriptions,
	Dropdown,
	Flex,
	Input,
	Radio,
	Select,
	Skeleton,
	Switch,
	Tag,
	Tooltip,
	Typography
} from 'antd';
import { DownOutlined } from '@ant-design/icons';
import { providerMark } from '../../../../interactions/providerMark.js';
import { PageHeader, type Crumb } from '../../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';
import { bucketHref, connectionHref } from '../../frame/routes.js';
import { Link, useLeaveGuard, useNavigate } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { bucketCan } from '../../frame/can.js';
import { SaveBar } from '../../settings/SaveBar.js';
import type { Change } from '../../settings/model.js';
import { ADMIN_BUCKET_ID } from '../../../consts.js';
import type { BucketView } from '../bucketView.js';
import { ScheduledBanner } from '../ScheduledBanner.js';
import {
	federationApi,
	type PlainAssertionsView,
	type ProviderDetail
} from './providerTypes.js';
import { providerBlocks, useProviderActions } from './useProviderActions.js';
import { useTrySignIn } from './TrySignIn.js';
import { FederationOffNotice } from './FederationOffNotice.js';
import { BrandConflictNotice } from './BrandConflictNotice.js';
import { brandNameOf } from './brandName.js';

/*
 * One identity provider, at an address of its own (specs/084 US2): everything an operator does to it after it
 * is connected. Its cards collect into one draft and one save bar, because they are one record on the server;
 * a save that lets more people in is asked as a danger question naming exactly those changes.
 */

interface Draft {
	displayName: string;
	provisioning: 'jit' | 'existing_only';
	allowedEmailDomains: string[];
	emailTrusted: boolean;
	acceptsGlobalTokenRevocation: boolean;
	acceptsBackChannelLogout: boolean;
	acceptsIdentityAssertions: boolean;
	plainAssertions: PlainAssertionsView | null;
	clientId: string;
	// Empty means "keep the stored one": a secret is replaced, never shown or edited.
	clientSecret: string;
	scopes: string[];
	emailClaim: string;
	teamId: string;
	keyId: string;
	signingKey: string;
}

const LABELS: Record<keyof Draft, string> = {
	displayName: 'Button label',
	provisioning: 'First-time users',
	allowedEmailDomains: 'Email domains',
	emailTrusted: 'Link existing accounts by verified email',
	acceptsGlobalTokenRevocation: 'Accept global token revocation',
	acceptsBackChannelLogout: 'Accept back-channel logout',
	acceptsIdentityAssertions: 'Accept identity assertions (ID-JAG)',
	plainAssertions: 'Accept plain assertions',
	clientId: 'Client id',
	clientSecret: 'Client secret',
	scopes: 'Scopes',
	emailClaim: 'Email claim',
	teamId: 'Team id',
	keyId: 'Key id',
	signingKey: 'Signing key'
};

const SECRET_KEYS: (keyof Draft)[] = ['clientSecret', 'signingKey'];

function draftOf(p: ProviderDetail): Draft {
	return {
		displayName: p.displayName,
		provisioning: p.provisioning,
		allowedEmailDomains: p.allowedEmailDomains,
		emailTrusted: p.emailTrusted,
		acceptsGlobalTokenRevocation: p.acceptsGlobalTokenRevocation === true,
		acceptsBackChannelLogout: p.acceptsBackChannelLogout === true,
		acceptsIdentityAssertions: p.acceptsIdentityAssertions === true,
		plainAssertions: p.plainAssertions ?? null,
		clientId: p.clientId,
		clientSecret: '',
		scopes: p.scopes,
		emailClaim: p.emailClaim,
		teamId: p.teamId ?? '',
		keyId: p.keyId ?? '',
		signingKey: ''
	};
}

const same = (a: unknown, b: unknown) =>
	JSON.stringify(a) === JSON.stringify(b);

/*
 * The changes that let more people in, and those that let fewer in, each as one line (specs/084 R7). Only the
 * first kind is asked as a danger question; the second is listed in the same question so the operator sees the
 * whole of what changes who can get in.
 */
function trustLines(
	from: Draft,
	to: Draft
): { widen: string[]; narrow: string[] } {
	const widen: string[] = [];
	const narrow: string[] = [];
	if (from.provisioning !== to.provisioning) {
		(to.provisioning === 'jit' ? widen : narrow).push(
			to.provisioning === 'jit'
				? 'First-time users: an account is created for anyone the provider lets sign in.'
				: 'First-time users: only people who already have an account here.'
		);
	}
	if (!same(from.allowedEmailDomains, to.allowedEmailDomains)) {
		const added = to.allowedEmailDomains.filter(
			(d) => !from.allowedEmailDomains.includes(d)
		);
		const removed = from.allowedEmailDomains.filter(
			(d) => !to.allowedEmailDomains.includes(d)
		);
		if (to.allowedEmailDomains.length === 0) {
			widen.push('Email domains: any address may now sign in.');
		} else if (from.allowedEmailDomains.length === 0) {
			narrow.push(`Email domains: only ${to.allowedEmailDomains.join(', ')}.`);
		} else {
			if (added.length > 0)
				widen.push(`Email domains: adds ${added.join(', ')}.`);
			if (removed.length > 0) {
				narrow.push(`Email domains: removes ${removed.join(', ')}.`);
			}
		}
	}
	if (from.emailTrusted !== to.emailTrusted) {
		(to.emailTrusted ? widen : narrow).push(
			to.emailTrusted
				? 'Whoever controls an address at the provider gets the account here with that verified address.'
				: 'Existing accounts are no longer linked by email.'
		);
	}
	const signal = (
		key: 'acceptsGlobalTokenRevocation' | 'acceptsBackChannelLogout',
		name: string
	) => {
		if (from[key] !== to[key]) {
			(to[key] ? widen : narrow).push(
				to[key]
					? `${name}: the provider may end people's sessions here.`
					: `${name}: no longer accepted.`
			);
		}
	};
	signal('acceptsGlobalTokenRevocation', 'Global token revocation');
	signal('acceptsBackChannelLogout', 'Back-channel logout');
	if (from.acceptsIdentityAssertions !== to.acceptsIdentityAssertions) {
		(to.acceptsIdentityAssertions ? widen : narrow).push(
			to.acceptsIdentityAssertions
				? "Identity assertions: an agent the provider vouches for gets tokens for this project's APIs, with no consent screen."
				: 'Identity assertions: no longer accepted.'
		);
	}
	if (!same(from.plainAssertions, to.plainAssertions)) {
		(to.plainAssertions ? widen : narrow).push(
			to.plainAssertions
				? `Plain assertions: ${to.plainAssertions.applications.join(', ') || 'no application'} may present the provider's assertions for ${to.plainAssertions.apis.map((api) => api.identifier).join(', ') || 'no API'}.`
				: 'Plain assertions: no longer accepted.'
		);
	}
	return { widen, narrow };
}

export function ProviderPage({
	bucketId,
	providerId
}: {
	bucketId: string;
	providerId: string;
}) {
	const consoleBucket = bucketId === ADMIN_BUCKET_ID;
	const navigate = useNavigate();
	const actions = useProviderActions(bucketId, consoleBucket);
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [provider, setProvider] = useState<ProviderDetail | null>(null);
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	// Which endpoint just appeared because a signal was turned on, so focus can go to its Copy.
	const [justEnabled, setJustEnabled] = useState<'gtr' | 'bcl' | null>(null);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchAll = useCallback(async () => {
		try {
			const [b, p] = await Promise.all([
				request<BucketView>(
					'GET',
					`/admin/api/projects/${encodeURIComponent(bucketId)}`
				),
				request<ProviderDetail>('GET', federationApi(bucketId, providerId))
			]);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setBucket(b.data);
			if (!p.ok) {
				setLoadStatus(p.status);
				setLoadMessage(p.error.message);
				return;
			}
			setLoadStatus(null);
			setProvider(p.data);
		} finally {
			setLoading(false);
		}
	}, [bucketId, providerId]);
	useEffect(() => {
		void fetchAll();
	}, [fetchAll]);
	const reload = () => void fetchAll();

	const can = bucketCan(bucket);
	const trySignIn = useTrySignIn(bucketId, provider, can.edit);
	const listHref = consoleBucket
		? '/admin/administrators/identity-providers'
		: bucketHref(bucketId, 'identity-providers');

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="identity provider"
				backHref={bucket ? listHref : '/admin/projects'}
				backLabel={bucket ? 'Back to Identity providers' : 'Back to Projects'}
			/>
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={reload}
			/>
		);
	}

	const crumbs: Crumb[] = consoleBucket
		? [
				{ label: 'Administrators', href: '/admin/administrators' },
				{ label: 'Identity providers', href: listHref },
				{ label: provider?.displayName ?? '…' }
			]
		: [
				{ label: 'Projects', href: '/admin/projects' },
				{ label: bucket?.name ?? '…', href: bucketHref(bucketId) },
				{ label: 'Identity providers', href: listHref },
				{ label: provider?.displayName ?? '…' }
			];

	const blocks =
		bucket && provider
			? providerBlocks(bucket, provider, provider.boundConnection)
			: { disable: null, remove: null };

	const headerActions =
		provider && can.edit ? (
			<Flex gap={8}>
				{trySignIn.button}
				<Dropdown
					trigger={['click']}
					menu={{
						items: [
							provider.enabled
								? {
										key: 'disable',
										label: blocks.disable ? (
											<Tooltip title={blocks.disable}>Disable…</Tooltip>
										) : (
											'Disable…'
										),
										danger: true,
										disabled: blocks.disable !== null,
										onClick: () =>
											void actions
												.setEnabled(provider, false)
												.then((done) => done && reload())
									}
								: {
										key: 'enable',
										label: 'Enable',
										onClick: () =>
											void actions
												.setEnabled(provider, true)
												.then((done) => done && reload())
									}
						]
					}}
				>
					<Button>
						More <DownOutlined />
					</Button>
				</Dropdown>
			</Flex>
		) : undefined;

	return (
		<>
			<PageHeader
				crumbs={crumbs}
				title={
					provider ? (
						<Flex
							gap={8}
							align="center"
						>
							{providerMark(provider.recognised ?? undefined)}
							{provider.displayName}
						</Flex>
					) : (
						'…'
					)
				}
				tags={
					provider ? (
						<Tag color={provider.enabled ? 'green' : 'default'}>
							{provider.enabled ? 'Enabled' : 'Disabled'}
						</Tag>
					) : undefined
				}
				meta={
					provider ? (
						<>
							{provider.recognised ? 'Recognised provider' : 'OIDC provider'}
							{' · '}
							{provider.linkedUsers}{' '}
							{provider.linkedUsers === 1 ? 'person' : 'people'} linked
							{provider.boundConnection && (
								<>
									{' · Used by provisioning connection '}
									<Link
										href={connectionHref(bucketId, provider.boundConnection.id)}
									>
										{provider.boundConnection.displayName}
									</Link>
								</>
							)}
						</>
					) : undefined
				}
				actions={headerActions}
			/>
			{loading && !provider && <Skeleton active />}
			{bucket?.deletion && (
				<ScheduledBanner
					bucket={{ ...bucket, deletion: bucket.deletion }}
					canDelete={can.delete}
					onRestored={() => void fetchAll()}
				/>
			)}
			{provider?.warnings.includes('federation_off') && (
				<FederationOffNotice style={{ marginBottom: 16 }} />
			)}
			{provider && (
				<BrandConflictNotice
					warnings={provider.warnings}
					name={brandNameOf(provider)}
					style={{ marginBottom: 16 }}
				/>
			)}
			{trySignIn.panel}
			{bucket && provider && (
				<ProviderEditor
					key={JSON.stringify(provider)}
					bucketId={bucketId}
					bucket={bucket}
					provider={provider}
					canEdit={can.edit}
					consoleBucket={consoleBucket}
					focusEndpoint={justEnabled}
					onSaved={(turnedOn) => {
						setJustEnabled(turnedOn);
						reload();
					}}
					deleteBlocked={blocks.remove}
					onDelete={() =>
						void actions.remove(provider).then((done) => {
							if (done) void navigate(listHref);
						})
					}
				/>
			)}
		</>
	);
}

function ProviderEditor({
	bucketId,
	bucket,
	provider,
	canEdit,
	consoleBucket,
	focusEndpoint,
	onSaved,
	deleteBlocked,
	onDelete
}: {
	bucketId: string;
	bucket: BucketView;
	provider: ProviderDetail;
	canEdit: boolean;
	consoleBucket: boolean;
	focusEndpoint: 'gtr' | 'bcl' | null;
	onSaved: (turnedOn: 'gtr' | 'bcl' | null) => void;
	deleteBlocked: string | null;
	onDelete: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const baseline = draftOf(provider);
	const [draft, setDraft] = useState<Draft>(baseline);
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const [replacingSecret, setReplacingSecret] = useState(false);

	const keys = Object.keys(LABELS) as (keyof Draft)[];
	const dirty = keys.filter((key) => !same(draft[key], baseline[key]));
	useLeaveGuard(dirty.length > 0, dirty.length);
	const changes: Change[] = dirty.map((key) => ({
		key,
		label: LABELS[key],
		group: 'provider',
		from: SECRET_KEYS.includes(key) ? 'stored' : baseline[key],
		to: SECRET_KEYS.includes(key) ? 'replaced' : draft[key]
	}));

	function set<K extends keyof Draft>(key: K, value: Draft[K]) {
		setRefusal(null);
		setDraft((d) => ({ ...d, [key]: value }));
	}

	const bound = provider.boundConnection;
	const apple =
		provider.recognised === 'apple' || provider.teamId !== undefined;
	const github =
		provider.recognised !== null &&
		!provider.logoutSignals.globalTokenRevocation &&
		!provider.logoutSignals.backChannelLogout;

	async function save() {
		const { widen, narrow } = trustLines(baseline, draft);
		if (widen.length > 0) {
			const agreed = await confirm('provider.trust.widen', {
				target: provider.displayName,
				consequences: [...widen, ...narrow]
			});
			if (!agreed) return;
		}
		const body: Record<string, unknown> = Object.fromEntries(
			dirty.map((key) => [key, draft[key]])
		);
		setSaving(true);
		try {
			const result = await request(
				'PATCH',
				federationApi(bucketId, provider.id),
				body
			);
			if (!result.ok) {
				if (result.status >= 500 || result.error.error_reference) {
					feedback.failed(result);
				} else {
					setRefusal(result.error.message);
				}
				return;
			}
			feedback.done(`Identity provider ${draft.displayName} saved.`);
			const turnedOn =
				draft.acceptsGlobalTokenRevocation &&
				!baseline.acceptsGlobalTokenRevocation
					? 'gtr'
					: draft.acceptsBackChannelLogout && !baseline.acceptsBackChannelLogout
						? 'bcl'
						: null;
			onSaved(turnedOn);
		} finally {
			setSaving(false);
		}
	}

	const endpoint = (
		url: string | undefined,
		flagOn: boolean,
		capable: boolean,
		focus: boolean,
		label: string
	) => {
		if (!flagOn) return null;
		if (!capable) {
			return (
				<Typography.Text type="secondary">
					The address appears once an instance administrator turns this
					capability on in Settings.
				</Typography.Text>
			);
		}
		if (!url) {
			return (
				<Typography.Text type="secondary">
					The address to give the provider appears after you save.
				</Typography.Text>
			);
		}
		return (
			<Flex
				gap={8}
				align="center"
				wrap
			>
				<Typography.Text type="secondary">{label}</Typography.Text>
				<Typography.Text code>{url}</Typography.Text>
				<Button
					size="small"
					autoFocus={focus}
					onClick={() =>
						void navigator.clipboard.writeText(url).then(
							() => feedback.done('Address copied.'),
							() =>
								feedback.refused({
									error: 'clipboard',
									message:
										'The address could not be copied. Select it and copy it by hand.'
								})
						)
					}
				>
					Copy
				</Button>
			</Flex>
		);
	};

	if (!canEdit) {
		return (
			<Card title="Settings">
				<Descriptions
					column={1}
					size="small"
					items={[
						{ label: 'Button label', children: provider.displayName },
						{
							label: 'First-time users',
							children:
								provider.provisioning === 'jit'
									? 'An account is created for them'
									: 'Only people who already have an account here'
						},
						{
							label: 'Email domains',
							children:
								provider.allowedEmailDomains.length > 0
									? provider.allowedEmailDomains.join(', ')
									: 'Any address'
						},
						{
							label: 'Link existing accounts by verified email',
							children: provider.emailTrusted ? 'On' : 'Off'
						},
						{
							label: 'Global token revocation',
							children: provider.acceptsGlobalTokenRevocation
								? 'Accepted'
								: 'Off'
						},
						{
							label: 'Back-channel logout',
							children: provider.acceptsBackChannelLogout ? 'Accepted' : 'Off'
						},
						{
							label: 'Identity assertions (ID-JAG)',
							children: provider.acceptsIdentityAssertions ? 'Accepted' : 'Off'
						},
						{ label: 'Callback address', children: provider.callbackUri },
						{ label: 'Issuer', children: provider.issuer },
						{ label: 'Client id', children: provider.clientId }
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

			<Card title="Sign-in button">
				<Flex
					gap={24}
					align="center"
					wrap
				>
					<div style={{ minWidth: 280 }}>
						<Typography.Text strong>Button label</Typography.Text>
						<Input
							aria-label="Button label"
							value={draft.displayName}
							onChange={(e) => set('displayName', e.target.value)}
							style={{ marginTop: 4 }}
						/>
						{provider.recognised && (
							<Typography.Text
								type="secondary"
								style={{ fontSize: 12 }}
							>
								People see the provider's own branded button; this label names
								it in the console.
							</Typography.Text>
						)}
					</div>
					<div aria-hidden>
						<Typography.Text
							type="secondary"
							style={{ display: 'block', fontSize: 12 }}
						>
							Preview
						</Typography.Text>
						<Button
							icon={providerMark(provider.recognised ?? undefined)}
							tabIndex={-1}
						>
							{provider.recognised
								? provider.displayName
								: draft.displayName || '…'}
						</Button>
					</div>
				</Flex>
			</Card>

			<Card
				title="Who may sign in"
				extra={<Tag color="orange">affects who can sign in</Tag>}
			>
				<Flex
					vertical
					gap={16}
				>
					<div>
						<Typography.Text strong>First-time users</Typography.Text>
						<Radio.Group
							value={draft.provisioning}
							onChange={(e) =>
								set('provisioning', e.target.value as Draft['provisioning'])
							}
							style={{ display: 'block', marginTop: 4 }}
						>
							<Flex
								vertical
								gap={4}
							>
								<Radio value="existing_only">
									Only people who already have an account here
								</Radio>
								<Radio
									value="jit"
									disabled={bound !== null}
								>
									Create an account for them
								</Radio>
							</Flex>
						</Radio.Group>
						{bound ? (
							<Typography.Text type="secondary">
								Fixed while {bound.displayName} provisions this project: the
								directory creates the accounts.
							</Typography.Text>
						) : (
							draft.provisioning === 'jit' && (
								<Typography.Text type="secondary">
									{consoleBucket
										? 'On the console, this also needs sign-up open on this project.'
										: bucket.registrationOpen
											? 'Anyone the provider lets sign in gets an account.'
											: "Anyone the provider lets sign in gets an account, even though this project's Sign-up is closed."}
								</Typography.Text>
							)
						)}
					</div>
					<div>
						<Typography.Text strong>Email domains</Typography.Text>
						<Select
							aria-label="Email domains"
							mode="tags"
							tokenSeparators={[' ', ',']}
							placeholder="acme.com"
							value={draft.allowedEmailDomains}
							onChange={(v: string[]) => set('allowedEmailDomains', v)}
							style={{ display: 'block', marginTop: 4 }}
						/>
						<Typography.Text type="secondary">
							Empty means any address the provider vouches for. People already
							linked keep signing in whatever their domain.
						</Typography.Text>
					</div>
					<Flex
						gap={12}
						align="start"
					>
						<Switch
							aria-label={LABELS.emailTrusted}
							checked={draft.emailTrusted}
							onChange={(v) => set('emailTrusted', v)}
						/>
						<div>
							<Typography.Text strong>{LABELS.emailTrusted}</Typography.Text>
							<br />
							<Typography.Text type="secondary">
								Turn on only for a provider that really verifies addresses:
								whoever controls that address there gets the account here.
							</Typography.Text>
						</div>
					</Flex>
				</Flex>
			</Card>

			<Card
				title="Logout signals"
				extra={<Tag color="orange">affects who can sign in</Tag>}
			>
				{github ? (
					<Typography.Text type="secondary">
						{provider.displayName} sends no logout signals, so there is nothing
						to accept.
					</Typography.Text>
				) : (
					<Flex
						vertical
						gap={16}
					>
						{provider.logoutSignals.globalTokenRevocation && (
							<Flex
								vertical
								gap={4}
							>
								<Flex
									gap={12}
									align="start"
								>
									<Switch
										aria-label={LABELS.acceptsGlobalTokenRevocation}
										checked={draft.acceptsGlobalTokenRevocation}
										onChange={(v) => set('acceptsGlobalTokenRevocation', v)}
									/>
									<div>
										<Typography.Text strong>
											Accept global token revocation (Okta Universal Logout)
										</Typography.Text>
										<br />
										<Typography.Text type="secondary">
											Lets the provider end everything one of its users holds
											here — sessions and tokens — with a request signed by its
											own keys. The account is not deactivated.
										</Typography.Text>
									</div>
								</Flex>
								{endpoint(
									provider.globalTokenRevocationEndpoint,
									baseline.acceptsGlobalTokenRevocation,
									provider.capabilities.globalTokenRevocation,
									focusEndpoint === 'gtr',
									'Endpoint to give the provider'
								)}
							</Flex>
						)}
						{provider.logoutSignals.backChannelLogout && (
							<Flex
								vertical
								gap={4}
							>
								<Flex
									gap={12}
									align="start"
								>
									<Switch
										aria-label={LABELS.acceptsBackChannelLogout}
										checked={draft.acceptsBackChannelLogout}
										onChange={(v) => set('acceptsBackChannelLogout', v)}
									/>
									<div>
										<Typography.Text strong>
											Accept back-channel logout (Keycloak, Auth0, Ping)
										</Typography.Text>
										<br />
										<Typography.Text type="secondary">
											When a person signs out at the provider, or an
											administrator there ends their session, the sessions here
											that sign-in reached end too. Turn on the provider's
											“session required” option so only that session ends.
										</Typography.Text>
									</div>
								</Flex>
								{endpoint(
									provider.backChannelLogoutEndpoint,
									baseline.acceptsBackChannelLogout,
									provider.capabilities.backChannelLogout,
									focusEndpoint === 'bcl',
									'Back-channel logout address to register'
								)}
							</Flex>
						)}
					</Flex>
				)}
			</Card>

			<AssertionsCard
				bucketId={bucketId}
				provider={provider}
				github={github}
				checked={draft.acceptsIdentityAssertions}
				onChange={(v) => set('acceptsIdentityAssertions', v)}
				plain={draft.plainAssertions}
				onPlainChange={(v) => set('plainAssertions', v)}
			/>

			<Card title="Connection">
				<Flex
					vertical
					gap={12}
				>
					<div>
						<Typography.Text strong>Callback address</Typography.Text>{' '}
						<Typography.Text
							code
							copyable={{ text: provider.callbackUri }}
						>
							{provider.callbackUri}
						</Typography.Text>
						<br />
						<Typography.Text type="secondary">
							The same for every provider of this project. If sign-in fails on
							the provider's own page, this address not being registered there
							is the likeliest cause.
						</Typography.Text>
						{provider.callbackStability === 'provisional' && (
							<Alert
								style={{ marginTop: 8 }}
								type="warning"
								showIcon
								title="This address will change"
								description="This project has no address of its own. If it gets a path or a host, the callback changes and the provider must be given the new one."
							/>
						)}
					</div>
					<div>
						<Typography.Text strong>Issuer</Typography.Text>{' '}
						<Typography.Text code>{provider.issuer}</Typography.Text>
						{provider.tenant && (
							<>
								{' · '}
								<Typography.Text>
									Account type {provider.tenant}
								</Typography.Text>
							</>
						)}
						<br />
						<Typography.Text type="secondary">
							Can't be changed: people's links name this provider, and a
							different issuer would hand their accounts to other people.
							Connect a new provider instead.
						</Typography.Text>
					</div>
					<div style={{ maxWidth: 480 }}>
						<Typography.Text strong>Client id</Typography.Text>
						<Input
							aria-label="Client id"
							autoComplete="off"
							value={draft.clientId}
							onChange={(e) => set('clientId', e.target.value)}
							style={{ marginTop: 4 }}
						/>
					</div>
					<div style={{ maxWidth: 480 }}>
						<Typography.Text strong>
							{apple ? 'Signing key' : 'Client secret'}
						</Typography.Text>{' '}
						{replacingSecret ? (
							apple ? (
								<Input.TextArea
									aria-label="New signing key"
									rows={4}
									autoComplete="off"
									placeholder="-----BEGIN PRIVATE KEY-----"
									value={draft.signingKey}
									onChange={(e) => set('signingKey', e.target.value)}
								/>
							) : (
								<Input.Password
									aria-label="New client secret"
									autoComplete="new-password"
									value={draft.clientSecret}
									onChange={(e) => set('clientSecret', e.target.value)}
								/>
							)
						) : (
							<>
								<Typography.Text type="secondary">
									•••••• stored
								</Typography.Text>{' '}
								<Button
									size="small"
									onClick={() => setReplacingSecret(true)}
								>
									{apple ? 'Replace key' : 'Replace secret'}
								</Button>
							</>
						)}
					</div>
					{apple && (
						<Flex
							gap={12}
							wrap
						>
							<div>
								<Typography.Text strong>Team id</Typography.Text>
								<Input
									aria-label="Team id"
									autoComplete="off"
									value={draft.teamId}
									onChange={(e) => set('teamId', e.target.value)}
								/>
							</div>
							<div>
								<Typography.Text strong>Key id</Typography.Text>
								<Input
									aria-label="Key id"
									autoComplete="off"
									value={draft.keyId}
									onChange={(e) => set('keyId', e.target.value)}
								/>
							</div>
						</Flex>
					)}
					<Collapse
						ghost
						items={[
							{
								key: 'advanced',
								label: 'Advanced',
								children: (
									<Flex
										vertical
										gap={12}
										style={{ maxWidth: 480 }}
									>
										<div>
											<Typography.Text strong>Scopes</Typography.Text>
											<Select
												aria-label="Scopes"
												mode="tags"
												tokenSeparators={[' ', ',']}
												value={draft.scopes}
												onChange={(v: string[]) => set('scopes', v)}
												style={{ display: 'block' }}
											/>
										</div>
										<div>
											<Typography.Text strong>Email claim</Typography.Text>
											<Input
												aria-label="Email claim"
												value={draft.emailClaim}
												onChange={(e) => set('emailClaim', e.target.value)}
											/>
										</div>
									</Flex>
								)
							}
						]}
					/>
				</Flex>
			</Card>

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
						<Typography.Text strong>Delete identity provider</Typography.Text>
						<br />
						<Typography.Text type="secondary">
							{deleteBlocked ??
								"Removes the provider and every person's link to it. Their accounts stay."}
						</Typography.Text>
					</div>
					<Button
						danger
						disabled={deleteBlocked !== null}
						onClick={onDelete}
					>
						Delete identity provider…
					</Button>
				</Flex>
			</Card>

			<SaveBar
				changes={changes}
				saving={saving}
				onSave={() => void save()}
				onDiscard={() => {
					setRefusal(null);
					setReplacingSecret(false);
					setDraft(baseline);
				}}
			/>
		</Flex>
	);
}

/*
 * Whether this provider may vouch for people to the project's APIs with identity assertions (specs/108): the
 * receiving side of MCP enterprise-managed authorization. Its own card, apart from the logout signals, because
 * it lets more in rather than fewer.
 */
function AssertionsCard({
	bucketId,
	provider,
	github,
	checked,
	onChange,
	plain,
	onPlainChange
}: {
	bucketId: string;
	provider: ProviderDetail;
	github: boolean;
	checked: boolean;
	onChange: (value: boolean) => void;
	plain: PlainAssertionsView | null;
	onPlainChange: (value: PlainAssertionsView | null) => void;
}) {
	const lastUsed = provider.assertionsLastUsedAt;
	return (
		<Card
			title="Agents and assertions"
			extra={<Tag color="orange">affects who can get tokens</Tag>}
		>
			{github ? (
				<Typography.Text type="secondary">
					{provider.displayName} publishes no signing keys, so its assertions
					cannot be trusted.
				</Typography.Text>
			) : (
				<Flex
					vertical
					gap={8}
				>
					<Flex
						gap={12}
						align="start"
					>
						<Switch
							aria-label={LABELS.acceptsIdentityAssertions}
							checked={checked}
							onChange={onChange}
						/>
						<div>
							<Typography.Text strong>
								{LABELS.acceptsIdentityAssertions}
							</Typography.Text>
							<br />
							<Typography.Text type="secondary">
								Lets an agent your users signed in to through this provider get
								tokens for this project's APIs without a browser or a consent
								screen. The provider decides who may; this project still limits
								what.
							</Typography.Text>
						</div>
					</Flex>
					{!provider.capabilities.identityAssertions && (
						<Typography.Text type="secondary">
							Turned off for this instance in Settings → Grants.
						</Typography.Text>
					)}
					<Typography.Text type="secondary">
						Last used:{' '}
						{lastUsed === null
							? 'never'
							: new Date(lastUsed * 1000).toLocaleString()}
					</Typography.Text>
					<Collapse
						ghost
						items={[
							{
								key: 'plain',
								label: 'Advanced: accept plain assertions',
								children: (
									<PlainAssertionsEditor
										bucketId={bucketId}
										value={plain}
										onChange={onPlainChange}
									/>
								)
							}
						]}
					/>
				</Flex>
			)}
		</Card>
	);
}

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

interface ApplicationChoice {
	clientId: string;
	clientName?: string;
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
}

/* Every application is listed, so one that cannot present them says why rather than going missing. */
function plainChoiceOf(application: ApplicationChoice) {
	const name = application.clientName
		? `${application.clientName} (${application.clientId})`
		: application.clientId;
	const why =
		application.tokenEndpointAuthMethod === 'none'
			? 'does not authenticate'
			: application.grantTypes.includes(JWT_BEARER)
				? null
				: 'lacks the JWT bearer grant';
	return {
		value: application.clientId,
		label: why ? `${name} — ${why}` : name,
		disabled: why !== null
	};
}

/*
 * A plain RFC 7523 assertion names no client and no grant (specs/108 story 4), so the trust itself says which of
 * the project's applications may present one and the most it may yield. The server checks every name.
 */
function PlainAssertionsEditor({
	bucketId,
	value,
	onChange
}: {
	bucketId: string;
	value: PlainAssertionsView | null;
	onChange: (value: PlainAssertionsView | null) => void;
}) {
	const [applications, setApplications] = useState<ApplicationChoice[]>([]);
	useEffect(() => {
		let live = true;
		void request<ApplicationChoice[]>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucketId)}/clients`
		).then((result) => {
			if (live && result.ok) setApplications(result.data);
		});
		return () => {
			live = false;
		};
	}, [bucketId]);
	const apis = value?.apis ?? [];
	const setApis = (next: PlainAssertionsView['apis']) =>
		onChange({ applications: value?.applications ?? [], apis: next });
	return (
		<Flex
			vertical
			gap={8}
			style={{ maxWidth: 560 }}
		>
			<Flex
				gap={12}
				align="start"
			>
				<Switch
					aria-label={LABELS.plainAssertions}
					checked={value !== null}
					onChange={(on) =>
						onChange(on ? { applications: [], apis: [] } : null)
					}
				/>
				<Typography.Text type="secondary">
					For a trusted system that signs short JWTs about a person — a legacy
					identity system being migrated, a partner platform. Each assertion is
					accepted once.
				</Typography.Text>
			</Flex>
			{value && (
				<>
					<div>
						<Typography.Text strong>
							Applications that may present them
						</Typography.Text>
						<Select
							aria-label="Applications that may present plain assertions"
							mode="multiple"
							showSearch={{ optionFilterProp: 'label' }}
							options={applications.map(plainChoiceOf)}
							value={value.applications}
							onChange={(applications: string[]) =>
								onChange({ ...value, applications })
							}
							style={{ display: 'block' }}
						/>
					</div>
					<Typography.Text strong>
						APIs and scopes they may yield
					</Typography.Text>
					{apis.map((api, index) => (
						<Flex
							key={index}
							gap={8}
						>
							<Input
								aria-label="API"
								placeholder="https://api.example.com/"
								value={api.identifier}
								onChange={(e) =>
									setApis(
										apis.map((a, i) =>
											i === index ? { ...a, identifier: e.target.value } : a
										)
									)
								}
							/>
							<Select
								aria-label="Scopes"
								mode="tags"
								placeholder="Scopes"
								value={api.scopes}
								onChange={(scopes: string[]) =>
									setApis(
										apis.map((a, i) => (i === index ? { ...a, scopes } : a))
									)
								}
								style={{ minWidth: 200 }}
							/>
							<Button
								aria-label="Remove API"
								onClick={() => setApis(apis.filter((_, i) => i !== index))}
							>
								Remove
							</Button>
						</Flex>
					))}
					<Button
						onClick={() => setApis([...apis, { identifier: '', scopes: [] }])}
					>
						Add API
					</Button>
				</>
			)}
		</Flex>
	);
}
