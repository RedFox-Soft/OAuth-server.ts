import { useCallback, useEffect, useState } from 'react';
import {
	Button,
	Modal,
	Form,
	Input,
	Select,
	Switch,
	Tag,
	Typography,
	Alert,
	Skeleton
} from 'antd';
import { PageHeader } from '../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../frame/states.js';
import { bucketHref } from '../frame/routes.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { bucketCan, type BucketCan } from '../frame/can.js';
import { reservedOf } from '../../consts.js';
import { useMe } from '../frame/me.js';
import { BucketOverview } from './BucketOverview.js';
import { BucketSettings } from './BucketSettings.js';
import type { BucketSummary, BucketView } from './bucketView.js';
import { FederationPanel } from './FederationPanel.js';
import { BucketKeysPanel } from './BucketKeysPanel.js';
import { BucketActivityPanel } from './BucketActivityPanel.js';
import { ProvisioningPanel, type ConnectionView } from './ProvisioningPanel.js';
import { BucketGroupsPanel } from './BucketGroupsPanel.js';
import { BucketUsersPanel } from './BucketUsersPanel.js';

interface BucketSettingsValues {
	name?: string;
	passwordLogin?: boolean;
	registrationOpen?: boolean;
	emailVerificationRequired?: boolean;
	verificationMethod?: 'link' | 'code';
	totpRequired?: boolean;
}

/*
 * Said once, above an area the caller may look at but not change, instead of a page of controls that
 * would each answer 403.
 */
function ReadOnlyNotice() {
	return (
		<Alert
			type="info"
			showIcon
			style={{ marginBottom: 16 }}
			title="Only members of the group that owns this bucket can change this."
		/>
	);
}

/*
 * The bucket's areas, each an address of its own (specs/079); only the one shown loads. The Overview is the
 * bucket's bare address and Settings comes last, with the acts that break things at its foot (specs/081).
 */
export type BucketTab =
	| 'overview'
	| 'users'
	| 'userGroups'
	| 'providers'
	| 'provisioning'
	| 'keys'
	| 'activity'
	| 'settings';

const TABS: { key: BucketTab; segment?: string; label: string }[] = [
	{ key: 'overview', label: 'Overview' },
	{ key: 'users', segment: 'users', label: 'Users' },
	{ key: 'userGroups', segment: 'user-groups', label: 'User groups' },
	{
		key: 'providers',
		segment: 'identity-providers',
		label: 'Identity providers'
	},
	{ key: 'provisioning', segment: 'provisioning', label: 'Provisioning' },
	{ key: 'keys', segment: 'keys', label: 'Signing keys' },
	{ key: 'activity', segment: 'activity', label: 'Activity' },
	{ key: 'settings', segment: 'settings', label: 'Settings' }
];

/*
 * The console's own bucket shows two areas (specs/080): its identity providers, which a super administrator
 * configures as on any bucket, and its activity. Its accounts are on the Administrators page, and its groups,
 * provisioning and keys stay closed to it.
 */
const CONSOLE_TABS: readonly BucketTab[] = ['providers', 'activity'];

/* Whether the caller may open an area at all; the others are open to anyone who can read the bucket. */
function tabAllowed(
	key: BucketTab,
	can: BucketCan,
	reserved: boolean
): boolean {
	if (reserved) {
		if (key === 'providers') return can.read;
		if (key === 'activity') return can.readActivity;
		return false;
	}
	if (key === 'overview' || key === 'settings') return can.read;
	if (key === 'keys') return can.edit;
	if (key === 'activity') return can.readActivity;
	return true;
}

/* What turning password sign-in to the console off would do (GET /admin/api/admins/sign-in-readiness). */
interface SignInReadiness {
	passwordLogin: boolean;
	signedInWith: string | null;
	callerLinkedAt: string[];
	reachableSuperAdministrators: number;
	unlinkedAdministrators: { id: string; email: string }[];
}

/* Whether this session could turn password sign-in off: it came in through a provider the caller is linked at. */
function mayTurnPasswordsOff(readiness: SignInReadiness | null): boolean {
	return (
		readiness !== null &&
		readiness.signedInWith !== null &&
		readiness.callerLinkedAt.includes(readiness.signedInWith)
	);
}

export function BucketDetail({
	bucketId,
	tab
}: {
	bucketId: string;
	tab: BucketTab;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}`;
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [bucket, setBucket] = useState<BucketView | null>(null);
	// The status a failed read answered, so a missing or foreign bucket is told apart from a fault.
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	// Only read on the administrators' bucket, where requiring verification needs your own address proven.
	const [selfVerified, setSelfVerified] = useState(true);
	const [sendingVerification, setSendingVerification] = useState(false);
	const [connections, setConnections] = useState<ConnectionView[]>([]);
	/*
	 * The two panels below each fetch their own list, and each changes what the other shows: a connection
	 * closes its provider to just-in-time creation, and a provider's state is a connection's warning. A
	 * bumped key is how one tells the other to look again without either holding the other's state.
	 */
	const [federationKey, setFederationKey] = useState(0);
	const [provisioningKey, setProvisioningKey] = useState(0);
	const [bucketEditOpen, setBucketEditOpen] = useState(false);
	/*
	 * Both stay on the settings dialog until something changes: a refusal there explains a rule (what to
	 * enable before password sign-in can go), and an advisory says what a saved setting does not yet do.
	 * A toast that fades in eight seconds is gone before either has been read.
	 */
	const [settingsRefusal, setSettingsRefusal] = useState<string | null>(null);
	const [readiness, setReadiness] = useState<SignInReadiness | null>(null);
	const [settingsAdvisory, setSettingsAdvisory] = useState<string | null>(null);
	// The counts the Overview, the header's held tag and the delete dialog read (specs/081).
	const [summary, setSummary] = useState<BucketSummary | null>(null);
	const [summaryFailed, setSummaryFailed] = useState(false);
	// Group names for the header and Settings; a group the caller is not in is named generically.
	const [groupNames, setGroupNames] = useState<Map<string, string>>(new Map());
	const { me } = useMe();
	const [saving, setSaving] = useState(false);
	const [loading, setLoading] = useState(true);
	const [bucketForm] = Form.useForm<BucketSettingsValues>();

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchBucket = useCallback(async () => {
		try {
			const b = await request<BucketView>('GET', base);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setLoadStatus(null);
			setBucket(b.data);
			if (b.data.reserved !== 'administrators') {
				const [s, scope] = await Promise.all([
					request<BucketSummary>('GET', `${base}/summary`),
					request<{ available: { id: string; name: string }[] }>(
						'GET',
						'/admin/api/scope'
					)
				]);
				setSummary(s.ok ? s.data : null);
				setSummaryFailed(!s.ok);
				if (scope.ok) {
					setGroupNames(
						new Map(scope.data.available.map((g) => [g.id, g.name]))
					);
				}
			}
			// The administrators' bucket answers no user list here — its accounts have their own page.
			if (b.data.reserved === 'administrators') {
				const me = await request<{ verified?: boolean }>(
					'GET',
					'/admin/api/me'
				);
				if (me.ok) setSelfVerified(me.data.verified === true);
				return;
			}
			// The user-groups area names each group's connection; the panel that lists them is not mounted beside it.
			if (tab === 'userGroups') {
				const c = await request<ConnectionView[]>(
					'GET',
					`${base}/provisioning-connections`
				);
				if (c.ok) setConnections(c.data);
				else feedback.failed(c);
			}
		} finally {
			setLoading(false);
		}
	}, [base, tab, feedback]);
	function load() {
		return fetchBucket();
	}
	useEffect(() => {
		void fetchBucket();
	}, [fetchBucket]);

	const can = bucketCan(bucket);

	function openSettings() {
		setSettingsRefusal(null);
		setSettingsAdvisory(null);
		setReadiness(null);
		if (bucket?.reserved === 'administrators') {
			void request<SignInReadiness>(
				'GET',
				'/admin/api/admins/sign-in-readiness'
			).then((answer) => {
				if (answer.ok) setReadiness(answer.data);
			});
		}
		bucketForm.setFieldsValue({
			passwordLogin: bucket?.passwordLogin !== false,
			// Renamed on Settings → General for every bucket that has a Settings tab (specs/081).
			...(bucket?.reserved === 'administrators' ? { name: bucket.name } : {}),
			registrationOpen: bucket?.registrationOpen ?? true,
			emailVerificationRequired: bucket?.emailVerificationRequired ?? false,
			verificationMethod: bucket?.verificationMethod ?? 'link',
			totpRequired: bucket?.totpRequired ?? false
		});
		setBucketEditOpen(true);
	}

	/*
	 * Turning password sign-in to the console off is the one change here that can shut people out, so it is
	 * asked about with who it shuts out (C2). The server refuses it unless this session came in through a
	 * linked provider; asking first only spares the operator a refusal they could have read.
	 *
	 * The settings dialog steps aside while the question is asked, so no dialog opens on top of another, and
	 * comes back with what was typed either way: to be saved, or to be changed.
	 */
	async function confirmPasswordsOff(values: BucketSettingsValues) {
		const turningOff =
			bucket?.reserved === 'administrators' &&
			bucket.passwordLogin &&
			values.passwordLogin === false;
		if (!turningOff) return true;
		const unlinked = readiness?.unlinkedAdministrators ?? [];
		setBucketEditOpen(false);
		const agreed = await confirm('bucket.passwordSignIn.off', {
			target: 'the console',
			consequences: [
				`${String(readiness?.reachableSuperAdministrators ?? 0)} super administrator(s) can still sign in through an identity provider.`,
				unlinked.length === 0
					? 'Every administrator has a linked identity.'
					: `These administrators have no linked identity and will not be able to sign in: ${unlinked.map((a) => a.email).join(', ')}.`,
				'No new identity can be linked while password sign-in is off.'
			]
		});
		setBucketEditOpen(true);
		bucketForm.setFieldsValue(values);
		return agreed;
	}

	async function onSaveBucket(values: BucketSettingsValues) {
		if (!(await confirmPasswordsOff(values))) return;
		setSaving(true);
		try {
			setSettingsAdvisory(null);
			const result = await request<{ advisory?: string }>(
				'PATCH',
				base,
				values
			);
			if (!result.ok) {
				/*
				 * The server's own reason, kept on the dialog. Turning password sign-in off on a bucket with no
				 * enabled provider is refused with an explanation of what to do first — a rule about the whole
				 * bucket, not one field, so it stays above the form until the next edit. A refusal naming a
				 * field lands on that field, and a fault is reported as one.
				 */
				if (
					result.status >= 500 ||
					result.error.error_reference ||
					result.error.field
				) {
					feedback.failed(result, bucketForm);
				} else {
					setSettingsRefusal(result.error.message);
				}
				return;
			}
			feedback.done(`Bucket ${bucket?.name ?? ''} updated.`);
			/*
			 * A write can succeed and still have something to say — an inert second factor, or the console
			 * open to anyone without proof of address. Shown, not swallowed: the same sentence an agent reads,
			 * and the dialog stays open so it is read before it is dismissed.
			 */
			if (result.data.advisory) setSettingsAdvisory(result.data.advisory);
			else setBucketEditOpen(false);
			await load();
		} finally {
			setSaving(false);
		}
	}

	const reserved = bucket?.reserved === 'administrators';

	async function onVerifySelf() {
		setSendingVerification(true);
		try {
			const result = await request<{
				alreadyVerified?: boolean;
				codeUrl?: string;
			}>('POST', '/admin/api/me/verification');
			if (!result.ok) {
				feedback.refused(result);
				return;
			}
			if (result.data.alreadyVerified) {
				setSelfVerified(true);
				return;
			}
			if (result.data.codeUrl) {
				window.open(result.data.codeUrl, '_blank', 'noopener');
				feedback.done(
					'Verification code sent. Enter the code from your email on the page that opened.'
				);
			} else {
				feedback.done(
					'Verification link sent. Follow it from your inbox, then reload this page.'
				);
			}
		} finally {
			setSendingVerification(false);
		}
	}

	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="bucket"
				backHref="/admin/buckets"
				backLabel="Back to Buckets"
			/>
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={() => void load()}
			/>
		);
	}

	// The console's bucket has no Users area or Overview yet; those addresses land on its providers.
	const shownTab =
		reserved && (tab === 'users' || tab === 'overview') ? 'providers' : tab;
	const tabs = TABS.filter(
		(t) =>
			(!reserved || CONSOLE_TABS.includes(t.key)) &&
			tabAllowed(t.key, can, reserved)
	).map((t) => ({
		key: t.key,
		label: t.label,
		href: bucketHref(bucketId, t.segment)
	}));
	const special = bucket ? reservedOf(bucket._id) : null;
	const groupName = bucket
		? (groupNames.get(bucket.ownerGroupId) ?? 'a group you are not in')
		: '';
	/*
	 * An area the caller may not open is said to be so at its own address, rather than quietly showing
	 * Users there: the address keeps meaning what it says, and a link someone shared explains itself.
	 */
	const shownTabLabel = TABS.find((t) => t.key === shownTab)?.label ?? '';
	const tabRefused = bucket !== null && !tabAllowed(shownTab, can, reserved);

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Buckets', href: '/admin/buckets' },
					{ label: bucket?.name ?? '…' }
				]}
				title={bucket?.name ?? '…'}
				tags={
					<>
						{special === 'administrators' && (
							<Tag color="gold">Administrators</Tag>
						)}
						{special === 'default' && <Tag>Default</Tag>}
						{summary && summary.held > 0 && (
							<Tag color="red">Deprovisioning held</Tag>
						)}
					</>
				}
				meta={
					bucket && !reserved ? (
						<>
							Owned by {groupName}
							{bucket.issuer ? (
								<>
									{' · '}
									<Typography.Text copyable>{bucket.issuer}</Typography.Text>
								</>
							) : null}
						</>
					) : undefined
				}
				description={
					special === 'default'
						? "Projects without a bucket of their own sign people in here. Served at the server's root. It cannot be moved, re-addressed or deleted."
						: undefined
				}
				actions={
					bucket && can.editSettings ? (
						<Button onClick={openSettings}>
							{reserved ? 'Edit…' : 'Edit sign-in…'}
						</Button>
					) : undefined
				}
				tabs={tabs}
				activeTab={shownTab}
			/>
			{loading && !bucket && <Skeleton active />}
			{reserved && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="This is the console's own bucket"
					description="Its accounts are the administrators of this instance and are managed on the Administrators page. Here you set how they sign in: with a password, through your organisation's identity provider, or both; whether people may register; whether they must verify their address; and whether an authenticator app is required for password sign-in. Whoever an identity provider here vouches for can be linked to an administrator account, so only super administrators configure them."
				/>
			)}
			{reserved && !selfVerified && can.editSettings && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					title="Your own address is not verified"
					description="Requiring administrators to verify their email is refused until you have verified yours, so the requirement can never lock you out."
					action={
						<Button
							size="small"
							loading={sendingVerification}
							onClick={() => void onVerifySelf()}
						>
							Verify my address
						</Button>
					}
				/>
			)}
			{tabRefused && (
				<NoAccess
					what={`bucket's ${shownTabLabel.toLowerCase()}`}
					backHref={reserved ? '/admin/buckets' : bucketHref(bucketId)}
					backLabel={reserved ? 'Back to Buckets' : 'Go to Users'}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'overview' && (
				<BucketOverview
					bucket={bucket}
					summary={summary}
					summaryFailed={summaryFailed}
					can={can}
					superAdmin={me?.superAdmin === true}
					groupName={groupName}
					onOpenSignIn={openSettings}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'settings' && (
				<BucketSettings
					bucket={bucket}
					can={can}
					groupName={groupName}
					onChanged={() => void load()}
				/>
			)}
			{bucket && !tabRefused && !reserved && (
				<>
					{shownTab === 'users' && !can.manageUsers && <ReadOnlyNotice />}
					{(shownTab === 'userGroups' ||
						shownTab === 'providers' ||
						shownTab === 'provisioning') &&
						!can.edit && <ReadOnlyNotice />}
				</>
			)}
			{bucket && !reserved && !tabRefused && shownTab === 'users' && (
				<BucketUsersPanel
					bucketId={bucketId}
					can={can}
				/>
			)}

			{/*
			 * Mounted only once the bucket is known: each panel fetches on mount, and before the bucket
			 * loads `reserved` reads false, so the console's own bucket would fire requests it refuses.
			 */}
			{bucket && !reserved && shownTab === 'userGroups' && (
				<BucketGroupsPanel
					bucketId={bucketId}
					can={can}
					connections={connections}
					onChanged={() => void load()}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'providers' && (
				<FederationPanel
					key={federationKey}
					bucketId={bucketId}
					consoleBucket={reserved}
					canEdit={reserved ? can.editSettings : can.edit}
					onChanged={() => {
						void load();
						setProvisioningKey((k) => k + 1);
					}}
				/>
			)}
			{bucket && !reserved && shownTab === 'provisioning' && (
				<ProvisioningPanel
					bucketId={bucketId}
					canEdit={can.edit}
					refreshKey={provisioningKey}
					onConnections={setConnections}
					onChanged={(event) => {
						void load();
						if (event === 'created') setFederationKey((k) => k + 1);
					}}
				/>
			)}
			{bucket && !reserved && !tabRefused && shownTab === 'keys' && (
				<BucketKeysPanel
					bucketId={bucketId}
					canEdit={can.edit}
				/>
			)}
			{bucket && !tabRefused && shownTab === 'activity' && (
				<BucketActivityPanel bucketId={bucketId} />
			)}

			<Modal
				title={reserved ? 'Edit bucket' : 'Sign-in'}
				open={bucketEditOpen}
				onCancel={() => setBucketEditOpen(false)}
				onOk={() => bucketForm.submit()}
				okText="Save"
				confirmLoading={saving}
				destroyOnHidden
			>
				{settingsRefusal !== null && (
					<Alert
						type="error"
						showIcon
						style={{ marginBottom: 16 }}
						title={settingsRefusal}
					/>
				)}
				{settingsAdvisory !== null && (
					<Alert
						type="warning"
						showIcon
						style={{ marginBottom: 16 }}
						title="Saved, with a warning"
						description={settingsAdvisory}
					/>
				)}
				<Form<BucketSettingsValues>
					form={bucketForm}
					layout="vertical"
					onFinish={onSaveBucket}
					onValuesChange={() => setSettingsRefusal(null)}
					scrollToFirstError
				>
					{reserved && (
						<Form.Item
							name="name"
							label="Name"
							rules={[{ required: true }]}
						>
							<Input />
						</Form.Item>
					)}
					{/*
					 * On the console's own bucket the switch is disabled, with the reason beside it, until this
					 * session has come in through a linked provider: the server would refuse anything else.
					 */}
					<Form.Item
						name="passwordLogin"
						label="Accept email and password sign-in"
						valuePropName="checked"
						tooltip={
							reserved
								? "Turn off so administrators sign in only through this bucket's identity providers. Allowed only from a session that signed in through one of them, and never while it would leave no super administrator a way in."
								: 'Turn off for a bucket whose users must come from an identity provider. Refused unless this bucket has an enabled provider.'
						}
						extra={
							reserved &&
							bucket.passwordLogin &&
							!mayTurnPasswordsOff(readiness)
								? "To turn it off, sign in through one of this bucket's identity providers first."
								: undefined
						}
					>
						<Switch
							disabled={
								reserved &&
								bucket.passwordLogin &&
								!mayTurnPasswordsOff(readiness)
							}
						/>
					</Form.Item>
					{/*
					 * Disabled rather than hidden when password sign-in is off: the setting still exists and
					 * still means something, and hiding it would leave an operator wondering where it went.
					 * The server accepts it either way and returns the same explanation.
					 */}
					<Form.Item
						name="totpRequired"
						label="Require an authenticator app"
						valuePropName="checked"
						tooltip="Password sign-ins to this bucket must also carry a 6-digit code. Anyone without an authenticator sets one up at their next sign-in. Applies to password sign-in only: provider sign-ins use the provider's own second factor."
					>
						<Switch disabled={bucket?.passwordLogin === false} />
					</Form.Item>
					<Form.Item
						name="registrationOpen"
						label="Self-service registration open"
						valuePropName="checked"
						tooltip={
							reserved
								? 'Anyone who can reach the console sign-in page may register an administrator account. Each gets a personal group and nothing else.'
								: 'Allow visitors to register accounts in this bucket'
						}
					>
						<Switch />
					</Form.Item>
					{/*
					 * The method before the requirement: a message is sent in whichever method is saved, so it is
					 * chosen first — on the console's own bucket, before verifying your own address.
					 */}
					<Form.Item
						name="verificationMethod"
						label="Verification method"
						tooltip="How an account confirms its email"
					>
						<Select
							options={[
								{ label: 'Email link', value: 'link' },
								{ label: '6-digit code', value: 'code' }
							]}
						/>
					</Form.Item>
					<Form.Item
						name="emailVerificationRequired"
						label="Require email verification"
						valuePropName="checked"
						tooltip="Accounts must confirm their email before they can sign in. An unverified account that signs in is sent a new message."
					>
						<Switch />
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
