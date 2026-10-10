import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Switch,
	Tag,
	Typography,
	Tooltip,
	Alert,
	Flex,
	Space
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { PageHeader } from '../frame/PageHeader.js';
import { EmptyState, LoadFailed, NoAccess } from '../frame/states.js';
import { bucketHref } from '../frame/routes.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { bucketCan, type BucketCan } from '../frame/can.js';
import type { UserBucket, User } from '../../../adapters/types.js';
import { FederationPanel } from './FederationPanel.js';
import { BucketKeysPanel } from './BucketKeysPanel.js';
import { BucketActivityPanel } from './BucketActivityPanel.js';
import { UserIdentities } from './UserIdentities.js';
import { ProvisioningPanel, type ConnectionView } from './ProvisioningPanel.js';
import { BucketGroupsPanel, type GroupView } from './BucketGroupsPanel.js';

/*
 * What the API actually returns, which is not the stored record: `presentUser` removes the password
 * hash and the authenticator secret, and substitutes the two derived facts an operator may see. Typed
 * from that shape rather than from `User` so the console cannot accidentally reference a field the
 * server does not send.
 */
type EndUser = Omit<User, 'password' | 'totp' | 'lockedLocally'> & {
	totpEnrolled: boolean;
	totpEnrolledAt: string | null;
	groups?: { id: string; displayName: string; provisionedBy?: string }[];
	lockedLocally?: { at: string; by: string; reason: string };
};

/*
 * The bucket as the API presents it. The administrators' own bucket carries `reserved`, and the page
 * changes shape on it: its accounts are administrators, managed on their own page, and only its settings
 * and activity belong here.
 */
type BucketView = UserBucket & {
	reserved?: 'administrators';
	can?: Partial<BucketCan>;
};

interface CreateValues {
	email: string;
	password: string;
	claimsText?: string;
}

interface AssignValues {
	connectionId: string;
	userName?: string;
	externalId?: string;
}

interface EditValues {
	active: boolean;
	claimsText?: string;
	/* The groups administrators keep that this user is in; a directory's groups are not edited here. */
	groupIds?: string[];
}

interface BucketSettingsValues {
	name: string;
	passwordLogin?: boolean;
	registrationOpen?: boolean;
	emailVerificationRequired?: boolean;
	verificationMethod?: 'link' | 'code';
	totpRequired?: boolean;
}

/*
 * The claims an account releases, edited as JSON text. Parsed here only to refuse what is not an object
 * before a round trip; which names are allowed is the server's rule, and its refusal is shown as is.
 */
function parseClaims(text: string | undefined): Record<string, unknown> {
	const trimmed = text?.trim();
	if (!trimmed) return {};
	const value: unknown = JSON.parse(trimmed);
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		throw new TypeError('claims must be a JSON object');
	}
	return value as Record<string, unknown>;
}

function ClaimsField() {
	return (
		<Form.Item
			name="claimsText"
			label="Claims"
			tooltip='JSON, e.g. {"name":"Ada Lovelace","locale":"en-GB"}. Released to a client only when the claims setting names them under a scope the client was granted. sub, email and email_verified come from the account itself and cannot be set here.'
			rules={[
				{
					validator: async (_rule, text: string | undefined) => {
						parseClaims(text);
					}
				}
			]}
		>
			<Input.TextArea
				rows={4}
				spellCheck={false}
				placeholder='{"name":"Ada Lovelace"}'
			/>
		</Form.Item>
	);
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

/* The bucket's areas, each an address of its own (specs/079); only the one shown loads. */
export type BucketTab =
	'users' | 'userGroups' | 'providers' | 'provisioning' | 'keys' | 'activity';

const TABS: { key: BucketTab; segment: string; label: string }[] = [
	{ key: 'users', segment: 'users', label: 'Users' },
	{ key: 'userGroups', segment: 'user-groups', label: 'User groups' },
	{
		key: 'providers',
		segment: 'identity-providers',
		label: 'Identity providers'
	},
	{ key: 'provisioning', segment: 'provisioning', label: 'Provisioning' },
	{ key: 'keys', segment: 'keys', label: 'Signing keys' },
	{ key: 'activity', segment: 'activity', label: 'Activity' }
];

/* Whether the caller may open an area at all; the others are open to anyone who can read the bucket. */
function tabAllowed(key: BucketTab, can: BucketCan): boolean {
	if (key === 'keys') return can.edit;
	if (key === 'activity') return can.readActivity;
	return true;
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
	const [usersError, setUsersError] = useState<string | null>(null);
	// Only read on the administrators' bucket, where requiring verification needs your own address proven.
	const [selfVerified, setSelfVerified] = useState(true);
	const [sendingVerification, setSendingVerification] = useState(false);
	const [rows, setRows] = useState<EndUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [createOpen, setCreateOpen] = useState(false);
	const [editUser, setEditUser] = useState<EndUser | null>(null);
	const [pwUser, setPwUser] = useState<EndUser | null>(null);
	const [identitiesUser, setIdentitiesUser] = useState<EndUser | null>(null);
	const [assignUser, setAssignUser] = useState<EndUser | null>(null);
	const [lockUser, setLockUser] = useState<EndUser | null>(null);
	const [unlockUser, setUnlockUser] = useState<EndUser | null>(null);
	const [connections, setConnections] = useState<ConnectionView[]>([]);
	/*
	 * The two panels below each fetch their own list, and each changes what the other shows: a connection
	 * closes its provider to just-in-time creation, and a provider's state is a connection's warning. A
	 * bumped key is how one tells the other to look again without either holding the other's state.
	 */
	const [federationKey, setFederationKey] = useState(0);
	const [provisioningKey, setProvisioningKey] = useState(0);
	const [groupsKey, setGroupsKey] = useState(0);
	const [bucketGroups, setBucketGroups] = useState<GroupView[]>([]);
	const [bucketEditOpen, setBucketEditOpen] = useState(false);
	/*
	 * Both stay on the settings dialog until something changes: a refusal there explains a rule (what to
	 * enable before password sign-in can go), and an advisory says what a saved setting does not yet do.
	 * A toast that fades in eight seconds is gone before either has been read.
	 */
	const [settingsRefusal, setSettingsRefusal] = useState<string | null>(null);
	const [settingsAdvisory, setSettingsAdvisory] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const [createForm] = Form.useForm<CreateValues>();
	const [editForm] = Form.useForm<EditValues>();
	const [pwForm] = Form.useForm<{ password: string }>();
	const [assignForm] = Form.useForm<AssignValues>();
	const [lockForm] = Form.useForm<{ reason: string }>();
	const [bucketForm] = Form.useForm<BucketSettingsValues>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
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
			// The administrators' bucket answers no user list here — its accounts have their own page.
			if (b.data.reserved === 'administrators') {
				const me = await request<{ verified?: boolean }>(
					'GET',
					'/admin/api/me'
				);
				if (me.ok) setSelfVerified(me.data.verified === true);
				return;
			}
			/*
			 * The users table names each user's groups and offers their connections, and the user-groups
			 * area offers the bucket's users — read here for the area shown, since the panels that used to
			 * hand these up are no longer mounted beside it.
			 */
			if (tab === 'users' || tab === 'userGroups') {
				const [u, g, c] = await Promise.all([
					request<EndUser[]>('GET', `${base}/users`),
					request<{ groups: GroupView[] }>('GET', `${base}/groups`),
					request<ConnectionView[]>('GET', `${base}/provisioning-connections`)
				]);
				if (u.ok) {
					setRows(u.data);
					setUsersError(null);
				} else {
					setUsersError(u.error.message);
				}
				// Not the users area's own read, so a failure is said rather than turned into a failed page.
				if (g.ok) setBucketGroups(g.data.groups);
				else feedback.failed(g);
				if (c.ok) setConnections(c.data);
				else feedback.failed(c);
			}
		} finally {
			setLoading(false);
		}
	}, [base, tab, feedback]);
	function load() {
		setLoading(true);
		return fetchBucket();
	}
	useEffect(() => {
		void fetchBucket();
	}, [fetchBucket]);

	const can = bucketCan(bucket);

	const connectionName = (id: string) =>
		connections.find((c) => c.id === id)?.displayName ?? id;

	async function onCreate({ claimsText, ...values }: CreateValues) {
		const claims = parseClaims(claimsText);
		setSaving(true);
		try {
			const body = Object.keys(claims).length ? { ...values, claims } : values;
			const result = await request('POST', `${base}/users`, body);
			if (!result.ok) {
				feedback.failed(result, createForm);
				return;
			}
			feedback.done(`User ${values.email} created.`);
			setCreateOpen(false);
			createForm.resetFields();
			await load();
		} finally {
			setSaving(false);
		}
	}

	function openEdit(row: EndUser) {
		setEditUser(row);
		editForm.setFieldsValue({
			groupIds: (row.groups ?? [])
				.filter((g) => !g.provisionedBy)
				.map((g) => g.id),
			active: row.active,
			claimsText: row.claims ? JSON.stringify(row.claims, null, 2) : ''
		});
	}

	async function onEdit({ claimsText, groupIds, ...values }: EditValues) {
		const user = editUser;
		if (!user) return;
		setSaving(true);
		try {
			/*
			 * Membership is changed through the group's own routes, one per group that changed, so a change
			 * made here and one made from the group read the same in the audit trail.
			 */
			const kept = new Set(
				bucketGroups.filter((g) => !g.provisionedBy).map((g) => g.id)
			);
			const before = new Set(
				(user.groups ?? []).map((g) => g.id).filter((id) => kept.has(id))
			);
			const after = new Set(groupIds ?? []);
			const groupsBase = `${base}/groups`;
			const uid = encodeURIComponent(user._id);
			for (const gid of after) {
				if (before.has(gid)) continue;
				const added = await request(
					'POST',
					`${groupsBase}/${encodeURIComponent(gid)}/members`,
					{ userIds: [user._id] }
				);
				if (!added.ok) feedback.failed(added);
			}
			for (const gid of before) {
				if (after.has(gid)) continue;
				const removed = await request(
					'DELETE',
					`${groupsBase}/${encodeURIComponent(gid)}/members/${uid}`
				);
				if (!removed.ok) feedback.failed(removed);
			}
			setGroupsKey((k) => k + 1);
			// An emptied field clears the claims: an edit replaces the account's whole set.
			const result = await request('PATCH', `${base}/users/${uid}`, {
				...values,
				claims: parseClaims(claimsText)
			});
			if (!result.ok) {
				feedback.failed(result, editForm);
				return;
			}
			feedback.done(`User ${user.email} updated.`);
			setEditUser(null);
			await load();
		} finally {
			setSaving(false);
		}
	}

	/*
	 * The password is typed in its dialog, which closes before the question is asked: a confirmation on top
	 * of a dialog is a second modal the operator has to read through the first.
	 */
	async function onSetPassword(values: { password: string }) {
		const user = pwUser;
		if (!user) return;
		setPwUser(null);
		pwForm.resetFields();
		if (
			!(await confirm('user.password.set', {
				target: user.email,
				consequences: [
					'The password they use now stops working.',
					'Whoever is told the new one can sign in as them.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'POST',
			`${base}/users/${encodeURIComponent(user._id)}/password`,
			values
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`New password set for ${user.email}.`);
	}

	async function onAssign(values: AssignValues) {
		const user = assignUser;
		if (!user) return;
		const userName = values.userName?.trim();
		const externalId = values.externalId?.trim();
		const body = {
			connectionId: values.connectionId,
			...(userName ? { userName } : {}),
			...(externalId ? { externalId } : {})
		};
		const connection = connectionName(values.connectionId);
		setAssignUser(null);
		if (
			!(await confirm('user.connection.assign', {
				target: user.email,
				consequences: [
					`${connection} then owns this account: it is read-only here except for a local lock.`,
					'It cannot be handed back from the console.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'POST',
			`${base}/users/${encodeURIComponent(user._id)}/connection`,
			body
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`User ${user.email} handed over to ${connection}.`);
		assignForm.resetFields();
		setProvisioningKey((k) => k + 1);
		await load();
	}

	async function onDelete(user: EndUser) {
		if (
			!(await confirm('user.delete', {
				target: user.email,
				consequences: [
					'Their sign-in sessions, consents and every issued token are destroyed immediately — they are signed out everywhere.',
					'The account cannot be restored.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'DELETE',
			`${base}/users/${encodeURIComponent(user._id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`User ${user.email} deleted.`);
		await load();
	}

	async function onSignOut(user: EndUser) {
		if (
			!(await confirm('user.signOut', {
				target: user.email,
				consequences: [
					'Every session and token ends at once and relying parties are told.',
					'The account stays active: they can sign in again, and will be asked to consent again.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'POST',
			`${base}/users/${encodeURIComponent(user._id)}/sign-out`
		);
		if (!result.ok) {
			// The server's own reason: a partial sweep names the areas whose records survived.
			feedback.failed(result);
			return;
		}
		feedback.done(`${user.email} signed out everywhere.`);
		await load();
	}

	async function onResetTotp(user: EndUser) {
		if (
			!(await confirm('user.totp.reset', {
				target: user.email,
				consequences: [
					'Their current authenticator stops working immediately.',
					'They are signed out everywhere.',
					'They set up a new one at their next sign-in.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'DELETE',
			`${base}/users/${encodeURIComponent(user._id)}/totp`
		);
		if (!result.ok) {
			// The server's own reason — a partial session sweep says which areas survived, and replacing
			// that with a generic sentence would hide the half that matters.
			feedback.failed(result);
			return;
		}
		feedback.done(`Authenticator of ${user.email} reset.`);
		await load();
	}

	async function onLock({ reason }: { reason: string }) {
		const user = lockUser;
		if (!user) return;
		setSaving(true);
		try {
			const result = await request(
				'POST',
				`${base}/users/${encodeURIComponent(user._id)}/lock`,
				{ reason: reason.trim() }
			);
			if (!result.ok) {
				feedback.failed(result, lockForm);
				return;
			}
			feedback.done(`User ${user.email} locked.`);
			setLockUser(null);
			lockForm.resetFields();
			await load();
		} finally {
			setSaving(false);
		}
	}

	async function onUnlock() {
		const user = unlockUser;
		if (!user) return;
		setSaving(true);
		try {
			const result = await request(
				'POST',
				`${base}/users/${encodeURIComponent(user._id)}/unlock`
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(`User ${user.email} unlocked.`);
			setUnlockUser(null);
			await load();
		} finally {
			setSaving(false);
		}
	}

	function openSettings() {
		setSettingsRefusal(null);
		setSettingsAdvisory(null);
		bucketForm.setFieldsValue({
			passwordLogin: bucket?.passwordLogin !== false,
			name: bucket?.name ?? '',
			registrationOpen: bucket?.registrationOpen ?? true,
			emailVerificationRequired: bucket?.emailVerificationRequired ?? false,
			verificationMethod: bucket?.verificationMethod ?? 'link',
			totpRequired: bucket?.totpRequired ?? false
		});
		setBucketEditOpen(true);
	}

	async function onSaveBucket(values: BucketSettingsValues) {
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
			feedback.done(`Bucket ${values.name} updated.`);
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
				// This route answers a reason code rather than a message; the status says which one.
				feedback.refused({
					error: 'verification_not_sent',
					message:
						result.status === 429
							? 'A message was sent recently. Check your inbox, or try again in a minute.'
							: result.status === 409
								? 'Mail delivery is not configured, so no message can be sent.'
								: 'The message could not be sent. Try again later.'
				});
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

	function userActions(row: EndUser): RowAction[] {
		if (!can.manageUsers) return [];
		/*
		 * The directory owns a provisioned record, and the server refuses these for one. Shown disabled with
		 * the reason rather than hidden, so the operator learns where the change belongs instead of
		 * wondering why the items vanished — and folded into one line, since the reason is one.
		 */
		const managed = row.provisionedBy
			? `Managed by ${connectionName(row.provisionedBy)} — change this user in the directory`
			: null;
		const items: RowAction[] = [
			{
				key: 'edit',
				label: 'Edit…',
				group: 'edit',
				blocked: managed,
				onClick: () => openEdit(row)
			},
			{
				key: 'password',
				label: 'Set password…',
				group: 'edit',
				blocked: managed,
				onClick: () => setPwUser(row)
			},
			{
				key: 'identities',
				label: 'Linked identities…',
				group: 'edit',
				onClick: () => setIdentitiesUser(row)
			},
			// Allowed on a provisioned user too: it ends access and edits nothing the connection owns.
			{
				key: 'signOut',
				label: 'Sign out everywhere',
				group: 'state',
				onClick: () => void onSignOut(row)
			}
		];
		// Offered only where there is something to reset.
		if (row.totpEnrolled) {
			items.push({
				key: 'totp',
				label: 'Reset authenticator',
				group: 'state',
				onClick: () => void onResetTotp(row)
			});
		}
		// The local lock is the one thing an administrator keeps over a provisioned user.
		items.push(
			row.lockedLocally
				? {
						key: 'unlock',
						label: 'Unlock…',
						group: 'state',
						onClick: () => setUnlockUser(row)
					}
				: {
						key: 'lock',
						label: 'Lock…',
						group: 'state',
						onClick: () => {
							lockForm.resetFields();
							setLockUser(row);
						}
					}
		);
		// Handing a user to a connection is a provisioning write, so it is the bucket owners' (`can.edit`).
		if (can.edit && !row.provisionedBy && connections.length > 0) {
			items.push({
				key: 'assign',
				label: 'Hand over to connection…',
				group: 'handover',
				onClick: () => {
					assignForm.resetFields();
					setAssignUser(row);
				}
			});
		}
		items.push({
			key: 'delete',
			label: 'Delete',
			group: 'danger',
			blocked: managed,
			onClick: () => void onDelete(row)
		});
		return items;
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

	const shownTab = reserved ? 'activity' : tab;
	const tabs = reserved
		? []
		: TABS.filter((t) => tabAllowed(t.key, can)).map((t) => ({
				key: t.key,
				label: t.label,
				href: bucketHref(bucketId, t.segment)
			}));
	/*
	 * An area the caller may not open is said to be so at its own address, rather than quietly showing
	 * Users there: the address keeps meaning what it says, and a link someone shared explains itself.
	 */
	const shownTabLabel = TABS.find((t) => t.key === shownTab)?.label ?? '';
	const tabRefused = bucket !== null && !tabAllowed(shownTab, can);

	const newUserButton = (
		<Button
			type="primary"
			icon={<PlusOutlined />}
			onClick={() => setCreateOpen(true)}
		>
			New user
		</Button>
	);

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Buckets', href: '/admin/buckets' },
					{ label: bucket?.name ?? '…' }
				]}
				title={bucket?.name ?? '…'}
				tags={
					reserved ? (
						<Tag color="gold">Administrators</Tag>
					) : bucket?._id === 'redfox' ? (
						<Tag>Default</Tag>
					) : undefined
				}
				actions={
					bucket && can.editSettings ? (
						<Button onClick={openSettings}>Edit…</Button>
					) : undefined
				}
				tabs={tabs}
				activeTab={shownTab}
			/>
			{reserved && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="This is the console's own bucket"
					description="Its accounts are the administrators of this instance and are managed on the Administrators page. Here you set how they sign in: whether people may register, whether they must verify their address, and whether an authenticator app is required. Turning email verification on needs mail delivery configured and your own address verified."
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
			{bucket && !tabRefused && !reserved && (
				<>
					{shownTab === 'users' && !can.manageUsers && <ReadOnlyNotice />}
					{(shownTab === 'userGroups' ||
						shownTab === 'providers' ||
						shownTab === 'provisioning') &&
						!can.edit && <ReadOnlyNotice />}
				</>
			)}
			{shownTab === 'users' &&
				!tabRefused &&
				(usersError !== null ? (
					<LoadFailed
						reason={usersError}
						onRetry={() => void load()}
					/>
				) : (
					<>
						{can.manageUsers && (
							<Flex
								justify="end"
								style={{ marginBottom: 12 }}
							>
								{newUserButton}
							</Flex>
						)}
						<Table<EndUser>
							rowKey="_id"
							loading={loading}
							dataSource={rows}
							locale={{
								emptyText: (
									<EmptyState
										purpose="No end users in this bucket yet. People register here, arrive through an identity provider or a directory, or are created by an administrator."
										create={can.manageUsers ? newUserButton : undefined}
									/>
								)
							}}
							columns={[
								{
									title: 'Email',
									dataIndex: 'email',
									// The way into the user: their editor, where the record is theirs to edit.
									render: (email: string, row: EndUser) =>
										can.manageUsers && !row.provisionedBy ? (
											<Typography.Link onClick={() => openEdit(row)}>
												{email}
											</Typography.Link>
										) : (
											email
										)
								},
								{
									title: 'Groups',
									dataIndex: 'groups',
									render: (groups: EndUser['groups']) =>
										(groups ?? []).map((g) => (
											<Tag
												key={g.id}
												color={g.provisionedBy ? 'purple' : undefined}
											>
												{g.displayName}
											</Tag>
										))
								},
								{
									title: 'Status',
									render: (_: unknown, row: EndUser) => (
										<Space
											size={4}
											wrap
										>
											{row.active ? (
												<Tag color="green">Active</Tag>
											) : (
												<Tag>Deactivated</Tag>
											)}
											{row.lockedLocally && (
												<Tooltip
													title={`Locked ${new Date(row.lockedLocally.at).toLocaleString()}: ${row.lockedLocally.reason}`}
												>
													<Tag color="red">Locked</Tag>
												</Tooltip>
											)}
											{!row.verified && <Tag color="orange">Unverified</Tag>}
										</Space>
									)
								},
								{
									// Whether there is an authenticator, and since when. Never the secret behind it —
									// the server does not send it, to any role.
									title: 'Authenticator',
									dataIndex: 'totpEnrolled',
									render: (enrolled: boolean, row: EndUser) =>
										enrolled ? (
											<Tooltip
												title={
													row.totpEnrolledAt
														? `Enrolled ${new Date(row.totpEnrolledAt).toLocaleString()}`
														: 'Enrolled'
												}
											>
												<Tag color="green">enrolled</Tag>
											</Tooltip>
										) : (
											<Tag>none</Tag>
										)
								},
								{
									/*
									 * Who owns the record. A connection's display name where it is known; its id
									 * otherwise, because a stale list must not make a managed user look local.
									 */
									title: 'Managed by',
									dataIndex: 'provisionedBy',
									render: (provisionedBy: string | undefined) =>
										provisionedBy ? (
											<Tag color="purple">
												Managed by {connectionName(provisionedBy)}
											</Tag>
										) : (
											<Typography.Text type="secondary">local</Typography.Text>
										)
								},
								{
									title: '',
									render: (_: unknown, row: EndUser) => (
										<RowActions
											name={row.email}
											items={userActions(row)}
										/>
									)
								}
							]}
						/>
					</>
				))}

			{/*
			 * Mounted only once the bucket is known: each panel fetches on mount, and before the bucket
			 * loads `reserved` reads false, so the console's own bucket would fire requests it refuses.
			 */}
			{bucket && !reserved && shownTab === 'userGroups' && (
				<BucketGroupsPanel
					bucketId={bucketId}
					can={can}
					users={rows}
					connections={connections}
					refreshKey={groupsKey}
					onGroups={setBucketGroups}
					onChanged={() => void load()}
				/>
			)}
			{bucket && !reserved && shownTab === 'providers' && (
				<FederationPanel
					key={federationKey}
					bucketId={bucketId}
					canEdit={can.edit}
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

			<UserIdentities
				bucketId={bucketId}
				user={identitiesUser}
				canRemove={can.manageUsers}
				onClose={() => setIdentitiesUser(null)}
			/>

			<Modal
				title="New user"
				open={createOpen}
				onCancel={() => setCreateOpen(false)}
				onOk={() => createForm.submit()}
				okText="Create user"
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<CreateValues>
					form={createForm}
					layout="vertical"
					onFinish={onCreate}
					scrollToFirstError
				>
					{/* An address beside a password reads as a sign-in form to a browser, which filled both
					    with the administrator's own credentials. See the same pair in Admins.tsx. */}
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="password"
						label="Initial password"
						rules={[{ required: true, min: 8 }]}
					>
						<Input.Password
							autoComplete="new-password"
							placeholder="at least 8 characters"
						/>
					</Form.Item>
					<ClaimsField />
				</Form>
			</Modal>

			<Modal
				title={
					assignUser
						? `Hand ${assignUser.email} over to a connection`
						: 'Hand over to a connection'
				}
				open={assignUser !== null}
				onCancel={() => setAssignUser(null)}
				onOk={() => assignForm.submit()}
				okText="Continue"
				destroyOnHidden
			>
				<Typography.Paragraph type="secondary">
					The directory then owns this account: it is read-only here except for
					a local lock. Give the names the directory knows this person by, so
					its next sync matches them instead of creating someone new.
				</Typography.Paragraph>
				<Form<AssignValues>
					form={assignForm}
					layout="vertical"
					onFinish={onAssign}
					scrollToFirstError
				>
					<Form.Item
						name="connectionId"
						label="Connection"
						rules={[{ required: true }]}
					>
						<Select
							options={connections.map((c) => ({
								label: c.displayName,
								value: c.id
							}))}
						/>
					</Form.Item>
					<Form.Item
						name="userName"
						label="userName"
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="externalId"
						label="externalId"
						dependencies={['userName']}
						rules={[
							({ getFieldValue }) => ({
								validator: async (_rule, value: string | undefined) => {
									const userName = (
										getFieldValue('userName') as string | undefined
									)?.trim();
									if (!userName && !value?.trim()) {
										throw new Error('give a userName, an externalId, or both');
									}
								}
							})
						]}
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title={editUser ? `Edit ${editUser.email}` : 'Edit user'}
				open={editUser !== null}
				onCancel={() => setEditUser(null)}
				onOk={() => editForm.submit()}
				okText="Save"
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form
					form={editForm}
					layout="vertical"
					onFinish={onEdit}
					scrollToFirstError
				>
					<Form.Item
						name="groupIds"
						label="User groups"
						tooltip="Groups administrators keep. A directory's groups are changed in the directory."
					>
						<Select
							mode="multiple"
							showSearch={{ optionFilterProp: 'label' }}
							options={bucketGroups
								.filter((g) => !g.provisionedBy)
								.map((g) => ({ label: g.displayName, value: g.id }))}
						/>
					</Form.Item>
					<Form.Item
						name="active"
						label="Active"
						valuePropName="checked"
					>
						<Switch />
					</Form.Item>
					<ClaimsField />
				</Form>
			</Modal>

			<Modal
				title={pwUser ? `Set password for ${pwUser.email}` : 'Set password'}
				open={pwUser !== null}
				onCancel={() => setPwUser(null)}
				onOk={() => pwForm.submit()}
				okText="Continue"
				destroyOnHidden
			>
				<Form
					form={pwForm}
					layout="vertical"
					onFinish={onSetPassword}
					scrollToFirstError
				>
					<Form.Item
						name="password"
						label="New password"
						rules={[{ required: true, min: 8 }]}
					>
						{/* This sets somebody else's password, so a stored one is never the right value. */}
						<Input.Password autoComplete="new-password" />
					</Form.Item>
				</Form>
			</Modal>

			{/*
			 * The reason is the confirmation: it is asked for because it is kept on the record, and typing it
			 * is a deliberate act no stray click makes.
			 */}
			<Modal
				title={lockUser ? `Lock ${lockUser.email}` : 'Lock user'}
				open={lockUser !== null}
				onCancel={() => setLockUser(null)}
				onOk={() => lockForm.submit()}
				okText="Lock"
				okButtonProps={{ danger: true }}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Typography.Paragraph type="secondary">
					Their sessions and tokens end at once, and they cannot sign in until
					an administrator unlocks them — whatever a directory managing them
					sends.
				</Typography.Paragraph>
				<Form<{ reason: string }>
					form={lockForm}
					layout="vertical"
					onFinish={onLock}
					scrollToFirstError
				>
					<Form.Item
						name="reason"
						label="Reason"
						tooltip="Kept on the user's record, not in the audit trail, because it may name a person or an incident."
						rules={[{ required: true, whitespace: true, max: 500 }]}
					>
						<Input.TextArea rows={3} />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title={unlockUser ? `Unlock ${unlockUser.email}?` : 'Unlock user?'}
				open={unlockUser !== null}
				onCancel={() => setUnlockUser(null)}
				onOk={() => void onUnlock()}
				okText="Unlock"
				okButtonProps={{ danger: true }}
				confirmLoading={saving}
				destroyOnHidden
			>
				{unlockUser?.lockedLocally && (
					<Typography.Paragraph>
						Locked {new Date(unlockUser.lockedLocally.at).toLocaleString()}:{' '}
						{unlockUser.lockedLocally.reason}
					</Typography.Paragraph>
				)}
				<Typography.Paragraph type="secondary">
					They can sign in again at once. Unlock only once whatever the lock was
					for has been dealt with.
				</Typography.Paragraph>
			</Modal>

			<Modal
				title="Edit bucket"
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
					<Form.Item
						name="name"
						label="Name"
						rules={[{ required: true }]}
					>
						<Input />
					</Form.Item>
					{/*
					 * Not offered on the console's own bucket: it holds no provider, so turning password sign-in
					 * off is always refused there, and a switch that can only fail is not a control.
					 */}
					{!reserved && (
						<Form.Item
							name="passwordLogin"
							label="Accept email and password sign-in"
							valuePropName="checked"
							tooltip="Turn off for a bucket whose users must come from an identity provider. Refused unless this bucket has an enabled provider."
						>
							<Switch />
						</Form.Item>
					)}
					{/*
					 * Disabled rather than hidden when password sign-in is off: the setting still exists and
					 * still means something, and hiding it would leave an operator wondering where it went.
					 * The server accepts it either way and returns the same explanation.
					 */}
					<Form.Item
						name="totpRequired"
						label="Require an authenticator app"
						valuePropName="checked"
						tooltip="Password sign-ins to this bucket must also carry a 6-digit code. Anyone without an authenticator sets one up at their next sign-in. Federated sign-in is not affected — the identity provider owns that policy."
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
