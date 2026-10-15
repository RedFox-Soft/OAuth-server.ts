import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Dropdown, Skeleton, Typography } from 'antd';
import { DownOutlined } from '@ant-design/icons';
import { PageHeader } from '../../frame/PageHeader.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';
import { bucketHref, userHref } from '../../frame/routes.js';
import { request } from '../../frame/request.js';
import { bucketCan } from '../../frame/can.js';
import { AccountStatusTags } from '../../accounts/AccountStatusTags.js';
import { LockModal } from '../../accounts/LockModal.js';
import type { BucketView } from '../bucketView.js';
import type { ConnectionView } from '../ProvisioningPanel.js';
import { nameOf, usersApi, type EndUser } from './endUser.js';
import { useUserActions } from './useUserActions.js';
import { UserProfileTab } from './UserProfileTab.js';
import { UserSignInTab } from './UserSignInTab.js';
import { UserGroupsTab } from './UserGroupsTab.js';
import { UserActivityTab } from './UserActivityTab.js';

export type UserTab = 'profile' | 'signIn' | 'groups' | 'activity';

const TABS: { key: UserTab; segment?: string; label: string }[] = [
	{ key: 'profile', label: 'Profile' },
	{ key: 'signIn', segment: 'sign-in-methods', label: 'Sign-in methods' },
	{ key: 'groups', segment: 'groups', label: 'Groups' },
	{ key: 'activity', segment: 'activity', label: 'Activity' }
];

/*
 * One person in a bucket, at an address of their own (specs/082): who they are, whether they can sign in
 * and why not, and the acts on them at the weight each carries. The acts that end access sit in the
 * header, where an incident is handled in two clicks; the ones that cannot be undone sit at the foot of
 * the Profile, in a Danger zone.
 */
export function UserPage({
	bucketId,
	userId,
	tab
}: {
	bucketId: string;
	userId: string;
	tab: UserTab;
}) {
	const actions = useUserActions(bucketId);
	const [bucket, setBucket] = useState<BucketView | null>(null);
	const [user, setUser] = useState<EndUser | null>(null);
	const [connections, setConnections] = useState<ConnectionView[]>([]);
	const [loadStatus, setLoadStatus] = useState<number | null>(null);
	const [loadMessage, setLoadMessage] = useState<string | null>(null);
	const [lockOpen, setLockOpen] = useState(false);
	const [loading, setLoading] = useState(true);

	// Every state write follows an await, so the mount effect calls this without setting `loading` first.
	const fetchAll = useCallback(async () => {
		try {
			const b = await request<BucketView>(
				'GET',
				`/admin/api/projects/${encodeURIComponent(bucketId)}`
			);
			if (!b.ok) {
				setLoadStatus(b.status);
				setLoadMessage(b.error.message);
				return;
			}
			setBucket(b.data);
			// The administrators' accounts have their own page; nothing about them is read here.
			if (b.data.reserved === 'administrators') return;
			const [u, c] = await Promise.all([
				request<EndUser>('GET', usersApi(bucketId, userId)),
				request<ConnectionView[]>(
					'GET',
					`/admin/api/projects/${encodeURIComponent(bucketId)}/provisioning-connections`
				)
			]);
			if (!u.ok) {
				setLoadStatus(u.status);
				setLoadMessage(u.error.message);
				return;
			}
			setLoadStatus(null);
			setUser(u.data);
			if (c.ok) setConnections(c.data);
		} finally {
			setLoading(false);
		}
	}, [bucketId, userId]);
	useEffect(() => {
		void fetchAll();
	}, [fetchAll]);
	const reload = () => void fetchAll();

	const can = bucketCan(bucket);
	const usersHref = bucketHref(bucketId, 'users');

	if (bucket?.reserved === 'administrators') {
		return (
			<NoAccess
				what="user here"
				backHref="/admin/administrators"
				backLabel="Go to Administrators"
			/>
		);
	}
	if (loadStatus !== null) {
		return loadStatus === 403 || loadStatus === 404 ? (
			<NoAccess
				what="user"
				backHref={loadStatus === 404 && bucket ? usersHref : '/admin/projects'}
				backLabel={
					loadStatus === 404 && bucket ? 'Back to Users' : 'Back to Projects'
				}
			/>
		) : (
			<LoadFailed
				reason={loadMessage ?? undefined}
				onRetry={reload}
			/>
		);
	}

	const connectionName = (id: string) =>
		connections.find((c) => c.id === id)?.displayName ?? id;
	const managedBy = user?.provisionedBy
		? connectionName(user.provisionedBy)
		: null;
	const name = user ? nameOf(user) : null;

	const tabs = TABS.filter((t) => t.key !== 'activity' || can.edit).map(
		(t) => ({
			key: t.key,
			label: t.label,
			href: userHref(bucketId, userId, t.segment)
		})
	);
	const shownTab = tab === 'activity' && bucket && !can.edit ? null : tab;

	const after = (done: boolean) => {
		if (done) reload();
	};

	const headerActions =
		user && can.manageUsers ? (
			<>
				<Button onClick={() => void actions.signOut(user).then(after)}>
					Sign out everywhere
				</Button>
				{user.lockedLocally ? (
					<Button onClick={() => void actions.unlock(user).then(after)}>
						Unlock…
					</Button>
				) : (
					<Button
						danger
						onClick={() => setLockOpen(true)}
					>
						Lock…
					</Button>
				)}
				{/* `active` belongs to whoever manages the person; for a provisioned one, the directory. */}
				{!user.provisionedBy && (
					<Dropdown
						trigger={['click']}
						menu={{
							items: [
								// A password chosen by the person, never by an administrator (specs/089).
								...(bucket?.passwordLogin !== false
									? [
											{
												key: 'invite',
												label: 'Send invitation…',
												onClick: () => void actions.invite(user).then(after)
											}
										]
									: []),
								user.active
									? {
											key: 'deactivate',
											label: 'Deactivate',
											danger: true,
											onClick: () => void actions.deactivate(user).then(after)
										}
									: {
											key: 'activate',
											label: 'Activate',
											onClick: () => void actions.activate(user).then(after)
										}
							]
						}}
					>
						<Button>
							More <DownOutlined />
						</Button>
					</Dropdown>
				)}
			</>
		) : undefined;

	return (
		<>
			<PageHeader
				crumbs={[
					{ label: 'Projects', href: '/admin/projects' },
					{ label: bucket?.name ?? '…', href: bucketHref(bucketId) },
					{ label: 'Users', href: usersHref },
					{ label: user?.email ?? '…' }
				]}
				title={user?.email ?? '…'}
				tags={user ? <AccountStatusTags account={user} /> : undefined}
				meta={
					user ? (
						<>
							{name ? `${name} · ` : ''}
							<Typography.Text
								type="secondary"
								copyable={{ text: user._id }}
							>
								ID {user._id}
							</Typography.Text>
							{' · '}Created {new Date(user.createdAt).toLocaleDateString()}
						</>
					) : undefined
				}
				actions={headerActions}
				tabs={tabs}
				activeTab={tab}
			/>
			{managedBy && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title={`Managed by ${managedBy}`}
					description="The directory owns this person's details, status and password: change them there. Here you can lock them, sign them out, and reset their authenticator."
				/>
			)}
			{bucket && !can.manageUsers && (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="Only members of the team that owns this project can change this."
				/>
			)}
			{loading && !user && <Skeleton active />}
			{shownTab === null && (
				<NoAccess
					what="person's activity"
					backHref={userHref(bucketId, userId)}
					backLabel="Go to Profile"
				/>
			)}
			{bucket && user && shownTab === 'profile' && (
				<UserProfileTab
					bucketId={bucketId}
					bucket={bucket}
					user={user}
					can={can}
					connections={connections}
					onChanged={reload}
				/>
			)}
			{bucket && user && shownTab === 'signIn' && (
				<UserSignInTab
					bucketId={bucketId}
					bucket={bucket}
					user={user}
					can={can}
					onChanged={reload}
				/>
			)}
			{bucket && user && shownTab === 'groups' && (
				<UserGroupsTab
					bucketId={bucketId}
					user={user}
					can={can}
					connectionName={connectionName}
					onChanged={reload}
				/>
			)}
			{bucket && user && shownTab === 'activity' && (
				<UserActivityTab
					bucketId={bucketId}
					userId={userId}
				/>
			)}
			<LockModal
				account={lockOpen ? user : null}
				url={`${usersApi(bucketId, userId)}/lock`}
				onClose={() => setLockOpen(false)}
				onDone={reload}
			/>
		</>
	);
}
