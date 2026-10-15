import { useCallback, useEffect, useState } from 'react';
import {
	App,
	Button,
	Flex,
	Form,
	Input,
	Modal,
	Radio,
	Select,
	Space,
	Table,
	Tag,
	Tooltip,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { AreaToolbar } from '../frame/AreaToolbar.js';
import { EmptyState, LoadFailed, NoMatch } from '../frame/states.js';
import { bucketHref, userHref } from '../frame/routes.js';
import { Link, useNavigate, useRoute } from '../frame/router.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import type { BucketCan } from '../frame/can.js';
import { AccountStatusTags } from '../accounts/AccountStatusTags.js';
import { SetPasswordModal } from '../accounts/SetPasswordModal.js';
import { LockModal } from '../accounts/LockModal.js';
import { ClaimsField, parseClaims } from '../accounts/ClaimsDrawer.js';
import type { ConnectionView } from './ProvisioningPanel.js';
import {
	nameOf,
	usersApi,
	type EndUser,
	type EndUserPage
} from './users/endUser.js';
import { useUserActions } from './users/useUserActions.js';
import { BULK_LIMIT, BulkUsersBar } from './users/BulkUsersBar.js';

const PAGE_SIZE = 50;

/* The filters the address carries (specs/082 contracts/console.md), each narrowing the server's answer. */
const FILTER_KEYS = [
	'status',
	'managedBy',
	'verified',
	'authenticator'
] as const;
type FilterKey = (typeof FILTER_KEYS)[number];

interface CreateValues {
	email: string;
	/* How the person gets a password: typed here, or chosen by them from an invitation (specs/089). */
	access: 'password' | 'invite';
	password?: string;
	claimsText?: string;
}

/*
 * A bucket's people, read from the server one page at a time (specs/082): the list is never the whole
 * bucket, so search and filters are the server's, and live in the address so a filtered list is a link.
 *
 * Each row shows who the person is and then only what is out of the ordinary. Opening a person is the
 * row's link; the menu holds the acts that do not need their page.
 */
export function BucketUsersPanel({
	bucketId,
	can,
	mailConfigured,
	passwordLogin
}: {
	bucketId: string;
	can: BucketCan;
	/* Whether an invitation could be sent and used; unknown (undefined) offers it and lets the server decide. */
	mailConfigured?: boolean;
	passwordLogin?: boolean;
}) {
	const feedback = useFeedback();
	const { notification } = App.useApp();
	const navigate = useNavigate();
	const actions = useUserActions(bucketId);
	const { query } = useRoute();
	const q = query.get('q') ?? '';
	const page = Math.max(Number(query.get('page') ?? '1') || 1, 1);
	const filters = Object.fromEntries(
		FILTER_KEYS.map((key) => [key, query.get(key) ?? undefined])
	) as Record<FilterKey, string | undefined>;
	const filtered = FILTER_KEYS.some((key) => filters[key] !== undefined);

	const [search, setSearch] = useState(q);
	const [data, setData] = useState<EndUserPage | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const [connections, setConnections] = useState<ConnectionView[]>([]);
	const [createOpen, setCreateOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [pwUser, setPwUser] = useState<EndUser | null>(null);
	const [lockUser, setLockUser] = useState<EndUser | null>(null);
	const [createForm] = Form.useForm<CreateValues>();
	const access = Form.useWatch('access', { form: createForm, preserve: true });
	/*
	 * Kept by id across pages and searches, so a selection built from several filtered views survives; the
	 * rows themselves are kept too, because the bar forecasts skips from what it was shown.
	 */
	const [selected, setSelected] = useState<Map<string, EndUser>>(new Map());
	const inviteBlocked =
		mailConfigured === false
			? 'Set up mail delivery first (Settings → Mail).'
			: passwordLogin === false
				? "This project doesn't sign people in with a password."
				: null;

	/* Writes the list's state into the address; the address is what the list reads. */
	const go = useCallback(
		(changes: Record<string, string | undefined>) => {
			const params = new URLSearchParams(query);
			for (const [key, value] of Object.entries(changes)) {
				if (value === undefined || value === '') params.delete(key);
				else params.set(key, value);
			}
			// A narrower list starts at its first page.
			if (!('page' in changes)) params.delete('page');
			const qs = params.toString();
			void navigate(`${bucketHref(bucketId, 'users')}${qs ? `?${qs}` : ''}`, {
				replace: true
			});
		},
		[query, navigate, bucketId]
	);

	// Typing waits for a pause before it becomes a request, and an address.
	useEffect(() => {
		if (search.trim() === q) return;
		const timer = setTimeout(() => {
			go({ q: search.trim() });
		}, 300);
		return () => {
			clearTimeout(timer);
		};
	}, [search, q, go]);

	const queryKey = query.toString();
	const fetchPage = useCallback(async () => {
		const params = new URLSearchParams();
		if (q) params.set('q', q);
		for (const key of FILTER_KEYS) {
			const value = filters[key];
			if (value) params.set(key, value);
		}
		params.set('startIndex', String((page - 1) * PAGE_SIZE + 1));
		params.set('count', String(PAGE_SIZE));
		try {
			const result = await request<EndUserPage>(
				'GET',
				`${usersApi(bucketId)}?${params.toString()}`
			);
			if (result.ok) {
				setData(result.data);
				setLoadError(null);
			} else {
				setLoadError(result.error.message);
			}
		} finally {
			setLoading(false);
		}
		// `filters`, `q` and `page` are all read from the address, which `queryKey` stands for.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [bucketId, queryKey]);
	function reload() {
		setLoading(true);
		return fetchPage();
	}
	useEffect(() => {
		void fetchPage();
	}, [fetchPage]);

	useEffect(() => {
		void request<ConnectionView[]>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucketId)}/provisioning-connections`
		).then((c) => {
			if (c.ok) setConnections(c.data);
		});
	}, [bucketId]);

	const connectionName = (id: string) =>
		connections.find((c) => c.id === id)?.displayName ?? id;

	async function onCreate({
		claimsText,
		password,
		email,
		access: how
	}: CreateValues) {
		const claims = parseClaims(claimsText);
		const invite = how === 'invite';
		setSaving(true);
		try {
			const result = await request<{
				_id?: string;
				invitation?: 'sent' | 'failed';
			}>('POST', usersApi(bucketId), {
				email,
				...(invite ? { invite: true } : password ? { password } : {}),
				...(Object.keys(claims).length ? { claims } : {})
			});
			if (!result.ok) {
				feedback.failed(result, createForm);
				return;
			}
			if (result.data.invitation === 'failed') {
				notification.warning({
					title: `User ${email} created, but the invitation could not be sent`,
					description: "Send it again from the user's page.",
					duration: 0
				});
			} else {
				feedback.done(
					invite ? `Invitation sent to ${email}.` : `User ${email} created.`
				);
			}
			setCreateOpen(false);
			createForm.resetFields();
			// Their page is where the next thing is done: groups, a password, a verification message.
			if (result.data._id) void navigate(userHref(bucketId, result.data._id));
			else await reload();
		} finally {
			setSaving(false);
		}
	}

	function rowActions(row: EndUser): RowAction[] {
		if (!can.manageUsers) return [];
		/*
		 * The directory owns a provisioned record, and the server refuses these for one. Shown disabled with
		 * the reason rather than hidden, and folded into one line, since the reason is one.
		 */
		const managed = row.provisionedBy
			? `Managed by ${connectionName(row.provisionedBy)} — change this user in the directory`
			: null;
		const after = (done: boolean) => {
			if (done) void reload();
		};
		const items: RowAction[] = [
			{
				key: 'password',
				label: 'Set password…',
				group: 'edit',
				blocked: managed,
				onClick: () => setPwUser(row)
			}
		];
		if (row.totpEnrolled) {
			items.push({
				key: 'totp',
				label: 'Reset authenticator',
				group: 'state',
				onClick: () => void actions.resetTotp(row).then(after)
			});
		}
		items.push(
			// Allowed on a provisioned user too: it ends access and edits nothing the connection owns.
			{
				key: 'signOut',
				label: 'Sign out everywhere',
				group: 'state',
				onClick: () => void actions.signOut(row).then(after)
			},
			// The local lock is the one thing an administrator keeps over a provisioned user.
			row.lockedLocally
				? {
						key: 'unlock',
						label: 'Unlock…',
						group: 'state',
						onClick: () => void actions.unlock(row).then(after)
					}
				: {
						key: 'lock',
						label: 'Lock…',
						group: 'state',
						onClick: () => setLockUser(row)
					},
			row.active
				? {
						key: 'deactivate',
						label: 'Deactivate',
						group: 'state',
						blocked: managed,
						onClick: () => void actions.deactivate(row).then(after)
					}
				: {
						key: 'activate',
						label: 'Activate',
						group: 'state',
						blocked: managed,
						onClick: () => void actions.activate(row).then(after)
					},
			{
				key: 'delete',
				label: 'Delete…',
				group: 'danger',
				blocked: managed,
				onClick: () => void actions.remove(row).then(after)
			}
		);
		return items;
	}

	const newUserButton = can.manageUsers ? (
		<Button
			type="primary"
			icon={<PlusOutlined />}
			onClick={() => setCreateOpen(true)}
		>
			New user
		</Button>
	) : undefined;

	const filterSelect = (
		key: FilterKey,
		placeholder: string,
		options: { label: string; value: string }[]
	) => (
		<Select
			allowClear
			placeholder={placeholder}
			value={filters[key]}
			onChange={(value: string | undefined) => go({ [key]: value })}
			options={options}
			style={{ minWidth: 150 }}
			aria-label={placeholder}
		/>
	);

	if (loadError !== null) {
		return (
			<LoadFailed
				reason={loadError}
				onRetry={() => void reload()}
			/>
		);
	}

	const narrowed = q !== '' || filtered;

	return (
		<>
			<AreaToolbar
				search={search}
				onSearch={setSearch}
				searchPlaceholder="Email or username starts with…, or an exact ID"
				filters={
					<>
						{filterSelect('status', 'Status', [
							{ label: 'Active', value: 'active' },
							{ label: 'Deactivated', value: 'deactivated' },
							{ label: 'Locked', value: 'locked' }
						])}
						{filterSelect('managedBy', 'Managed by', [
							{ label: 'This console', value: 'console' },
							...connections.map((c) => ({
								label: c.displayName,
								value: c.id
							}))
						])}
						{filterSelect('verified', 'Verified', [
							{ label: 'Verified', value: 'yes' },
							{ label: 'Unverified', value: 'no' }
						])}
						{filterSelect('authenticator', 'Authenticator', [
							{ label: 'Set up', value: 'yes' },
							{ label: 'Not set up', value: 'no' }
						])}
						{filtered && (
							<Button
								type="link"
								onClick={() =>
									go(
										Object.fromEntries(
											FILTER_KEYS.map((key) => [key, undefined])
										)
									)
								}
							>
								Clear filters
							</Button>
						)}
					</>
				}
				create={newUserButton}
			/>
			{can.manageUsers && selected.size > 0 && (
				<BulkUsersBar
					bucketId={bucketId}
					selected={[...selected.values()]}
					onClear={() => setSelected(new Map())}
					onDone={() => {
						setSelected(new Map());
						void reload();
					}}
				/>
			)}
			<Table<EndUser>
				rowKey="_id"
				loading={loading}
				rowSelection={
					can.manageUsers
						? {
								selectedRowKeys: [...selected.keys()],
								preserveSelectedRowKeys: true,
								// The bulk routes take at most this many; the list stops offering more rather than the server refusing.
								getCheckboxProps: (row) => ({
									disabled:
										selected.size >= BULK_LIMIT && !selected.has(row._id),
									title:
										selected.size >= BULK_LIMIT && !selected.has(row._id)
											? `Up to ${String(BULK_LIMIT)} people at a time`
											: undefined
								}),
								onChange: (_keys, rows) => {
									setSelected((current) => {
										const next = new Map<string, EndUser>();
										const shown = new Set(
											(data?.users ?? []).map((u) => u._id)
										);
										// Keep what was picked on other pages; replace this page's picks with the table's.
										for (const [id, user] of current) {
											if (!shown.has(id)) next.set(id, user);
										}
										for (const row of rows) {
											if (next.size >= BULK_LIMIT) break;
											next.set(row._id, row);
										}
										return next;
									});
								}
							}
						: undefined
				}
				dataSource={data?.users ?? []}
				pagination={{
					current: page,
					pageSize: PAGE_SIZE,
					total: data?.totalResults ?? 0,
					showSizeChanger: false,
					hideOnSinglePage: true,
					showTotal: (total) => `${String(total)} users`,
					onChange: (next) => go({ page: next > 1 ? String(next) : undefined })
				}}
				locale={{
					// Before the first answer nothing is known, and "no users yet" would be a claim.
					emptyText: !data ? (
						' '
					) : narrowed ? (
						<NoMatch
							query={q || 'these filters'}
							clearLabel={q ? 'Clear search' : 'Clear filters'}
							onClear={() => {
								setSearch('');
								go({
									q: undefined,
									...Object.fromEntries(
										FILTER_KEYS.map((key) => [key, undefined])
									)
								});
							}}
						/>
					) : (
						<EmptyState
							purpose="No end users in this project yet. People register here, arrive through an identity provider or a directory, or are created by an administrator."
							create={newUserButton}
						/>
					)
				}}
				columns={[
					{
						title: 'User',
						key: 'user',
						render: (_: unknown, row: EndUser) => {
							const name = nameOf(row);
							return (
								<Flex vertical>
									<Link href={userHref(bucketId, row._id)}>{row.email}</Link>
									{name && (
										<Typography.Text type="secondary">{name}</Typography.Text>
									)}
								</Flex>
							);
						}
					},
					{
						title: 'Status',
						key: 'status',
						render: (_: unknown, row: EndUser) => (
							<Space
								size={4}
								wrap
							>
								<AccountStatusTags account={row} />
							</Space>
						)
					},
					{
						title: 'Groups',
						key: 'groups',
						render: (_: unknown, row: EndUser) => {
							const groups = row.groups ?? [];
							const shown = groups.slice(0, 3);
							return (
								<Space
									size={4}
									wrap
								>
									{shown.map((g) => (
										<Tag
											key={g.id}
											color={g.provisionedBy ? 'purple' : undefined}
										>
											{g.displayName}
										</Tag>
									))}
									{groups.length > shown.length && (
										<Tooltip
											title={groups
												.slice(shown.length)
												.map((g) => g.displayName)
												.join(', ')}
										>
											<Tag>+{groups.length - shown.length}</Tag>
										</Tooltip>
									)}
								</Space>
							);
						}
					},
					{
						// How they get in. Never the authenticator's secret — the server does not send it.
						title: 'Sign-in methods',
						key: 'methods',
						render: (_: unknown, row: EndUser) => (
							<Space
								size={4}
								wrap
							>
								{row.passwordSet === true && <Tag>Password</Tag>}
								{row.totpEnrolled && <Tag color="green">Authenticator</Tag>}
								{(row.federated ?? []).map((link) => (
									<Tag
										key={`${link.providerId}:${link.sub}`}
										color="blue"
									>
										{link.providerId}
									</Tag>
								))}
							</Space>
						)
					},
					{
						/*
						 * Who owns the record. A connection's display name where it is known; its id otherwise,
						 * because a stale list must not make a managed user look local.
						 */
						title: 'Managed by',
						key: 'managedBy',
						render: (_: unknown, row: EndUser) =>
							row.provisionedBy ? (
								<Tag color="purple">{connectionName(row.provisionedBy)}</Tag>
							) : (
								<Typography.Text type="secondary">Console</Typography.Text>
							)
					},
					{
						title: '',
						key: 'actions',
						render: (_: unknown, row: EndUser) => (
							<RowActions
								name={row.email}
								items={rowActions(row)}
							/>
						)
					}
				]}
			/>

			<SetPasswordModal
				account={pwUser}
				url={pwUser ? `${usersApi(bucketId, pwUser._id)}/password` : ''}
				onClose={() => setPwUser(null)}
				onDone={() => void reload()}
			/>
			<LockModal
				account={lockUser}
				url={lockUser ? `${usersApi(bucketId, lockUser._id)}/lock` : ''}
				onClose={() => setLockUser(null)}
				onDone={() => void reload()}
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
					initialValues={{ access: 'password' }}
					onFinish={(values) => void onCreate(values)}
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
						name="access"
						label="Password"
					>
						<Radio.Group>
							<Radio value="password">Set a password</Radio>
							<Tooltip title={inviteBlocked ?? undefined}>
								<Radio
									value="invite"
									disabled={inviteBlocked !== null}
								>
									Invite by email
								</Radio>
							</Tooltip>
						</Radio.Group>
					</Form.Item>
					{access === 'invite' ? (
						<Typography.Paragraph type="secondary">
							They get a message with a link to choose their own password. The
							link works for 7 days, and opening it confirms their address.
						</Typography.Paragraph>
					) : (
						<Form.Item
							name="password"
							label="Initial password"
							rules={[{ min: 8 }]}
							extra="Optional. Without one, they sign in through an identity provider, or you set a password later."
						>
							<Input.Password
								autoComplete="new-password"
								placeholder="at least 8 characters"
							/>
						</Form.Item>
					)}
					<ClaimsField />
				</Form>
			</Modal>
		</>
	);
}
