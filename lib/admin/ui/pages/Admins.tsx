import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Tag,
	Tooltip,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { User } from '../../../adapters/types.js';
import { AreaToolbar } from '../frame/AreaToolbar.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { LoadFailed, NoMatch } from '../frame/states.js';
import { useMe } from '../frame/me.js';
import { useHydrated } from '../frame/hydrated.js';

/* What the list answers: the account without its password or secret, and whether it holds the instance privilege. */
type AdminUser = Pick<User, '_id' | 'email' | 'active' | 'verified'> & {
	superAdmin: boolean;
	totpEnrolled: boolean;
	totpEnrolledAt: string | null;
};

type StatusFilter = 'active' | 'deactivated' | 'super' | 'unverified';

const MATCHES: Record<StatusFilter, (a: AdminUser) => boolean> = {
	active: (a) => a.active,
	deactivated: (a) => !a.active,
	super: (a) => a.superAdmin,
	unverified: (a) => !a.verified
};

interface CreateAdminValues {
	email: string;
	password: string;
}

const adminApi = (id: string, path = '') =>
	`/admin/api/admins/${encodeURIComponent(id)}${path}`;

/*
 * The administrators of this instance (specs/083: Administrators → Accounts). A list of tens, not thousands,
 * so search and filter run in the browser. Each act sits at its weight in one menu per row; the ones that
 * would lock the caller out of the page they are using are not offered on their own row.
 */
export function Admins({
	verificationRequired
}: {
	/* Whether the console's bucket requires a verified address: then changing your own signs you out. */
	verificationRequired: boolean;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const { me } = useMe();
	const [admins, setAdmins] = useState<AdminUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [failed, setFailed] = useState<string | null>(null);
	const [search, setSearch] = useState('');
	const [status, setStatus] = useState<StatusFilter | undefined>(undefined);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateAdminValues>();
	const [editingEmail, setEditingEmail] = useState<AdminUser | null>(null);
	const [emailForm] = Form.useForm<{ email: string }>();
	const hydrated = useHydrated();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchAdmins = useCallback(async () => {
		try {
			const result = await request<AdminUser[]>('GET', '/admin/api/admins');
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setAdmins(result.data);
		} finally {
			setLoading(false);
		}
	}, []);
	function load() {
		setLoading(true);
		return fetchAdmins();
	}

	useEffect(() => {
		void fetchAdmins();
	}, [fetchAdmins]);

	/* One request after one question; the server's refusal (the last super administrator, say) is shown as is. */
	async function act(
		target: AdminUser,
		method: string,
		path: string,
		done: string,
		body?: unknown
	) {
		const result = await request(method, adminApi(target._id, path), body);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(done);
		await load();
	}

	/*
	 * The instance privilege is granted and withdrawn by operations of its own, never by an account edit, and
	 * the server refuses withdrawing it from the last active super administrator — its reason is shown as is.
	 */
	async function onSetSuperAdmin(target: AdminUser, next: boolean) {
		const yes = next
			? await confirm('admin.superAdmin.grant', {
					target: target.email,
					consequences: [
						'They gain authority over every team, setting and key of this instance.'
					]
				})
			: await confirm('admin.superAdmin.withdraw', {
					target: target.email,
					consequences: [
						'They keep their teams but lose authority over the whole instance.'
					]
				});
		if (!yes) return;
		await act(
			target,
			next ? 'POST' : 'DELETE',
			'/super-admin',
			next
				? `Super administration granted to ${target.email}.`
				: `Super administration withdrawn from ${target.email}.`
		);
	}

	async function onDeactivate(target: AdminUser) {
		const yes = await confirm('admin.deactivate', {
			target: target.email,
			consequences: [
				'They cannot sign in to the console, and any page they have open stops working at its next request.',
				'Their account, teams and history are kept; Activate gives them back.'
			]
		});
		if (yes) {
			await act(target, 'DELETE', '', `${target.email} deactivated.`);
		}
	}

	async function onActivate(target: AdminUser) {
		const yes = await confirm('admin.activate', {
			target: target.email,
			consequences: [
				'They can sign in to the console again, with everything their teams grant.'
			]
		});
		if (yes) {
			await act(target, 'PATCH', '', `${target.email} activated.`, {
				active: true
			});
		}
	}

	async function onSignOut(target: AdminUser) {
		const yes = await confirm('admin.signOut', {
			target: target.email,
			consequences: [
				'Every console session they have ends now, and so do the tokens agents hold on their behalf.',
				'They can sign in again.'
			]
		});
		if (yes) {
			await act(
				target,
				'POST',
				'/sign-out',
				`${target.email} signed out everywhere.`
			);
		}
	}

	async function onResetTotp(target: AdminUser) {
		const yes = await confirm('admin.totp.reset', {
			target: target.email,
			consequences: [
				'Their authenticator stops working immediately.',
				'They are signed out everywhere.',
				'They set up a new one at their next sign-in.'
			]
		});
		if (yes) {
			await act(
				target,
				'DELETE',
				'/totp',
				`Authenticator of ${target.email} reset.`
			);
		}
	}

	function openEmail(target: AdminUser, email: string) {
		emailForm.setFields([{ name: 'email', value: email, errors: [] }]);
		setEditingEmail(target);
	}

	/*
	 * Corrects an administrator's address. The server leaves the account unverified at the new one and
	 * refuses changing your own while administrators must verify theirs; either refusal is shown as is.
	 *
	 * The question is asked with the form closed — never a dialog over a dialog — and the form comes back
	 * with what was typed if the answer is no or the server refuses.
	 */
	async function onChangeEmail(target: AdminUser, email: string) {
		setEditingEmail(null);
		if (email === target.email) return;
		const yes = await confirm('admin.email.change', {
			target: target.email,
			consequences: [
				`They sign in as ${email} from now on; ${target.email} stops working.`,
				verificationRequired
					? 'Administrators must verify their email: they cannot sign in until they verify the new address.'
					: 'The new address is unverified until they verify it.'
			]
		});
		if (!yes) {
			openEmail(target, email);
			return;
		}
		const result = await request('PATCH', adminApi(target._id), { email });
		if (!result.ok) {
			openEmail(target, email);
			feedback.failed(result, emailForm);
			return;
		}
		feedback.done(`Email of ${target.email} changed to ${email}.`);
		await load();
	}

	async function onCreate(values: CreateAdminValues) {
		setCreating(true);
		try {
			const result = await request('POST', '/admin/api/admins', values);
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			feedback.done(`Administrator ${values.email} created.`);
			setOpen(false);
			form.resetFields();
			await load();
		} finally {
			setCreating(false);
		}
	}

	function rowActions(row: AdminUser): RowAction[] {
		const self = row._id === me?.userId;
		const items: RowAction[] = [
			{
				key: 'email',
				label: 'Change email…',
				group: 'edit',
				blocked:
					self && verificationRequired
						? 'Changing your own address would sign you out until you verify the new one'
						: null,
				onClick: () => openEmail(row, row.email)
			},
			row.superAdmin
				? {
						key: 'withdraw',
						label: 'Withdraw super administration…',
						group: 'danger',
						onClick: () => void onSetSuperAdmin(row, false)
					}
				: {
						key: 'grant',
						label: 'Make super administrator…',
						group: 'state',
						onClick: () => void onSetSuperAdmin(row, true)
					}
		];
		// Acts that would end the caller's own access are not offered on their own row: Log out does the one.
		if (self) return items;
		if (row.totpEnrolled) {
			items.push({
				key: 'totp',
				label: 'Reset authenticator',
				group: 'state',
				onClick: () => void onResetTotp(row)
			});
		}
		items.push(
			{
				key: 'signOut',
				label: 'Sign out everywhere',
				group: 'state',
				onClick: () => void onSignOut(row)
			},
			row.active
				? {
						key: 'deactivate',
						label: 'Deactivate',
						group: 'danger',
						onClick: () => void onDeactivate(row)
					}
				: {
						key: 'activate',
						label: 'Activate',
						group: 'state',
						onClick: () => void onActivate(row)
					}
		);
		return items;
	}

	const needle = search.trim().toLowerCase();
	const shown = admins.filter(
		(a) =>
			(!needle || a.email.toLowerCase().includes(needle)) &&
			(!status || MATCHES[status](a))
	);

	if (failed !== null) {
		return (
			<LoadFailed
				reason={failed}
				onRetry={() => void load()}
			/>
		);
	}

	return (
		<>
			<AreaToolbar
				search={search}
				onSearch={setSearch}
				searchPlaceholder="Search by email"
				filters={
					<Select<StatusFilter>
						allowClear
						placeholder="Status"
						aria-label="Status"
						value={status}
						onChange={setStatus}
						style={{ minWidth: 180 }}
						options={[
							{ label: 'Active', value: 'active' },
							{ label: 'Deactivated', value: 'deactivated' },
							{ label: 'Super administrators', value: 'super' },
							{ label: 'Unverified', value: 'unverified' }
						]}
					/>
				}
				create={
					<Button
						type="primary"
						icon={<PlusOutlined />}
						onClick={() => setOpen(true)}
					>
						New administrator
					</Button>
				}
			/>
			<Table<AdminUser>
				rowKey="_id"
				loading={loading}
				dataSource={shown}
				pagination={false}
				locale={{
					emptyText:
						admins.length > 0 ? (
							<NoMatch
								query={search || 'this filter'}
								clearLabel="Clear search and filter"
								onClear={() => {
									setSearch('');
									setStatus(undefined);
								}}
							/>
						) : (
							' '
						)
				}}
				columns={[
					{
						title: 'Administrator',
						key: 'email',
						render: (_: unknown, row: AdminUser) => (
							<Space
								size={6}
								wrap
							>
								<Typography.Text>{row.email}</Typography.Text>
								{row._id === me?.userId && <Tag color="blue">You</Tag>}
								{row.superAdmin && <Tag color="gold">Super administrator</Tag>}
								{!row.active && <Tag>Deactivated</Tag>}
								{!row.verified && <Tag color="orange">Unverified</Tag>}
							</Space>
						)
					},
					{
						// Whether there is one, and since when. Never the secret behind it.
						title: 'Authenticator',
						key: 'totp',
						render: (_: unknown, row: AdminUser) =>
							row.totpEnrolled ? (
								<Tooltip
									title={
										row.totpEnrolledAt
											? `Set up ${new Date(row.totpEnrolledAt).toLocaleString()}`
											: undefined
									}
								>
									<Tag color="green">Set up</Tag>
								</Tooltip>
							) : (
								<Typography.Text type="secondary">—</Typography.Text>
							)
					},
					{
						title: '',
						key: 'actions',
						render: (_: unknown, row: AdminUser) => (
							<RowActions
								name={row.email}
								items={rowActions(row)}
							/>
						)
					}
				]}
			/>
			{/*
			 * Not destroyed when hidden: a refusal naming the field is set on it while it reopens, which a
			 * form still being mounted would drop. Rendered ahead only once hydrated: a portal drawn on the
			 * server is markup the first client render does not have, and the page hydrated from scratch.
			 */}
			<Modal
				title="Change email"
				open={editingEmail !== null}
				onCancel={() => setEditingEmail(null)}
				onOk={() => emailForm.submit()}
				okText="Continue"
				forceRender={hydrated}
			>
				<Form<{ email: string }>
					form={emailForm}
					layout="vertical"
					scrollToFirstError
					onFinish={({ email }) => {
						if (editingEmail) void onChangeEmail(editingEmail, email);
					}}
				>
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>
			<Modal
				title="New administrator"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateAdminValues>
					form={form}
					layout="vertical"
					scrollToFirstError
					onFinish={onCreate}
				>
					{/*
					 * An address beside a password is a sign-in form as far as a browser is concerned, and it
					 * filled this one with the *administrator's own* saved credentials — one distracted OK away
					 * from creating an account with their own email and password. `new-password` is the part
					 * that does the work: it is the documented signal not to offer a stored pair.
					 */}
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="password"
						label="Password"
						rules={[{ required: true, min: 12 }]}
					>
						<Input.Password
							autoComplete="new-password"
							placeholder="at least 12 characters"
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
